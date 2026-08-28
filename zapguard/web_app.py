"""
ZapGuard Web Application - Flask-based web interface for ZAP vulnerability verification.
Replicates all functionality from the desktop GUI.
"""

import os
import json
import uuid
import threading
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, jsonify, send_file, Response
from flask_cors import CORS
from werkzeug.utils import secure_filename

try:
    from .models import Alert, Instance, TestResult, TestStatus, RiskLevel
    from .parsers import parse_zap_report
    from .http_client import HTTPClient
    from .vulnerability_tests import get_test_class
    from .reports import generate_html_report, generate_csv_report, generate_pdf_report
except ImportError:
    # Direct execution - add parent to path
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from zapguard.models import Alert, Instance, TestResult, TestStatus, RiskLevel
    from zapguard.parsers import parse_zap_report
    from zapguard.http_client import HTTPClient
    from zapguard.vulnerability_tests import get_test_class
    from zapguard.reports import generate_html_report, generate_csv_report, generate_pdf_report


app = Flask(__name__,
            template_folder='templates',
            static_folder='static')
CORS(app)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
app.config['UPLOAD_FOLDER'] = Path(__file__).parent / 'uploads'
app.config['OUTPUT_FOLDER'] = Path(__file__).parent / 'outputs'

# Ensure directories exist
app.config['UPLOAD_FOLDER'].mkdir(exist_ok=True)
app.config['OUTPUT_FOLDER'].mkdir(exist_ok=True)

# Store active validation sessions
sessions: Dict[str, dict] = {}


class ValidationSession:
    """Manages a validation session with progress tracking."""

    def __init__(self, session_id: str, alerts: List[Alert], base_url: str,
                 report_path: str, timeout: int = 20, max_workers: int = 10,
                 nmap_enabled: bool = False, nmap_scan_types: List[str] = None,
                 nmap_only: bool = False):
        self.session_id = session_id
        self.alerts = alerts
        self.base_url = base_url
        self.report_path = report_path
        self.timeout = timeout
        self.max_workers = max_workers
        self.nmap_enabled = nmap_enabled
        self.nmap_scan_types = nmap_scan_types or ["quick"]  # Default to quick scan
        self.nmap_only = nmap_only  # Skip ZAP verification, run only Nmap

        self.results: List[TestResult] = []
        self.nmap_result = None
        self.status = "idle"  # idle, running, stopped, completed
        self.progress = 0
        self.total = 0
        self.current_endpoint = ""
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.logs: List[str] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def log(self, message: str):
        """Add a log message."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append(f"[{timestamp}] {message}")

    def stop(self):
        """Signal to stop the validation."""
        self._stop_event.set()

    def is_stopped(self) -> bool:
        return self._stop_event.is_set()

    def run(self):
        """Run the validation."""
        self.status = "running"
        self.start_time = datetime.now()
        self._stop_event.clear()

        # If Nmap-only mode, skip ZAP verification
        if self.nmap_only:
            self.log("Nmap-only mode - skipping ZAP verification")
            self.total = 0
            if self.nmap_enabled:
                self._run_nmap_scan()
            self.end_time = datetime.now()
            self.status = "completed"
            return

        client = HTTPClient(self.base_url, self.timeout, self._stop_event)

        # Build task list
        tasks = []
        for alert in self.alerts:
            for instance in alert.instances:
                tasks.append((alert, instance))

        self.total = len(tasks)
        self.log(f"Starting validation of {self.total} endpoints...")

        completed = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_task = {}
            for alert, instance in tasks:
                if self.is_stopped():
                    break
                future = executor.submit(self._test_instance, client, alert, instance)
                future_to_task[future] = (alert, instance)

            for future in as_completed(future_to_task):
                if self.is_stopped():
                    executor.shutdown(wait=False, cancel_futures=True)
                    self.log("Validation cancelled.")
                    break

                try:
                    result = future.result(timeout=1)
                    if result and not self.is_stopped():
                        with self._lock:
                            self.results.append(result)
                        completed += 1
                        alert, instance = future_to_task[future]
                        self.progress = completed
                        self.current_endpoint = instance.url[:50]
                except Exception as e:
                    if not self.is_stopped():
                        self.log(f"Error: {str(e)[:80]}")

        self.end_time = datetime.now()
        if not self.is_stopped():
            passed = sum(1 for r in self.results if r.status == TestStatus.PASS)
            failed = sum(1 for r in self.results if r.status == TestStatus.FAIL)
            self.log(f"ZAP Verification: {failed} failed, {passed} passed")

            # Run Nmap scan after ZAP validation if enabled
            if self.nmap_enabled:
                self._run_nmap_scan()

            self.status = "completed"
        else:
            self.status = "stopped"

    def _test_instance(self, client: HTTPClient, alert: Alert, instance: Instance) -> Optional[TestResult]:
        """Test a single instance."""
        if self.is_stopped():
            return None

        test_class = get_test_class(alert.plugin_id)
        test = test_class(client)

        try:
            result = test.test(alert, instance)
            return None if self.is_stopped() else result
        except Exception as e:
            if self.is_stopped():
                return None
            return TestResult(
                alert_name=alert.name,
                plugin_id=alert.plugin_id,
                risk_level=alert.risk_level,
                status=TestStatus.ERROR,
                endpoint=instance.url,
                method=instance.method,
                details=f"Error: {str(e)}"
            )

    def get_stats(self) -> dict:
        """Get current statistics."""
        with self._lock:
            total = len(self.results)
            passed = sum(1 for r in self.results if r.status == TestStatus.PASS)
            failed = sum(1 for r in self.results if r.status == TestStatus.FAIL)
            not_testable = sum(1 for r in self.results if r.status == TestStatus.NOT_TESTABLE)
            errors = sum(1 for r in self.results if r.status == TestStatus.ERROR)
            testable = total - not_testable
            pass_rate = (passed / testable * 100) if testable > 0 else 0

            duration = 0
            if self.start_time:
                end = self.end_time or datetime.now()
                duration = (end - self.start_time).total_seconds()

            return {
                'total': total,
                'passed': passed,
                'failed': failed,
                'not_testable': not_testable,
                'errors': errors,
                'pass_rate': round(pass_rate, 1),
                'duration': round(duration, 1)
            }

    def get_results_json(self) -> List[dict]:
        """Get results as JSON-serializable list."""
        with self._lock:
            return [{
                'status': r.status.value,
                'risk_level': r.risk_level.name,
                'alert_name': r.alert_name,
                'plugin_id': r.plugin_id,
                'method': r.method,
                'endpoint': r.endpoint,
                'details': r.details
            } for r in self.results]

    def _run_nmap_scan(self):
        """Run Nmap scan after ZAP validation."""
        try:
            from .nmap_scanner import NmapScanner, NMAP_AVAILABLE, ScanType, SCAN_PROFILES
            if not NMAP_AVAILABLE:
                self.log("Nmap module not available, skipping scan")
                return

            self.log("=" * 40)
            self.log("NMAP SCAN INITIATED")
            self.log("=" * 40)
            scanner = NmapScanner(log_callback=self.log)

            if not scanner.check_nmap_installed():
                self.log("Nmap not installed on system, skipping scan")
                return

            # Convert scan type strings to ScanType enums
            scan_types = []
            for st in self.nmap_scan_types:
                try:
                    scan_types.append(ScanType(st))
                except ValueError:
                    self.log(f"Unknown scan type: {st}, skipping")

            if not scan_types:
                # Default to quick scan
                scan_types = [ScanType.QUICK]

            # Log selected scans
            scan_names = [SCAN_PROFILES[st]["name"] for st in scan_types]
            self.log(f"Selected scans: {', '.join(scan_names)}")

            # Run the scans
            if len(scan_types) == 1:
                self.nmap_result = scanner.run_scan(self.base_url, scan_types[0])
            else:
                self.nmap_result = scanner.run_multiple_scans(
                    self.base_url, scan_types, sequential=True
                )

            if self.nmap_result.error:
                self.log(f"Nmap error: {self.nmap_result.error}")
            else:
                self.log(f"Found {len(self.nmap_result.ports)} open ports")
                if self.nmap_result.ssl_findings:
                    self.log(f"SSL/TLS findings: {len(self.nmap_result.ssl_findings)}")

            self.log(f"Nmap scan completed in {self.nmap_result.scan_time:.1f}s")

        except ImportError as e:
            self.log(f"Nmap module error: {e}")
        except Exception as e:
            self.log(f"Nmap scan failed: {e}")

    def get_nmap_results_json(self) -> Optional[dict]:
        """Get Nmap results as JSON-serializable dict."""
        if not self.nmap_result:
            return None

        return {
            'target': self.nmap_result.target,
            'ip_address': self.nmap_result.ip_address,
            'hostname': self.nmap_result.hostname,
            'scan_time': self.nmap_result.scan_time,
            'scan_types': self.nmap_result.scan_types,
            'os_info': self.nmap_result.os_info,
            'host_status': self.nmap_result.host_status,
            'ports': [{
                'port': p.port,
                'protocol': p.protocol,
                'state': p.state,
                'service': p.service,
                'version': p.version,
                'product': p.product
            } for p in self.nmap_result.ports],
            'ssl_findings': [{
                'title': f.title,
                'severity': f.severity.value,
                'description': f.description,
                'port': f.port
            } for f in self.nmap_result.ssl_findings]
        }


def is_valid_url(url: str) -> bool:
    """Validate URL format."""
    import re
    from urllib.parse import urlparse

    if not url:
        return False
    try:
        result = urlparse(url)
        if result.scheme not in ('http', 'https'):
            return False
        if not result.netloc:
            return False
        netloc = result.netloc.split(':')[0]

        segments = netloc.split('.')
        looks_like_ip = len(segments) > 1 and all(seg.isdigit() for seg in segments)

        if len(segments) == 4:
            numeric_count = sum(1 for seg in segments if seg.isdigit())
            if numeric_count >= 3:
                try:
                    octets = [int(seg) for seg in segments]
                    return all(0 <= octet <= 255 for octet in octets)
                except ValueError:
                    return False

        if netloc.lower() == 'localhost':
            return True

        if '.' not in netloc:
            return False

        if all(seg.isdigit() for seg in segments):
            return False

        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$'
        if not re.match(domain_pattern, netloc):
            return False

        tld = segments[-1]
        if tld.isdigit():
            return False

        return True
    except Exception:
        return False


# ===== API Routes =====

@app.route('/')
def index():
    """Serve the main web interface."""
    return render_template('index.html')


@app.route('/api/validate-url', methods=['POST'])
def validate_url():
    """Validate a URL."""
    data = request.get_json()
    url = data.get('url', '')
    return jsonify({'valid': is_valid_url(url)})


@app.route('/api/upload-report', methods=['POST'])
def upload_report():
    """Upload and parse a ZAP report."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Check file extension
    allowed_extensions = {'.html', '.htm', '.xml', '.json'}
    ext = Path(file.filename).suffix.lower()
    if ext not in allowed_extensions:
        return jsonify({'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'}), 400

    # Save file
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{filename}"
    filepath = app.config['UPLOAD_FOLDER'] / filename
    file.save(filepath)

    try:
        alerts = parse_zap_report(str(filepath))
        total_instances = sum(len(a.instances) for a in alerts)

        return jsonify({
            'success': True,
            'filename': filename,
            'filepath': str(filepath),
            'alert_count': len(alerts),
            'instance_count': total_instances
        })
    except Exception as e:
        # Clean up on error
        filepath.unlink(missing_ok=True)
        return jsonify({'error': f'Failed to parse report: {str(e)}'}), 400


def check_device_connection(url: str) -> tuple:
    """Check if device is reachable. Returns (success, error_message)."""
    import requests as req
    try:
        req.get(url, timeout=10, verify=False)
        return True, None
    except req.exceptions.ConnectTimeout:
        return False, "Connection timed out. The device may be unreachable or slow to respond."
    except req.exceptions.ConnectionError as e:
        error_str = str(e).lower()
        if "name or service not known" in error_str or "getaddrinfo failed" in error_str:
            return False, "Could not resolve hostname. Please check the URL/IP address."
        elif "connection refused" in error_str:
            return False, "Connection refused. The device may be down or the port is not open."
        else:
            return False, f"Cannot connect to device. Please check if the device is online."
    except req.exceptions.Timeout:
        return False, "Request timed out. The device is not responding."
    except Exception as e:
        return False, f"Connection check failed: {str(e)[:100]}"


@app.route('/api/start-validation', methods=['POST'])
def start_validation():
    """Start a validation session."""
    data = request.get_json()

    url = data.get('url', '').strip()
    report_path = data.get('report_path', '').strip()
    nmap_enabled = data.get('nmap_enabled', False)
    nmap_scan_types = data.get('nmap_scan_types', ['quick'])  # List of scan type IDs
    nmap_only = data.get('nmap_only', False)  # Run only Nmap, skip ZAP

    if not url:
        return jsonify({'error': 'Target URL is required'}), 400

    if not is_valid_url(url):
        return jsonify({'error': 'Invalid URL format'}), 400

    # For Nmap-only mode, report is optional
    alerts = []
    if not nmap_only:
        if not report_path or not Path(report_path).exists():
            return jsonify({'error': 'Report file not found'}), 400

        try:
            alerts = parse_zap_report(report_path)
        except Exception as e:
            return jsonify({'error': f'Failed to parse report: {str(e)}'}), 400

        if not alerts:
            return jsonify({'error': 'No alerts found in the report'}), 400

    # Check device connectivity before proceeding
    is_reachable, error_msg = check_device_connection(url)
    if not is_reachable:
        return jsonify({
            'error': f'Device Not Reachable: {error_msg}',
            'connection_error': True,
            'details': 'Please verify: 1) The device is powered on and connected to the network, '
                      '2) The IP address or hostname is correct, '
                      '3) There are no firewall rules blocking the connection'
        }), 503

    # Create session
    session_id = str(uuid.uuid4())
    session = ValidationSession(
        session_id, alerts, url, report_path,
        nmap_enabled=nmap_enabled,
        nmap_scan_types=nmap_scan_types,
        nmap_only=nmap_only
    )
    sessions[session_id] = session

    # Start validation in background thread
    thread = threading.Thread(target=session.run, daemon=True)
    thread.start()

    return jsonify({
        'success': True,
        'session_id': session_id,
        'total': session.total,
        'nmap_only': nmap_only
    })


@app.route('/api/stop-validation', methods=['POST'])
def stop_validation():
    """Stop a running validation."""
    data = request.get_json()
    session_id = data.get('session_id')

    if not session_id or session_id not in sessions:
        return jsonify({'error': 'Invalid session'}), 400

    session = sessions[session_id]
    session.stop()

    return jsonify({'success': True})


@app.route('/api/status/<session_id>')
def get_status(session_id: str):
    """Get validation status and results."""
    if session_id not in sessions:
        return jsonify({'error': 'Session not found'}), 404

    session = sessions[session_id]

    return jsonify({
        'status': session.status,
        'progress': session.progress,
        'total': session.total,
        'current_endpoint': session.current_endpoint,
        'stats': session.get_stats(),
        'logs': session.logs[-50:],  # Last 50 log entries
        'results': session.get_results_json(),
        'nmap_results': session.get_nmap_results_json()
    })


@app.route('/api/export/<session_id>/<format>')
def export_report(session_id: str, format: str):
    """Export results in various formats."""
    if session_id not in sessions:
        return jsonify({'error': 'Session not found'}), 404

    session = sessions[session_id]

    if not session.results:
        return jsonify({'error': 'No results to export'}), 400

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = app.config['OUTPUT_FOLDER']

    try:
        if format == 'html':
            filename = f"zap_verification_report_{timestamp}.html"
            filepath = output_dir / filename
            generate_html_report(
                session.results,
                session.alerts,
                session.base_url,
                session.report_path,
                str(filepath)
            )
            return send_file(filepath, as_attachment=True, download_name=filename)

        elif format == 'pdf':
            filename = f"zap_verification_report_{timestamp}.pdf"
            filepath = output_dir / filename
            generate_pdf_report(
                session.results,
                session.alerts,
                session.base_url,
                session.report_path,
                str(filepath)
            )
            return send_file(filepath, as_attachment=True, download_name=filename)

        elif format == 'csv':
            filename = f"zap_verification_results_{timestamp}.csv"
            filepath = output_dir / filename
            generate_csv_report(session.results, str(filepath))
            return send_file(filepath, as_attachment=True, download_name=filename)

        else:
            return jsonify({'error': 'Invalid format'}), 400

    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500


@app.route('/api/export-nmap/<session_id>/<format>')
def export_nmap_report(session_id: str, format: str):
    """Export Nmap results in various formats."""
    if session_id not in sessions:
        return jsonify({'error': 'Session not found'}), 404

    session = sessions[session_id]

    if not session.nmap_result:
        return jsonify({'error': 'No Nmap results available'}), 400

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_dir = app.config['OUTPUT_FOLDER']

    try:
        from .nmap_scanner import generate_nmap_html_report, generate_nmap_csv_report

        if format == 'html':
            filename = f"nmap_scan_report_{timestamp}.html"
            filepath = output_dir / filename
            generate_nmap_html_report(session.nmap_result, str(filepath))
            return send_file(filepath, as_attachment=True, download_name=filename)

        elif format == 'csv':
            filename = f"nmap_scan_report_{timestamp}.csv"
            filepath = output_dir / filename
            generate_nmap_csv_report(session.nmap_result, str(filepath))
            return send_file(filepath, as_attachment=True, download_name=filename)

        else:
            return jsonify({'error': 'Invalid format. Use html or csv'}), 400

    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500


@app.route('/api/nmap-profiles')
def nmap_profiles():
    """Get available Nmap scan profiles."""
    try:
        from .nmap_scanner import get_scan_profiles, NMAP_AVAILABLE
        if not NMAP_AVAILABLE:
            return jsonify({'error': 'Nmap module not available'}), 400
        return jsonify({'profiles': get_scan_profiles()})
    except ImportError:
        return jsonify({'error': 'Nmap module not installed'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/nmap-status')
def nmap_status():
    """Check if Nmap is available on the system."""
    try:
        from .nmap_scanner import NMAP_AVAILABLE
        if not NMAP_AVAILABLE:
            return jsonify({
                'available': False,
                'reason': 'python-nmap not installed. Run: pip install python-nmap'
            })

        from .nmap_scanner import NmapScanner
        try:
            scanner = NmapScanner()
            if scanner.check_nmap_installed():
                return jsonify({
                    'available': True,
                    'reason': 'Nmap is installed and ready'
                })
            else:
                return jsonify({
                    'available': False,
                    'reason': 'Nmap not found. Install from nmap.org'
                })
        except RuntimeError as e:
            return jsonify({
                'available': False,
                'reason': 'Nmap not installed. Download from nmap.org'
            })
        except Exception as e:
            return jsonify({
                'available': False,
                'reason': f'Nmap error: {str(e)[:50]}'
            })
    except ImportError:
        return jsonify({
            'available': False,
            'reason': 'Nmap module not available'
        })
    except Exception as e:
        return jsonify({
            'available': False,
            'reason': str(e)[:50]
        })


@app.route('/api/clear/<session_id>', methods=['POST'])
def clear_session(session_id: str):
    """Clear a session."""
    if session_id in sessions:
        session = sessions[session_id]
        session.stop()
        del sessions[session_id]

    return jsonify({'success': True})


def run_server(host: str = '0.0.0.0', port: int = 5005, debug: bool = False):
    """Run the Flask server."""
    print(f"\n{'='*50}")
    print(f"  ZapGuard Web Server")
    print(f"  Running on http://{host}:{port}")
    print(f"{'='*50}\n")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == '__main__':
    run_server()
