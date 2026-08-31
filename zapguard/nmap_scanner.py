"""
Nmap Scanner Module for ZapGuard
Provides port scanning and SSL/TLS vulnerability detection.
"""

import re
import socket
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from enum import Enum
from urllib.parse import urlparse

import os
import sys

# Add common Nmap installation paths to system PATH
NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
    r"C:\Nmap",
]

for nmap_path in NMAP_PATHS:
    if os.path.exists(nmap_path) and nmap_path not in os.environ.get('PATH', ''):
        os.environ['PATH'] = nmap_path + os.pathsep + os.environ.get('PATH', '')
        break

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class ScanType(Enum):
    """Essential scan types - trimmed for efficiency."""
    QUICK = "quick"
    REGULAR = "regular"
    SERVICE_DETECTION = "service_detection"
    SSL_ONLY = "ssl_only"
    FULL = "full"


# Scan type configurations with nmap arguments
SCAN_PROFILES = {
    ScanType.QUICK: {
        "name": "Quick Scan",
        "description": "Fast scan of top 100 ports",
        "args": "-T4 -F",
        "ports": None,
        "requires_root": False,
        "estimated_time": "< 1 min"
    },
    ScanType.REGULAR: {
        "name": "Regular Scan",
        "description": "Standard scan with service detection on common ports",
        "args": "-sV -T4 --open",
        "ports": "21-25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443",
        "requires_root": False,
        "estimated_time": "1-3 min"
    },
    ScanType.SERVICE_DETECTION: {
        "name": "Service Detection",
        "description": "Detailed service/version detection on all common ports",
        "args": "-sV -sC -T4 --open",
        "ports": None,
        "requires_root": False,
        "estimated_time": "3-8 min"
    },
    ScanType.SSL_ONLY: {
        "name": "SSL/TLS Scan",
        "description": "Check SSL/TLS vulnerabilities (Heartbleed, POODLE, weak ciphers)",
        "args": "-sV --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params",
        "ports": "443,8443",
        "requires_root": False,
        "estimated_time": "1-3 min"
    },
    ScanType.FULL: {
        "name": "Full Scan",
        "description": "Comprehensive scan with OS detection, scripts, and version info",
        "args": "-T4 -A -v --open",
        "ports": None,
        "requires_root": False,
        "estimated_time": "5-15 min"
    }
}


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""
    product: str = ""
    extra_info: str = ""


@dataclass
class SSLFinding:
    title: str
    severity: Severity
    description: str
    port: int = 443


@dataclass
class NmapScanResult:
    target: str
    ip_address: str
    hostname: str
    scan_time: float
    ports: List[PortInfo] = field(default_factory=list)
    ssl_findings: List[SSLFinding] = field(default_factory=list)
    os_info: str = ""
    raw_output: str = ""
    error: str = ""
    scan_types: List[str] = field(default_factory=list)  # Track which scans were performed
    traceroute: List[Dict] = field(default_factory=list)  # Traceroute hops
    host_status: str = ""  # up/down for ping scans


def get_scan_profiles() -> List[Dict]:
    """Get list of available scan profiles for UI dropdown."""
    profiles = []
    for scan_type, profile in SCAN_PROFILES.items():
        profiles.append({
            "id": scan_type.value,
            "name": profile["name"],
            "description": profile["description"],
            "estimated_time": profile["estimated_time"],
            "requires_root": profile.get("requires_root", False)
        })
    return profiles


class NmapScanner:
    """Nmap scanner wrapper for security scanning."""

    def __init__(self, log_callback: Optional[Callable[[str], None]] = None):
        self.log_callback = log_callback or print
        self._stop_requested = False
        self.nm = None

        if not NMAP_AVAILABLE:
            raise ImportError("python-nmap is not installed. Run: pip install python-nmap")

        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError as e:
            raise RuntimeError(f"Nmap not found: {e}")

    def stop(self):
        """Request scan to stop."""
        self._stop_requested = True

    def _log(self, message: str):
        """Log a message."""
        if self.log_callback:
            self.log_callback(message)

    def _extract_host(self, url: str) -> str:
        """Extract hostname/IP from URL."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        # Remove port if present
        if ':' in host:
            host = host.split(':')[0]
        return host

    def _resolve_ip(self, host: str) -> str:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return host

    def check_nmap_installed(self) -> bool:
        """Check if nmap is installed on the system."""
        if self.nm is None:
            return False
        try:
            self.nm.nmap_version()
            return True
        except nmap.PortScannerError:
            return False
        except Exception:
            return False

    def basic_scan(self, target: str, ports: str = "21-25,53,80,110,143,443,445,993,995,3306,3389,5432,8080,8443") -> NmapScanResult:
        """
        Perform basic port scan with service detection.

        Args:
            target: URL or IP address to scan
            ports: Port range to scan (default: common ports)

        Returns:
            NmapScanResult with discovered ports and services
        """
        self._stop_requested = False
        host = self._extract_host(target)
        ip = self._resolve_ip(host)

        result = NmapScanResult(
            target=target,
            ip_address=ip,
            hostname=host,
            scan_time=0
        )

        self._log(f"Starting basic scan on {host} ({ip})...")
        self._log(f"Scanning ports: {ports}")

        try:
            # -sV: Service version detection
            # -sT: TCP connect scan (works without root)
            # --open: Only show open ports
            scan_result = self.nm.scan(
                hosts=ip,
                ports=ports,
                arguments='-sV -sT --open -T4'
            )

            if self._stop_requested:
                result.error = "Scan cancelled"
                return result

            result.scan_time = float(self.nm.scanstats().get('elapsed', 0))
            result.raw_output = str(scan_result)

            # Parse results
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]

                # Get hostname if available
                if 'hostnames' in host_info and host_info['hostnames']:
                    for h in host_info['hostnames']:
                        if h.get('name'):
                            result.hostname = h['name']
                            break

                # Get open ports
                for proto in host_info.all_protocols():
                    ports_list = host_info[proto].keys()
                    for port in ports_list:
                        port_info = host_info[proto][port]
                        if port_info['state'] == 'open':
                            result.ports.append(PortInfo(
                                port=port,
                                protocol=proto,
                                state=port_info['state'],
                                service=port_info.get('name', 'unknown'),
                                version=port_info.get('version', ''),
                                product=port_info.get('product', ''),
                                extra_info=port_info.get('extrainfo', '')
                            ))

                self._log(f"Found {len(result.ports)} open ports")

        except nmap.PortScannerError as e:
            result.error = f"Nmap error: {str(e)}"
            self._log(f"ERROR: {result.error}")
        except Exception as e:
            result.error = f"Scan error: {str(e)}"
            self._log(f"ERROR: {result.error}")

        return result

    def ssl_scan(self, target: str, port: int = 443) -> NmapScanResult:
        """
        Perform SSL/TLS vulnerability scan.

        Args:
            target: URL or IP address to scan
            port: Port to scan for SSL (default: 443)

        Returns:
            NmapScanResult with SSL findings
        """
        self._stop_requested = False
        host = self._extract_host(target)
        ip = self._resolve_ip(host)

        result = NmapScanResult(
            target=target,
            ip_address=ip,
            hostname=host,
            scan_time=0
        )

        self._log(f"Starting SSL scan on {host}:{port}...")

        try:
            # SSL-related NSE scripts
            ssl_scripts = [
                'ssl-enum-ciphers',
                'ssl-cert',
                'ssl-date',
                'ssl-known-key',
                'ssl-heartbleed',
                'ssl-poodle',
                'ssl-dh-params',
            ]
            script_args = ','.join(ssl_scripts)

            scan_result = self.nm.scan(
                hosts=ip,
                ports=str(port),
                arguments=f'-sV --script={script_args} -T4'
            )

            if self._stop_requested:
                result.error = "Scan cancelled"
                return result

            result.scan_time = float(self.nm.scanstats().get('elapsed', 0))
            result.raw_output = str(scan_result)

            # Parse SSL results
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]

                for proto in host_info.all_protocols():
                    if port in host_info[proto]:
                        port_info = host_info[proto][port]

                        # Add port info
                        result.ports.append(PortInfo(
                            port=port,
                            protocol=proto,
                            state=port_info.get('state', 'unknown'),
                            service=port_info.get('name', 'unknown'),
                            version=port_info.get('version', ''),
                            product=port_info.get('product', '')
                        ))

                        # Parse script outputs
                        if 'script' in port_info:
                            self._parse_ssl_scripts(port_info['script'], result, port)

            self._log(f"Found {len(result.ssl_findings)} SSL/TLS findings")

        except nmap.PortScannerError as e:
            result.error = f"Nmap error: {str(e)}"
            self._log(f"ERROR: {result.error}")
        except Exception as e:
            result.error = f"Scan error: {str(e)}"
            self._log(f"ERROR: {result.error}")

        return result

    def _parse_ssl_scripts(self, scripts: Dict, result: NmapScanResult, port: int):
        """Parse SSL script outputs and add findings."""

        # Check for Heartbleed
        if 'ssl-heartbleed' in scripts:
            output = scripts['ssl-heartbleed']
            if 'VULNERABLE' in output.upper():
                result.ssl_findings.append(SSLFinding(
                    title="Heartbleed Vulnerability (CVE-2014-0160)",
                    severity=Severity.CRITICAL,
                    description="Server is vulnerable to Heartbleed attack which can leak sensitive memory contents.",
                    port=port
                ))

        # Check for POODLE
        if 'ssl-poodle' in scripts:
            output = scripts['ssl-poodle']
            if 'VULNERABLE' in output.upper():
                result.ssl_findings.append(SSLFinding(
                    title="POODLE Vulnerability (CVE-2014-3566)",
                    severity=Severity.HIGH,
                    description="Server supports SSLv3 which is vulnerable to POODLE attack.",
                    port=port
                ))

        # Check cipher suites
        if 'ssl-enum-ciphers' in scripts:
            output = scripts['ssl-enum-ciphers']

            # Check for weak protocols
            if 'SSLv2' in output:
                result.ssl_findings.append(SSLFinding(
                    title="SSLv2 Protocol Supported",
                    severity=Severity.CRITICAL,
                    description="Server supports deprecated SSLv2 protocol which has known vulnerabilities.",
                    port=port
                ))

            if 'SSLv3' in output:
                result.ssl_findings.append(SSLFinding(
                    title="SSLv3 Protocol Supported",
                    severity=Severity.HIGH,
                    description="Server supports deprecated SSLv3 protocol (vulnerable to POODLE).",
                    port=port
                ))

            if 'TLSv1.0' in output:
                result.ssl_findings.append(SSLFinding(
                    title="TLSv1.0 Protocol Supported",
                    severity=Severity.MEDIUM,
                    description="Server supports TLSv1.0 which is considered weak. Recommend TLSv1.2 or higher.",
                    port=port
                ))

            if 'TLSv1.1' in output:
                result.ssl_findings.append(SSLFinding(
                    title="TLSv1.1 Protocol Supported",
                    severity=Severity.LOW,
                    description="Server supports TLSv1.1 which is being deprecated. Recommend TLSv1.2 or higher.",
                    port=port
                ))

            # Check for weak ciphers
            weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'anon']
            for cipher in weak_ciphers:
                if cipher in output:
                    result.ssl_findings.append(SSLFinding(
                        title=f"Weak Cipher Suite: {cipher}",
                        severity=Severity.MEDIUM if cipher in ['3DES', 'RC4'] else Severity.HIGH,
                        description=f"Server supports weak cipher suite containing {cipher}.",
                        port=port
                    ))
                    break  # Only report once for weak ciphers

        # Check DH parameters
        if 'ssl-dh-params' in scripts:
            output = scripts['ssl-dh-params']
            if 'VULNERABLE' in output.upper() or 'WEAK' in output.upper():
                result.ssl_findings.append(SSLFinding(
                    title="Weak Diffie-Hellman Parameters",
                    severity=Severity.MEDIUM,
                    description="Server uses weak DH parameters (Logjam vulnerability).",
                    port=port
                ))

        # Check certificate
        if 'ssl-cert' in scripts:
            output = scripts['ssl-cert']

            # Check for self-signed
            if 'self-signed' in output.lower():
                result.ssl_findings.append(SSLFinding(
                    title="Self-Signed Certificate",
                    severity=Severity.LOW,
                    description="Server uses a self-signed certificate which is not trusted by default.",
                    port=port
                ))

            # Check for expired certificate
            if 'expired' in output.lower() or 'not valid' in output.lower():
                result.ssl_findings.append(SSLFinding(
                    title="Expired or Invalid Certificate",
                    severity=Severity.HIGH,
                    description="Server certificate is expired or not yet valid.",
                    port=port
                ))

        # If no issues found, add info finding
        if not result.ssl_findings:
            result.ssl_findings.append(SSLFinding(
                title="SSL/TLS Configuration",
                severity=Severity.INFO,
                description="No major SSL/TLS vulnerabilities detected.",
                port=port
            ))

    def full_scan(self, target: str) -> NmapScanResult:
        """
        Perform comprehensive scan combining basic and SSL scans.

        Args:
            target: URL or IP address to scan

        Returns:
            NmapScanResult with all findings
        """
        self._log("Starting full scan...")

        # Run basic scan first
        result = self.basic_scan(target)

        if self._stop_requested or result.error:
            return result

        # Check if HTTPS port is open
        https_ports = [p for p in result.ports if p.port in [443, 8443] or 'ssl' in p.service.lower()]

        if https_ports:
            for port_info in https_ports:
                self._log(f"Running SSL scan on port {port_info.port}...")
                ssl_result = self.ssl_scan(target, port_info.port)
                result.ssl_findings.extend(ssl_result.ssl_findings)
                result.scan_time += ssl_result.scan_time

                if self._stop_requested:
                    break
        else:
            self._log("No HTTPS ports detected, skipping SSL scan")

        return result

    def run_scan(self, target: str, scan_type: ScanType) -> NmapScanResult:
        """
        Run a specific scan type from the SCAN_PROFILES.

        Args:
            target: URL or IP address to scan
            scan_type: Type of scan from ScanType enum

        Returns:
            NmapScanResult with scan findings
        """
        self._stop_requested = False
        host = self._extract_host(target)
        ip = self._resolve_ip(host)

        profile = SCAN_PROFILES[scan_type]
        scan_name = profile["name"]

        result = NmapScanResult(
            target=target,
            ip_address=ip,
            hostname=host,
            scan_time=0,
            scan_types=[scan_name]
        )

        self._log(f"Starting {scan_name}...")
        self._log(f"Target: {host} ({ip})")
        self._log(f"Estimated time: {profile['estimated_time']}")

        try:
            args = profile["args"]
            ports = profile.get("ports")

            # Run the scan
            if ports:
                scan_result = self.nm.scan(hosts=ip, ports=ports, arguments=args)
            else:
                scan_result = self.nm.scan(hosts=ip, arguments=args)

            if self._stop_requested:
                result.error = "Scan cancelled"
                return result

            result.scan_time = float(self.nm.scanstats().get('elapsed', 0))
            result.raw_output = str(scan_result)

            # Parse results
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]

                # Get host status
                result.host_status = host_info.state()

                # Get hostname if available
                if 'hostnames' in host_info and host_info['hostnames']:
                    for h in host_info['hostnames']:
                        if h.get('name'):
                            result.hostname = h['name']
                            break

                # Get OS info if available
                if 'osmatch' in host_info and host_info['osmatch']:
                    os_matches = host_info['osmatch']
                    if os_matches:
                        result.os_info = os_matches[0].get('name', '')
                        self._log(f"OS detected: {result.os_info}")

                # Get traceroute if available
                if 'tcp' in scan_result.get('scan', {}).get(ip, {}):
                    pass  # Traceroute handled below

                # Try to get traceroute from hostscript
                try:
                    if hasattr(host_info, 'traceroute') and host_info.traceroute():
                        for hop in host_info.traceroute():
                            result.traceroute.append({
                                'ttl': hop.get('ttl', ''),
                                'rtt': hop.get('rtt', ''),
                                'host': hop.get('host', ''),
                                'ipaddr': hop.get('ipaddr', '')
                            })
                except:
                    pass

                # Get open ports
                for proto in host_info.all_protocols():
                    ports_list = host_info[proto].keys()
                    for port in ports_list:
                        port_info = host_info[proto][port]
                        if port_info.get('state') == 'open':
                            result.ports.append(PortInfo(
                                port=port,
                                protocol=proto,
                                state=port_info['state'],
                                service=port_info.get('name', 'unknown'),
                                version=port_info.get('version', ''),
                                product=port_info.get('product', ''),
                                extra_info=port_info.get('extrainfo', '')
                            ))

                        # Parse SSL scripts if present
                        if 'script' in port_info:
                            self._parse_ssl_scripts(port_info['script'], result, port)

                self._log(f"Found {len(result.ports)} open ports")
                if result.host_status:
                    self._log(f"Host status: {result.host_status}")

            else:
                # Host not found in results
                result.host_status = "down"
                self._log("Host appears to be down or not responding")

        except nmap.PortScannerError as e:
            result.error = f"Nmap error: {str(e)}"
            self._log(f"ERROR: {result.error}")
        except Exception as e:
            result.error = f"Scan error: {str(e)}"
            self._log(f"ERROR: {result.error}")

        self._log(f"{scan_name} completed in {result.scan_time:.1f}s")
        return result

    def run_multiple_scans(self, target: str, scan_types: List[ScanType],
                          sequential: bool = True) -> NmapScanResult:
        """
        Run multiple scan types on a target.

        Args:
            target: URL or IP address to scan
            scan_types: List of scan types to run
            sequential: If True, run scans one by one; if False, combine results

        Returns:
            Combined NmapScanResult with all findings
        """
        self._stop_requested = False
        host = self._extract_host(target)
        ip = self._resolve_ip(host)

        combined_result = NmapScanResult(
            target=target,
            ip_address=ip,
            hostname=host,
            scan_time=0
        )

        self._log(f"Running {len(scan_types)} scan(s) on {host}...")

        for i, scan_type in enumerate(scan_types, 1):
            if self._stop_requested:
                self._log("Scans cancelled")
                break

            profile = SCAN_PROFILES[scan_type]
            self._log(f"\n[{i}/{len(scan_types)}] {profile['name']}")
            self._log("=" * 40)

            result = self.run_scan(target, scan_type)

            # Merge results
            combined_result.scan_types.extend(result.scan_types)
            combined_result.scan_time += result.scan_time

            # Merge ports (avoid duplicates)
            existing_ports = {(p.port, p.protocol) for p in combined_result.ports}
            for port in result.ports:
                if (port.port, port.protocol) not in existing_ports:
                    combined_result.ports.append(port)
                    existing_ports.add((port.port, port.protocol))

            # Merge SSL findings (avoid duplicates)
            existing_findings = {f.title for f in combined_result.ssl_findings}
            for finding in result.ssl_findings:
                if finding.title not in existing_findings:
                    combined_result.ssl_findings.append(finding)
                    existing_findings.add(finding.title)

            # Merge other info
            if result.os_info and not combined_result.os_info:
                combined_result.os_info = result.os_info
            if result.host_status and not combined_result.host_status:
                combined_result.host_status = result.host_status
            if result.traceroute and not combined_result.traceroute:
                combined_result.traceroute = result.traceroute

            if result.error:
                if combined_result.error:
                    combined_result.error += f"; {result.error}"
                else:
                    combined_result.error = result.error

        self._log(f"\nAll scans completed. Total time: {combined_result.scan_time:.1f}s")
        self._log(f"Total open ports found: {len(combined_result.ports)}")
        self._log(f"Total SSL findings: {len(combined_result.ssl_findings)}")

        return combined_result


def generate_nmap_html_report(result: NmapScanResult, output_path: str):
    """Generate HTML report for Nmap scan results."""

    severity_colors = {
        Severity.CRITICAL: '#dc2626',
        Severity.HIGH: '#ea580c',
        Severity.MEDIUM: '#ca8a04',
        Severity.LOW: '#2563eb',
        Severity.INFO: '#6b7280'
    }

    scan_types_str = ", ".join(result.scan_types) if result.scan_types else "Basic Scan"

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nmap Scan Report - {result.hostname}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1e3a5f, #0f172a);
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid #334155;
        }}
        .header h1 {{ color: #60a5fa; font-size: 28px; margin-bottom: 10px; }}
        .header p {{ color: #94a3b8; }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .info-item {{
            background: #1e293b;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #334155;
        }}
        .info-label {{ color: #64748b; font-size: 12px; text-transform: uppercase; }}
        .info-value {{ color: #f1f5f9; font-size: 16px; font-weight: 600; margin-top: 5px; }}
        .section {{
            background: #1e293b;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 20px;
            border: 1px solid #334155;
        }}
        .section h2 {{
            color: #60a5fa;
            font-size: 20px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #334155;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        th {{
            background: #0f172a;
            color: #94a3b8;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
        }}
        tr:hover {{ background: #334155; }}
        .port-open {{ color: #4ade80; }}
        .finding {{
            background: #0f172a;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid;
        }}
        .finding-critical {{ border-color: #dc2626; }}
        .finding-high {{ border-color: #ea580c; }}
        .finding-medium {{ border-color: #ca8a04; }}
        .finding-low {{ border-color: #2563eb; }}
        .finding-info {{ border-color: #6b7280; }}
        .finding-title {{
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        .finding-desc {{ color: #94a3b8; font-size: 14px; }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            margin-left: 10px;
        }}
        .badge-critical {{ background: rgba(220, 38, 38, 0.2); color: #dc2626; }}
        .badge-high {{ background: rgba(234, 88, 12, 0.2); color: #ea580c; }}
        .badge-medium {{ background: rgba(202, 138, 4, 0.2); color: #ca8a04; }}
        .badge-low {{ background: rgba(37, 99, 235, 0.2); color: #2563eb; }}
        .badge-info {{ background: rgba(107, 114, 128, 0.2); color: #6b7280; }}
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #64748b;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #64748b;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Nmap Scan Report</h1>
            <p>Network security assessment results</p>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Target</div>
                    <div class="info-value">{result.hostname}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">IP Address</div>
                    <div class="info-value">{result.ip_address}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Open Ports</div>
                    <div class="info-value">{len(result.ports)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Duration</div>
                    <div class="info-value">{result.scan_time:.1f}s</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Scan Type(s)</div>
                    <div class="info-value" style="font-size: 13px;">{scan_types_str}</div>
                </div>
                {f'<div class="info-item"><div class="info-label">OS Detected</div><div class="info-value">{result.os_info}</div></div>' if result.os_info else ''}
                {f'<div class="info-item"><div class="info-label">Host Status</div><div class="info-value">{result.host_status}</div></div>' if result.host_status else ''}
            </div>
        </div>

        <div class="section">
            <h2>Open Ports & Services</h2>
            {'<p class="no-findings">No open ports detected</p>' if not result.ports else ''}
            {'<table><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Version</th></tr></thead><tbody>' if result.ports else ''}
'''

    for port in result.ports:
        version_info = f"{port.product} {port.version}".strip() or port.extra_info or "-"
        html += f'''
            <tr>
                <td class="port-open">{port.port}</td>
                <td>{port.protocol.upper()}</td>
                <td class="port-open">{port.state}</td>
                <td>{port.service}</td>
                <td>{version_info}</td>
            </tr>'''

    if result.ports:
        html += '</tbody></table>'

    html += f'''
        </div>

        <div class="section">
            <h2>SSL/TLS Security Findings</h2>
            {'<p class="no-findings">No SSL/TLS issues detected</p>' if not result.ssl_findings else ''}
'''

    for finding in result.ssl_findings:
        severity_class = finding.severity.name.lower()
        html += f'''
            <div class="finding finding-{severity_class}">
                <div class="finding-title">
                    {finding.title}
                    <span class="severity-badge badge-{severity_class}">{finding.severity.value}</span>
                </div>
                <div class="finding-desc">{finding.description}</div>
            </div>'''

    html += f'''
        </div>

        <div class="footer">
            <p>Generated by ZapGuard | Developed by System Test Team | Maintained by Viswa M</p>
        </div>
    </div>
</body>
</html>'''

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)


def generate_nmap_csv_report(result: NmapScanResult, output_path: str):
    """Generate CSV report for Nmap scan results."""
    import csv

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        # Header info
        writer.writerow(['Nmap Scan Report'])
        writer.writerow(['Target', result.hostname])
        writer.writerow(['IP Address', result.ip_address])
        writer.writerow(['Scan Duration', f'{result.scan_time:.1f}s'])
        writer.writerow(['Scan Type(s)', ', '.join(result.scan_types) if result.scan_types else 'Basic Scan'])
        if result.os_info:
            writer.writerow(['OS Detected', result.os_info])
        if result.host_status:
            writer.writerow(['Host Status', result.host_status])
        writer.writerow([])

        # Open ports
        writer.writerow(['Open Ports'])
        writer.writerow(['Port', 'Protocol', 'State', 'Service', 'Version'])
        for port in result.ports:
            version_info = f"{port.product} {port.version}".strip() or port.extra_info
            writer.writerow([port.port, port.protocol, port.state, port.service, version_info])
        writer.writerow([])

        # SSL Findings
        writer.writerow(['SSL/TLS Findings'])
        writer.writerow(['Severity', 'Title', 'Description', 'Port'])
        for finding in result.ssl_findings:
            writer.writerow([finding.severity.value, finding.title, finding.description, finding.port])
