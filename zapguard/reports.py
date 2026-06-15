"""
Report generators for HTML and CSV output.
"""

import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .models import Alert, TestResult, TestStatus


def generate_html_report(results: List[TestResult], alerts: List[Alert],
                         base_url: str, report_path: str, output_path: str) -> str:
    """Generate HTML verification report."""

    total = len(results)
    passed = sum(1 for r in results if r.status == TestStatus.PASS)
    failed = sum(1 for r in results if r.status == TestStatus.FAIL)
    not_testable = sum(1 for r in results if r.status == TestStatus.NOT_TESTABLE)
    errors = sum(1 for r in results if r.status == TestStatus.ERROR)

    pass_rate = (passed / (total - not_testable) * 100) if (total - not_testable) > 0 else 0

    results_by_alert: Dict[str, List[TestResult]] = {}
    for result in results:
        key = f"{result.plugin_id}_{result.alert_name}"
        if key not in results_by_alert:
            results_by_alert[key] = []
        results_by_alert[key].append(result)

    html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ZAP Vulnerability Fix Verification Report</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            margin: 0; padding: 20px; background: #f5f5f5; color: #333;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #1a5276; border-bottom: 3px solid #1a5276; padding-bottom: 15px; }}
        h2 {{ color: #2874a6; margin-top: 30px; }}

        .header-info {{
            background: #fff; padding: 20px; border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;
        }}
        .header-info p {{ margin: 8px 0; }}

        .summary-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px; margin: 20px 0;
        }}
        .summary-card {{
            background: #fff; padding: 20px; border-radius: 8px; text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card .number {{ font-size: 36px; font-weight: bold; }}
        .summary-card .label {{ color: #666; margin-top: 5px; }}
        .summary-card.pass {{ border-top: 4px solid #27ae60; }}
        .summary-card.pass .number {{ color: #27ae60; }}
        .summary-card.fail {{ border-top: 4px solid #e74c3c; }}
        .summary-card.fail .number {{ color: #e74c3c; }}
        .summary-card.skip {{ border-top: 4px solid #f39c12; }}
        .summary-card.skip .number {{ color: #f39c12; }}
        .summary-card.error {{ border-top: 4px solid #9b59b6; }}
        .summary-card.error .number {{ color: #9b59b6; }}

        .pass-rate {{
            background: linear-gradient(135deg, #27ae60, #2ecc71);
            color: white; padding: 30px; border-radius: 8px; text-align: center;
            margin: 20px 0;
        }}
        .pass-rate .rate {{ font-size: 48px; font-weight: bold; }}

        table {{
            width: 100%; border-collapse: collapse; margin: 20px 0;
            background: #fff; border-radius: 8px; overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #2874a6; color: white; font-weight: 600; }}
        tr:hover {{ background: #f8f9fa; }}

        .status {{
            padding: 4px 12px; border-radius: 20px; font-weight: 600;
            display: inline-block; font-size: 12px;
        }}
        .status.pass {{ background: #d4edda; color: #155724; }}
        .status.fail {{ background: #f8d7da; color: #721c24; }}
        .status.skip {{ background: #fff3cd; color: #856404; }}
        .status.error {{ background: #e2d5f1; color: #5a3d7a; }}

        .risk {{ padding: 4px 10px; border-radius: 4px; color: white; font-size: 11px; }}
        .risk.high {{ background: #e74c3c; }}
        .risk.medium {{ background: #f39c12; }}
        .risk.low {{ background: #f1c40f; color: #333; }}
        .risk.info {{ background: #3498db; }}

        .endpoint {{ font-family: monospace; font-size: 12px; word-break: break-all; }}
        .details {{ font-size: 12px; color: #666; max-width: 400px; }}

        .alert-section {{
            background: #fff; margin: 20px 0; border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;
        }}
        .alert-header {{
            padding: 15px 20px; background: #f8f9fa;
            border-bottom: 1px solid #eee; display: flex;
            justify-content: space-between; align-items: center;
        }}
        .alert-header h3 {{ margin: 0; font-size: 16px; }}
        .alert-stats {{ display: flex; gap: 15px; }}
        .alert-stats span {{ font-size: 13px; }}

        .footer {{
            margin-top: 40px; padding: 20px; text-align: center;
            color: #666; font-size: 12px; border-top: 1px solid #ddd;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>ZAP Vulnerability Fix Verification Report</h1>

        <div class="header-info">
            <p><strong>Target URL:</strong> {base_url}</p>
            <p><strong>ZAP Report:</strong> {report_path}</p>
            <p><strong>Verification Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Total Alerts:</strong> {len(alerts)} types | <strong>Total Instances:</strong> {total}</p>
        </div>

        <div class="pass-rate">
            <div class="rate">{pass_rate:.1f}%</div>
            <div>Pass Rate (excluding not testable)</div>
        </div>

        <div class="summary-grid">
            <div class="summary-card pass">
                <div class="number">{passed}</div>
                <div class="label">PASSED</div>
            </div>
            <div class="summary-card fail">
                <div class="number">{failed}</div>
                <div class="label">FAILED</div>
            </div>
            <div class="summary-card skip">
                <div class="number">{not_testable}</div>
                <div class="label">NOT TESTABLE</div>
            </div>
            <div class="summary-card error">
                <div class="number">{errors}</div>
                <div class="label">ERRORS</div>
            </div>
        </div>

        <h2>Results by Alert Type</h2>
'''

    for key, alert_results in results_by_alert.items():
        if not alert_results:
            continue

        first = alert_results[0]
        alert_passed = sum(1 for r in alert_results if r.status == TestStatus.PASS)
        alert_failed = sum(1 for r in alert_results if r.status == TestStatus.FAIL)

        risk_class = first.risk_level.name.lower()

        html += f'''
        <div class="alert-section">
            <div class="alert-header">
                <h3>
                    <span class="risk {risk_class}">{first.risk_level.name}</span>
                    {first.alert_name} (Plugin: {first.plugin_id})
                </h3>
                <div class="alert-stats">
                    <span style="color:#27ae60">&#10003; {alert_passed}</span>
                    <span style="color:#e74c3c">&#10007; {alert_failed}</span>
                    <span>Total: {len(alert_results)}</span>
                </div>
            </div>
            <table>
                <tr>
                    <th width="10%">Status</th>
                    <th width="8%">Method</th>
                    <th width="40%">Endpoint</th>
                    <th width="42%">Details</th>
                </tr>
'''

        for result in alert_results:
            status_class = result.status.value.lower().replace('_', '')
            if status_class == 'nottestable':
                status_class = 'skip'

            html += f'''
                <tr>
                    <td><span class="status {status_class}">{result.status.value}</span></td>
                    <td>{result.method}</td>
                    <td class="endpoint">{result.endpoint}</td>
                    <td class="details">{result.details[:200] if result.details else '-'}</td>
                </tr>
'''

        html += '''
            </table>
        </div>
'''

    html += f'''
        <div class="footer">
            <p>ZAP Vulnerability Fix Verification Report</p>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
'''

    Path(output_path).write_text(html, encoding='utf-8')
    return output_path


def generate_csv_report(results: List[TestResult], output_path: str) -> str:
    """Generate CSV report."""
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Status', 'Risk Level', 'Plugin ID', 'Alert Name',
                        'Method', 'Endpoint', 'Details'])

        for result in results:
            writer.writerow([
                result.status.value,
                result.risk_level.name,
                result.plugin_id,
                result.alert_name,
                result.method,
                result.endpoint,
                result.details
            ])

    return output_path
