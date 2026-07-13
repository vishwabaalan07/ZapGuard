"""
Report generators for HTML, CSV, and PDF output.
"""

import csv
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from .models import Alert, TestResult, TestStatus, RiskLevel


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
            cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;
            text-decoration: none; display: block;
        }}
        .summary-card:hover {{
            transform: translateY(-3px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
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

        .status-section {{ scroll-margin-top: 20px; }}
        .status-section-header {{
            background: #fff; padding: 15px 20px; border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 30px 0 15px 0;
            display: flex; align-items: center; gap: 10px;
        }}
        .status-section-header h2 {{ margin: 0; }}

        .back-to-top {{
            display: inline-flex; align-items: center; gap: 6px;
            background: #2874a6; color: white; padding: 8px 16px;
            border-radius: 6px; text-decoration: none; font-size: 13px;
            margin: 15px 0; transition: background 0.2s;
        }}
        .back-to-top:hover {{ background: #1a5276; }}
        .back-to-top svg {{ width: 14px; height: 14px; }}

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

        <div id="summary" class="summary-grid">
            <a href="#section-passed" class="summary-card pass">
                <div class="number">{passed}</div>
                <div class="label">PASSED</div>
            </a>
            <a href="#section-failed" class="summary-card fail">
                <div class="number">{failed}</div>
                <div class="label">FAILED</div>
            </a>
            <a href="#section-not-testable" class="summary-card skip">
                <div class="number">{not_testable}</div>
                <div class="label">NOT TESTABLE</div>
            </a>
            <a href="#section-errors" class="summary-card error">
                <div class="number">{errors}</div>
                <div class="label">ERRORS</div>
            </a>
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

    # Add status-based sections
    status_sections = [
        ('section-passed', 'Passed', TestStatus.PASS, '#27ae60', 'pass'),
        ('section-failed', 'Failed', TestStatus.FAIL, '#e74c3c', 'fail'),
        ('section-not-testable', 'Not Testable', TestStatus.NOT_TESTABLE, '#f39c12', 'skip'),
        ('section-errors', 'Errors', TestStatus.ERROR, '#9b59b6', 'error'),
    ]

    for section_id, section_title, status, color, css_class in status_sections:
        section_results = [r for r in results if r.status == status]
        count = len(section_results)

        html += f'''
        <div id="{section_id}" class="status-section">
            <div class="status-section-header">
                <span class="status {css_class}">{count}</span>
                <h2 style="color: {color};">{section_title} Results</h2>
            </div>
'''
        if section_results:
            html += '''
            <table>
                <tr>
                    <th width="8%">Risk</th>
                    <th width="20%">Vulnerability</th>
                    <th width="8%">Method</th>
                    <th width="34%">Endpoint</th>
                    <th width="30%">Details</th>
                </tr>
'''
            for result in section_results:
                risk_class = result.risk_level.name.lower()
                html += f'''
                <tr>
                    <td><span class="risk {risk_class}">{result.risk_level.name}</span></td>
                    <td>{result.alert_name}</td>
                    <td>{result.method}</td>
                    <td class="endpoint">{result.endpoint}</td>
                    <td class="details">{result.details[:200] if result.details else '-'}</td>
                </tr>
'''
            html += '''
            </table>
'''
        else:
            html += f'''
            <div class="alert-section" style="padding: 20px; text-align: center; color: #666;">
                No {section_title.lower()} results
            </div>
'''
        html += '''
            <a href="#summary" class="back-to-top">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 19V5M5 12l7-7 7 7"/>
                </svg>
                Back to Summary
            </a>
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


def generate_pdf_report(results: List[TestResult], alerts: List[Alert],
                        base_url: str, report_path: str, output_path: str) -> str:
    """Generate PDF verification report."""

    total = len(results)
    passed = sum(1 for r in results if r.status == TestStatus.PASS)
    failed = sum(1 for r in results if r.status == TestStatus.FAIL)
    not_testable = sum(1 for r in results if r.status == TestStatus.NOT_TESTABLE)
    errors = sum(1 for r in results if r.status == TestStatus.ERROR)
    pass_rate = (passed / (total - not_testable) * 100) if (total - not_testable) > 0 else 0

    doc = SimpleDocTemplate(
        output_path,
        pagesize=landscape(A4),
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )

    styles = getSampleStyleSheet()
    elements = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a5276'),
        spaceAfter=20,
        alignment=TA_CENTER
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#2874a6'),
        spaceBefore=15,
        spaceAfter=10
    )

    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        spaceAfter=5
    )

    # Title
    elements.append(Paragraph("ZAP Vulnerability Fix Verification Report", title_style))
    elements.append(Spacer(1, 10))

    # Header info
    elements.append(Paragraph(f"<b>Target URL:</b> {base_url}", normal_style))
    elements.append(Paragraph(f"<b>ZAP Report:</b> {Path(report_path).name}", normal_style))
    elements.append(Paragraph(f"<b>Verification Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
    elements.append(Paragraph(f"<b>Total Alerts:</b> {len(alerts)} types | <b>Total Instances:</b> {total}", normal_style))
    elements.append(Spacer(1, 15))

    # Summary table
    elements.append(Paragraph("Summary", heading_style))

    summary_data = [
        ['Pass Rate', 'Passed', 'Failed', 'Not Testable', 'Errors', 'Total'],
        [f'{pass_rate:.1f}%', str(passed), str(failed), str(not_testable), str(errors), str(total)]
    ]

    summary_table = Table(summary_data, colWidths=[80, 70, 70, 90, 70, 70])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2874a6')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('FONTSIZE', (0, 1), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('TOPPADDING', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (0, 1), colors.HexColor('#27ae60')),  # Pass rate green
        ('TEXTCOLOR', (0, 1), (0, 1), colors.white),
        ('FONTNAME', (0, 1), (0, 1), 'Helvetica-Bold'),
        ('BACKGROUND', (1, 1), (1, 1), colors.HexColor('#d4edda')),  # Passed
        ('BACKGROUND', (2, 1), (2, 1), colors.HexColor('#f8d7da')),  # Failed
        ('BACKGROUND', (3, 1), (3, 1), colors.HexColor('#fff3cd')),  # Not testable
        ('BACKGROUND', (4, 1), (4, 1), colors.HexColor('#e2d5f1')),  # Errors
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 20))

    # Status color mapping
    status_bg_colors = {
        TestStatus.PASS: colors.HexColor('#d4edda'),
        TestStatus.FAIL: colors.HexColor('#f8d7da'),
        TestStatus.NOT_TESTABLE: colors.HexColor('#fff3cd'),
        TestStatus.ERROR: colors.HexColor('#e2d5f1'),
    }

    # Results sections by status
    status_sections = [
        ('Failed Results', TestStatus.FAIL),
        ('Error Results', TestStatus.ERROR),
        ('Passed Results', TestStatus.PASS),
        ('Not Testable Results', TestStatus.NOT_TESTABLE),
    ]

    for section_title, status in status_sections:
        section_results = [r for r in results if r.status == status]
        if not section_results:
            continue

        elements.append(Paragraph(f"{section_title} ({len(section_results)})", heading_style))

        # Table header
        table_data = [['Status', 'Risk', 'Vulnerability', 'Method', 'Endpoint', 'Details']]

        for result in section_results:
            endpoint = result.endpoint[:50] + '...' if len(result.endpoint) > 50 else result.endpoint
            details = (result.details[:60] + '...') if result.details and len(result.details) > 60 else (result.details or '-')

            table_data.append([
                result.status.value,
                result.risk_level.name,
                result.alert_name[:30] + '...' if len(result.alert_name) > 30 else result.alert_name,
                result.method,
                endpoint,
                details
            ])

        col_widths = [65, 55, 120, 45, 180, 200]
        results_table = Table(table_data, colWidths=col_widths, repeatRows=1)

        # Build table style
        table_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2874a6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 1), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('ALIGN', (0, 0), (0, -1), 'CENTER'),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('ALIGN', (3, 0), (3, -1), 'CENTER'),
        ]

        # Color rows based on status
        for i in range(1, len(table_data)):
            bg_color = status_bg_colors.get(status, colors.white)
            table_style.append(('BACKGROUND', (0, i), (0, i), bg_color))

        results_table.setStyle(TableStyle(table_style))
        elements.append(results_table)
        elements.append(Spacer(1, 15))

    # Footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dee2e6')))
    elements.append(Spacer(1, 10))

    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#666666'),
        alignment=TA_CENTER
    )
    elements.append(Paragraph("ZAP Vulnerability Fix Verification Report", footer_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", footer_style))

    doc.build(elements)
    return output_path
