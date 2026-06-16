"""
ZAP report parsers for HTML, XML, and JSON formats.
"""

import json
import re
from pathlib import Path
from typing import List
from xml.etree import ElementTree as ET

from .models import Alert, Instance, RiskLevel


def parse_zap_html_report(html_content: str) -> List[Alert]:
    """Parse ZAP HTML report using regex patterns."""
    alerts = []

    # Find all result tables
    table_pattern = re.compile(
        r'<table\s+class="results">(.*?)</table>',
        re.DOTALL | re.IGNORECASE
    )

    for table_match in table_pattern.finditer(html_content):
        table_content = table_match.group(1)

        # Extract risk level and alert name from header
        header_pattern = re.compile(
            r'<th[^>]*class="risk-(\d+)"[^>]*>.*?<div>(\w+)</div>.*?</th>\s*'
            r'<th[^>]*class="risk-\d+"[^>]*>(.*?)</th>',
            re.DOTALL | re.IGNORECASE
        )
        header_match = header_pattern.search(table_content)

        if not header_match:
            # Try alternative pattern
            header_pattern2 = re.compile(
                r'class="risk-(\d+)"[^>]*>.*?<a\s+id="(\d+)".*?<div>(\w+)</div>.*?</th>\s*'
                r'<th[^>]*>(.*?)</th>',
                re.DOTALL | re.IGNORECASE
            )
            header_match = header_pattern2.search(table_content)
            if header_match:
                risk_code = header_match.group(1)
                plugin_id = header_match.group(2)
                alert_name = header_match.group(4).strip()
            else:
                continue
        else:
            risk_code = header_match.group(1)
            alert_name = header_match.group(3).strip()
            plugin_id = ""

        # Extract Plugin ID
        plugin_pattern = re.compile(
            r'<td[^>]*>Plugin\s*Id</td>\s*<td[^>]*>.*?(\d+).*?</td>',
            re.DOTALL | re.IGNORECASE
        )
        plugin_match = plugin_pattern.search(table_content)
        if plugin_match:
            plugin_id = plugin_match.group(1)

        # Extract CWE ID
        cwe_pattern = re.compile(
            r'<td[^>]*>CWE\s*Id</td>\s*<td[^>]*>.*?definitions/(\d+)',
            re.DOTALL | re.IGNORECASE
        )
        cwe_match = cwe_pattern.search(table_content)
        cwe_id = cwe_match.group(1) if cwe_match else ""

        # Extract WASC ID
        wasc_pattern = re.compile(
            r'<td[^>]*>WASC\s*Id</td>\s*<td[^>]*>(\d+)</td>',
            re.DOTALL | re.IGNORECASE
        )
        wasc_match = wasc_pattern.search(table_content)
        wasc_id = wasc_match.group(1) if wasc_match else ""

        # Extract Description
        desc_pattern = re.compile(
            r'<td[^>]*>Description</td>\s*<td[^>]*>(.*?)</td>',
            re.DOTALL | re.IGNORECASE
        )
        desc_match = desc_pattern.search(table_content)
        description = ""
        if desc_match:
            description = re.sub(r'<[^>]+>', ' ', desc_match.group(1)).strip()
            description = re.sub(r'\s+', ' ', description)

        # Extract Solution
        sol_pattern = re.compile(
            r'<td[^>]*>Solution</td>\s*<td[^>]*>(.*?)</td>',
            re.DOTALL | re.IGNORECASE
        )
        sol_match = sol_pattern.search(table_content)
        solution = ""
        if sol_match:
            solution = re.sub(r'<[^>]+>', ' ', sol_match.group(1)).strip()
            solution = re.sub(r'\s+', ' ', solution)

        # Create alert
        alert = Alert(
            plugin_id=plugin_id,
            name=alert_name,
            risk_level=RiskLevel.from_string(risk_code),
            description=description,
            solution=solution,
            cwe_id=cwe_id,
            wasc_id=wasc_id
        )

        # Extract instances
        instance_block_pattern = re.compile(
            r'class="indent1"[^>]*>URL</td>\s*<td[^>]*>.*?href="([^"]+)".*?</td>'
            r'.*?class="indent2"[^>]*>Method</td>\s*<td[^>]*>([^<]*)</td>'
            r'.*?class="indent2"[^>]*>Parameter</td>\s*<td[^>]*>([^<]*)</td>'
            r'.*?class="indent2"[^>]*>Attack</td>\s*<td[^>]*>([^<]*)</td>'
            r'.*?class="indent2"[^>]*>Evidence</td>\s*<td[^>]*>(.*?)</td>'
            r'.*?class="indent2"[^>]*>Other Info</td>\s*<td[^>]*>(.*?)</td>',
            re.DOTALL | re.IGNORECASE
        )

        for inst_match in instance_block_pattern.finditer(table_content):
            instance = Instance(
                url=inst_match.group(1).strip(),
                method=inst_match.group(2).strip() or "GET",
                parameter=inst_match.group(3).strip(),
                attack=inst_match.group(4).strip(),
                evidence=re.sub(r'<[^>]+>', '', inst_match.group(5)).strip(),
                other_info=re.sub(r'<[^>]+>', '', inst_match.group(6)).strip()
            )
            alert.instances.append(instance)

        # Fallback: simpler URL extraction
        if not alert.instances:
            url_pattern = re.compile(
                r'<td[^>]*class="indent1"[^>]*>URL</td>\s*'
                r'<td[^>]*><a\s+href="([^"]+)"[^>]*>[^<]*</a></td>',
                re.DOTALL | re.IGNORECASE
            )
            for url_match in url_pattern.finditer(table_content):
                instance = Instance(url=url_match.group(1).strip())
                alert.instances.append(instance)

        if alert.instances:
            alerts.append(alert)

    return alerts


def parse_zap_xml_report(xml_content: str) -> List[Alert]:
    """Parse ZAP XML report."""
    alerts = []
    root = ET.fromstring(xml_content)

    alert_items = []

    # Format 1: OWASPZAPReport/site/alerts/alertitem
    for site in root.findall('.//site'):
        alert_items.extend(site.findall('.//alertitem'))

    # Format 2: Direct alerts
    if not alert_items:
        alert_items = root.findall('.//alertitem')

    for item in alert_items:
        alert = Alert(
            plugin_id=item.findtext('pluginid', ''),
            name=item.findtext('alert', '') or item.findtext('name', ''),
            risk_level=RiskLevel.from_string(item.findtext('riskcode', '0')),
            description=item.findtext('desc', ''),
            solution=item.findtext('solution', ''),
            reference=item.findtext('reference', ''),
            cwe_id=item.findtext('cweid', ''),
            wasc_id=item.findtext('wascid', '')
        )

        instances_elem = item.find('instances')
        if instances_elem is not None:
            for inst in instances_elem.findall('instance'):
                instance = Instance(
                    url=inst.findtext('uri', ''),
                    method=inst.findtext('method', 'GET'),
                    parameter=inst.findtext('param', ''),
                    attack=inst.findtext('attack', ''),
                    evidence=inst.findtext('evidence', '')
                )
                alert.instances.append(instance)
        else:
            instance = Instance(
                url=item.findtext('uri', ''),
                method=item.findtext('method', 'GET'),
                parameter=item.findtext('param', ''),
                attack=item.findtext('attack', ''),
                evidence=item.findtext('evidence', '')
            )
            if instance.url:
                alert.instances.append(instance)

        if alert.instances:
            alerts.append(alert)

    return alerts


def parse_zap_json_report(json_content: str) -> List[Alert]:
    """Parse ZAP JSON report."""
    alerts = []
    data = json.loads(json_content)

    alert_items = []

    if 'site' in data:
        sites = data['site'] if isinstance(data['site'], list) else [data['site']]
        for site in sites:
            if 'alerts' in site:
                alert_items.extend(site['alerts'])
    elif 'alerts' in data:
        alert_items = data['alerts']

    for item in alert_items:
        alert = Alert(
            plugin_id=str(item.get('pluginid', '')),
            name=item.get('alert', '') or item.get('name', ''),
            risk_level=RiskLevel.from_string(str(item.get('riskcode', '0'))),
            description=item.get('desc', ''),
            solution=item.get('solution', ''),
            reference=item.get('reference', ''),
            cwe_id=str(item.get('cweid', '')),
            wasc_id=str(item.get('wascid', ''))
        )

        for inst in item.get('instances', []):
            instance = Instance(
                url=inst.get('uri', ''),
                method=inst.get('method', 'GET'),
                parameter=inst.get('param', ''),
                attack=inst.get('attack', ''),
                evidence=inst.get('evidence', '')
            )
            alert.instances.append(instance)

        if alert.instances:
            alerts.append(alert)

    return alerts


def parse_zap_report(report_path: str) -> List[Alert]:
    """Parse ZAP report based on file extension."""
    path = Path(report_path)

    if not path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")

    content = path.read_text(encoding='utf-8', errors='ignore')
    extension = path.suffix.lower()

    if extension in ['.html', '.htm']:
        return parse_zap_html_report(content)
    elif extension == '.xml':
        return parse_zap_xml_report(content)
    elif extension == '.json':
        return parse_zap_json_report(content)
    else:
        raise ValueError(f"Unsupported file format: {extension}")
