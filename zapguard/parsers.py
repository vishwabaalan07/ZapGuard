"""
ZAP report parsers for HTML, XML, and JSON formats.
"""

import json
import re
from pathlib import Path
from typing import List
from xml.etree import ElementTree

from .models import Alert, Instance, RiskLevel


def parse_zap_report(file_path: str) -> List[Alert]:
    """Parse ZAP report file and return list of alerts."""
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Report file not found: {file_path}")

    suffix = path.suffix.lower()
    content = path.read_text(encoding='utf-8', errors='ignore')

    if suffix == '.json':
        return _parse_json_report(content)
    elif suffix == '.xml':
        return _parse_xml_report(content)
    else:
        return _parse_html_report(content)


def _parse_json_report(content: str) -> List[Alert]:
    """Parse JSON format ZAP report."""
    data = json.loads(content)
    alerts = []

    sites = data.get('site', [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_alerts = site.get('alerts', [])
        for alert_data in site_alerts:
            instances = []
            for inst in alert_data.get('instances', []):
                instances.append(Instance(
                    url=inst.get('uri', ''),
                    method=inst.get('method', 'GET'),
                    parameter=inst.get('param', ''),
                    attack=inst.get('attack', ''),
                    evidence=inst.get('evidence', '')
                ))

            alerts.append(Alert(
                plugin_id=str(alert_data.get('pluginid', '')),
                name=alert_data.get('name', ''),
                risk_level=RiskLevel.from_string(alert_data.get('riskdesc', '').split()[0] if alert_data.get('riskdesc') else 'info'),
                description=alert_data.get('desc', ''),
                solution=alert_data.get('solution', ''),
                instances=instances
            ))

    return alerts


def _parse_xml_report(content: str) -> List[Alert]:
    """Parse XML format ZAP report."""
    root = ElementTree.fromstring(content)
    alerts = []

    for site in root.findall('.//site'):
        for alert_elem in site.findall('.//alertitem'):
            instances = []
            for inst in alert_elem.findall('.//instance'):
                instances.append(Instance(
                    url=inst.findtext('uri', ''),
                    method=inst.findtext('method', 'GET'),
                    parameter=inst.findtext('param', ''),
                    attack=inst.findtext('attack', ''),
                    evidence=inst.findtext('evidence', '')
                ))

            alerts.append(Alert(
                plugin_id=alert_elem.findtext('pluginid', ''),
                name=alert_elem.findtext('name', ''),
                risk_level=RiskLevel.from_string(alert_elem.findtext('riskcode', '0')),
                description=alert_elem.findtext('desc', ''),
                solution=alert_elem.findtext('solution', ''),
                instances=instances
            ))

    return alerts


def _parse_html_report(content: str) -> List[Alert]:
    """Parse HTML format ZAP report."""
    alerts = []

    alert_pattern = r'<tr[^>]*class="risk-(\w+)"[^>]*>.*?<td[^>]*>(\d+)</td>.*?<td[^>]*>(.*?)</td>'
    detail_pattern = r'<div[^>]*class="alert-detail"[^>]*>.*?<h3[^>]*>(.*?)</h3>.*?plugin[:\s]+(\d+).*?</div>'

    # Try parsing alert tables
    table_matches = re.findall(
        r'<tr[^>]*>.*?<td[^>]*>(\d+)</td>.*?<td[^>]*>(.*?)</td>.*?<td[^>]*>(\d+)</td>.*?</tr>',
        content, re.DOTALL | re.IGNORECASE
    )

    if table_matches:
        for match in table_matches:
            plugin_id, name, risk = match[0], match[1], match[2]
            name = re.sub(r'<[^>]+>', '', name).strip()

            instances = _extract_instances_html(content, plugin_id)

            alerts.append(Alert(
                plugin_id=plugin_id,
                name=name,
                risk_level=RiskLevel.from_string(risk),
                instances=instances
            ))
    else:
        # Alternative HTML format parsing
        alert_sections = re.findall(
            r'<h\d[^>]*>(.*?)</h\d>.*?(?:Plugin\s*(?:ID)?[:\s]*|pluginid[:\s]*)(\d+)',
            content, re.DOTALL | re.IGNORECASE
        )

        for name, plugin_id in alert_sections:
            name = re.sub(r'<[^>]+>', '', name).strip()
            instances = _extract_instances_html(content, plugin_id)

            alerts.append(Alert(
                plugin_id=plugin_id,
                name=name,
                risk_level=RiskLevel.MEDIUM,
                instances=instances
            ))

    return alerts


def _extract_instances_html(content: str, plugin_id: str) -> List[Instance]:
    """Extract instances for a specific alert from HTML content."""
    instances = []

    url_patterns = [
        rf'(?:URL|URI|Endpoint)[:\s]*(?:<[^>]+>)*\s*(https?://[^\s<"\']+)',
        rf'<td[^>]*>(?:<[^>]+>)*(https?://[^\s<"\']+)',
    ]

    seen_urls = set()
    for pattern in url_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for url in matches:
            if url not in seen_urls:
                seen_urls.add(url)
                instances.append(Instance(url=url, method="GET"))

    return instances


def parse_zap_html_report(file_path: str) -> List[Alert]:
    """Legacy function for HTML report parsing."""
    return parse_zap_report(file_path)
