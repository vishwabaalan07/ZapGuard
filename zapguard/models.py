"""
Data models and enums for ZAP Vulnerability Verification Tool.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List


class TestStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_TESTABLE = "NOT_TESTABLE"
    ERROR = "ERROR"


class RiskLevel(Enum):
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFORMATIONAL = 0

    @classmethod
    def from_string(cls, value: str) -> 'RiskLevel':
        mapping = {
            'high': cls.HIGH, '3': cls.HIGH,
            'medium': cls.MEDIUM, '2': cls.MEDIUM,
            'low': cls.LOW, '1': cls.LOW,
            'informational': cls.INFORMATIONAL, 'info': cls.INFORMATIONAL, '0': cls.INFORMATIONAL
        }
        return mapping.get(value.lower().strip(), cls.INFORMATIONAL)


@dataclass
class Instance:
    """Represents a single vulnerability instance."""
    url: str
    method: str = "GET"
    parameter: str = ""
    attack: str = ""
    evidence: str = ""
    other_info: str = ""


@dataclass
class Alert:
    """Represents a ZAP alert/vulnerability finding."""
    plugin_id: str
    name: str
    risk_level: RiskLevel
    description: str = ""
    solution: str = ""
    reference: str = ""
    cwe_id: str = ""
    wasc_id: str = ""
    instances: List[Instance] = field(default_factory=list)


@dataclass
class TestResult:
    """Result of a vulnerability verification test."""
    alert_name: str
    plugin_id: str
    risk_level: RiskLevel
    status: TestStatus
    endpoint: str
    method: str = "GET"
    details: str = ""
    request_info: str = ""
    response_info: str = ""
