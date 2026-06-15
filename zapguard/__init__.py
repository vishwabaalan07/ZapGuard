"""
ZapGuard - ZAP Vulnerability Fix Verification Tool

A professional tool for verifying whether ZAP-identified vulnerabilities have been fixed.
"""

__version__ = "1.0.0"
__author__ = "Viswa Vengata Baalan M"

from .models import Alert, Instance, TestResult, TestStatus, RiskLevel
from .parsers import parse_zap_report
from .verifier import VulnerabilityVerifier

__all__ = [
    "Alert",
    "Instance",
    "TestResult",
    "TestStatus",
    "RiskLevel",
    "parse_zap_report",
    "VulnerabilityVerifier",
]
