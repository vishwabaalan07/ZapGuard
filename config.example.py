"""
Configuration settings for ZAP Vulnerability Verification Tool.
Copy this file to config.py and edit the values to match your environment.
"""

from pathlib import Path

# ============================================
# CONFIGURATION - EDIT THESE VALUES
# ============================================

# Target URL to verify vulnerabilities against
BASE_URL = "http://your-target-url.com"

# Path to ZAP report file (HTML, XML, or JSON)
ZAP_REPORT_PATH = r"C:\path\to\your\zap_report.html"

# Request timeout in seconds
REQUEST_TIMEOUT = 20

# Number of parallel request threads
MAX_WORKERS = 10

# ============================================

# Script directory for output files (do not modify)
SCRIPT_DIR = Path(__file__).parent.resolve()
