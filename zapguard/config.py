"""
Configuration settings for ZAP Vulnerability Verification Tool.
"""

import os
from pathlib import Path

# Default configuration values
DEFAULT_TIMEOUT = 20
DEFAULT_MAX_WORKERS = 10

# Get configuration from environment variables or use defaults
REQUEST_TIMEOUT = int(os.environ.get('ZAPGUARD_TIMEOUT', DEFAULT_TIMEOUT))
MAX_WORKERS = int(os.environ.get('ZAPGUARD_WORKERS', DEFAULT_MAX_WORKERS))

# Package directory
PACKAGE_DIR = Path(__file__).parent.resolve()
