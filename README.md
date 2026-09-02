# ZapGuard

Vulnerability Fix Verification Tool - Parses ZAP security scan reports and verifies whether vulnerabilities have been remediated. Includes optional Nmap port/service scanning.

## Features

- **Web Interface** - Dark/light theme, responsive design
- **Multi-format Support** - HTML, XML, JSON ZAP reports
- **Nmap Integration** - Port scanning with multiple scan profiles
- **Real-time Progress** - Live updates with stop/cancel support
- **Export Reports** - HTML, PDF, CSV, and Nmap reports
- **404 Page Testing** - Security headers checked even on error pages

## Supported Tests

| Vulnerability | Plugin IDs |
|--------------|------------|
| Content-Security-Policy | 10038, 10055, 70008, 70010 |
| X-Frame-Options | 10020 |
| Host Header Injection | 20019 |
| Vulnerable JS Libraries | 10003 |
| CSRF Token | 10202, 20012 |
| Charset in Content-Type | 70002 |
| Permissions-Policy | 10063 |
| Subresource Integrity | 90003 |

## Nmap Scan Types

| Scan | Description |
|------|-------------|
| Quick | Fast port scan (-F flag) |
| Regular | Top 1000 ports |
| Service Detection | Version detection (-sV) |
| SSL/TLS | SSL certificate and cipher analysis |
| Full | Comprehensive scan with scripts |

## Installation

```bash
# Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements-web.txt
```

**Nmap**: Install from https://nmap.org/download.html and add to PATH.

## Usage

```bash
python run_web.py
```

Access at: `http://localhost:5005`

### Options
```bash
python run_web.py --port 8080        # Custom port
python run_web.py --host 0.0.0.0     # Allow external access
```

## Project Structure

```
zapguard/
├── zapguard/
│   ├── web_app.py           # Flask web application
│   ├── nmap_scanner.py      # Nmap integration
│   ├── vulnerability_tests.py
│   ├── templates/index.html
│   └── static/css/, js/
├── run_web.py               # Entry point
└── requirements-web.txt
```

## Credits

Developed by System Test Team | Maintained by Viswa M
