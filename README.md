# ZapGuard

A professional tool for verifying ZAP (Zed Attack Proxy) vulnerability fixes. ZapGuard parses ZAP security scan reports and automatically tests whether identified vulnerabilities have been remediated. Available as both a desktop GUI and a web application.

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![PySide6](https://img.shields.io/badge/PySide6-6.5+-green.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-orange.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

- **Desktop & Web Interface** - Professional dark/light theme interface available as desktop GUI (PySide6) or web application (Flask)
- **Multi-format Support** - Parses HTML, XML, and JSON ZAP reports
- **Parallel Testing** - Concurrent vulnerability verification with configurable workers
- **Real-time Progress** - Live updates during validation with stop/cancel support
- **Export Reports** - Generate HTML, PDF, and CSV verification reports
- **URL Validation** - Built-in URL/IP format validation with visual feedback
- **Filtering & Sorting** - Filter results by status, risk level, and search; sort by any column
- **Vulnerability Details Panel** - View full details of selected vulnerabilities
- **Responsive Design** - Adapts to different screen sizes

## Supported Vulnerability Tests

| Plugin ID | Vulnerability Type |
|-----------|-------------------|
| 10038, 10055, 70008, 70010 | Content-Security-Policy Header |
| 10020 | X-Frame-Options Header |
| 20019 | Host Header Injection |
| 10003 | Vulnerable JavaScript Libraries |
| 10202, 20012 | CSRF Token Verification |
| 70002 | Charset in Content-Type |
| 10063 | Permissions-Policy Header |
| 90003 | Subresource Integrity (SRI) |

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/vishwabaalan07/ZapGuard.git
   cd zapguard
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   # Full installation (Desktop GUI + Web)
   pip install -r requirements.txt

   # Web-only installation (lighter, no PySide6)
   pip install -r requirements-web.txt
   ```

## Usage

### Desktop GUI Mode

```bash
python run_gui.py
```

1. Select scheme (https/http) and enter the target URL or IP
2. Browse and select your ZAP report file (.html, .xml, or .json)
3. Choose an output directory for reports
4. Click **Start Validation**
5. Use filters to narrow down results
6. Click on any row to see full vulnerability details
7. Export results as HTML, PDF, or CSV

### Web Mode

```bash
python run_web.py
```

Access at: `http://localhost:5005`

**Command line options:**
```bash
python run_web.py --host 0.0.0.0 --port 5005  # Default settings
python run_web.py --port 8080                  # Custom port
python run_web.py --debug                      # Enable debug mode
```

**Deploying on a Server:**
```bash
# On Linux server
pip install -r requirements-web.txt
python run_web.py --host 0.0.0.0 --port 5005

# Access from: http://<server-ip>:5005
```

### CLI Mode

```bash
python run_cli.py -u http://your-target-url.com -r path/to/zap_report.html
```

CLI options:
```
-u, --url       Target URL to verify against (required)
-r, --report    Path to ZAP report file (required)
-o, --output    Output directory for reports (default: current directory)
-t, --timeout   Request timeout in seconds (default: 20)
-w, --workers   Number of parallel workers (default: 10)
```

### Install as Package (Optional)

```bash
pip install -e .
```

Then run from anywhere:
```bash
zapguard      # GUI mode
zapguard-cli  # CLI mode
```

## Project Structure

```
zapguard/
├── .github/               # GitHub templates
│   ├── ISSUE_TEMPLATE/
│   └── pull_request_template.md
├── zapguard/              # Main package
│   ├── __init__.py
│   ├── gui.py             # Desktop GUI application (PySide6)
│   ├── web_app.py         # Web application (Flask)
│   ├── cli.py             # CLI application
│   ├── config.py          # Configuration settings
│   ├── models.py          # Data models (Alert, TestResult, etc.)
│   ├── parsers.py         # ZAP report parsers (HTML, XML, JSON)
│   ├── http_client.py     # HTTP client with retry logic (requests)
│   ├── vulnerability_tests.py  # Vulnerability test classes
│   ├── verifier.py        # Test orchestration
│   ├── reports.py         # HTML/PDF/CSV report generators
│   ├── templates/         # Web HTML templates
│   │   └── index.html
│   └── static/            # Web static assets
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── app.js
├── run_gui.py             # Desktop GUI entry point
├── run_web.py             # Web server entry point
├── run_cli.py             # CLI entry point
├── config.example.py      # Example configuration
├── requirements.txt       # Full dependencies (GUI + Web)
├── requirements-web.txt   # Web-only dependencies
├── pyproject.toml         # Package configuration
├── LICENSE                # MIT License
└── README.md              # This file
```

## Configuration

### Environment Variables (Optional)

You can override default settings using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `ZAPGUARD_TIMEOUT` | Request timeout in seconds | 20 |
| `ZAPGUARD_WORKERS` | Number of parallel workers | 10 |

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Code Style

This project follows PEP 8 guidelines. Format code with:
```bash
black .
isort .
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [OWASP ZAP](https://www.zaproxy.org/) - The security scanner that generates the reports
- [PySide6](https://doc.qt.io/qtforpython/) - Qt for Python framework (Desktop GUI)
- [Flask](https://flask.palletsprojects.com/) - Python web framework (Web version)
- [ReportLab](https://www.reportlab.com/) - PDF generation library
