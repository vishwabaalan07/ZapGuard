# ZapGuard

A professional GUI tool for verifying ZAP (Zed Attack Proxy) vulnerability fixes. ZapGuard parses ZAP security scan reports and automatically tests whether identified vulnerabilities have been remediated.

![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![PySide6](https://img.shields.io/badge/PySide6-6.5+-green.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Features

- **Modern GUI** - Professional dark/light theme interface built with PySide6
- **Multi-format Support** - Parses HTML, XML, and JSON ZAP reports
- **Parallel Testing** - Concurrent vulnerability verification with configurable workers
- **Real-time Progress** - Live updates during validation with stop/cancel support
- **Export Reports** - Generate HTML and CSV verification reports
- **URL Validation** - Built-in URL format validation with visual feedback

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
   git clone https://github.com/vishwabaalan07/zapguard.git
   cd zapguard
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### GUI Mode (Recommended)

```bash
python zapguard_gui.py
```

1. Enter the target URL (the application you want to verify)
2. Browse and select your ZAP report file (.html, .xml, or .json)
3. Choose an output directory for reports
4. Click **Start Validation**

### CLI Mode

For automated/scripted usage, edit `config.py` with your settings:

```python
BASE_URL = "http://your-target-url.com"
ZAP_REPORT_PATH = r"path/to/your/zap_report.html"
REQUEST_TIMEOUT = 20
MAX_WORKERS = 10
```

Then run:
```bash
python zap_verify.py
```

## Project Structure

```
zapguard/
├── zapguard_gui.py        # Main GUI application
├── zap_verify.py          # CLI entry point
├── config.py              # Configuration settings
├── models.py              # Data models (Alert, TestResult, etc.)
├── parsers.py             # ZAP report parsers (HTML, XML, JSON)
├── http_client.py         # HTTP client with retry logic
├── vulnerability_tests.py # Individual vulnerability test classes
├── verifier.py            # Test orchestration with parallel execution
├── reports.py             # HTML/CSV report generators
├── requirements.txt       # Python dependencies
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
- [PySide6](https://doc.qt.io/qtforpython/) - Qt for Python framework
