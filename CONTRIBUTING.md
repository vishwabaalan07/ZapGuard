# Contributing to ZapGuard

Thank you for your interest in contributing to ZapGuard! This document provides guidelines and information for contributors.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Set up your development environment
4. Create a new branch for your feature or bugfix

## Development Setup

```bash
# Clone your fork
git clone https://github.com/vishwabaalan07/zapguard.git
cd zapguard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy config example
cp config.example.py config.py
# Edit config.py with your test settings
```

## Code Style

- Follow PEP 8 guidelines
- Use meaningful variable and function names
- Add docstrings to all public functions and classes
- Keep functions focused and concise

## Adding New Vulnerability Tests

To add support for a new ZAP plugin:

1. Create a new test class in `vulnerability_tests.py`:

```python
class YourNewTest(VulnerabilityTest):
    """Test for your vulnerability type."""

    def test(self, alert: Alert, instance: Instance) -> TestResult:
        # Your test logic here
        url = self.client.get_full_url(instance.url)
        response = self.client.get(url)
        
        if response.get('error'):
            return self.create_result(alert, instance, TestStatus.ERROR,
                                      f"Request failed: {response['error']}")
        
        # Check for vulnerability
        if vulnerability_fixed:
            return self.create_result(alert, instance, TestStatus.PASS,
                                     "Vulnerability has been fixed")
        else:
            return self.create_result(alert, instance, TestStatus.FAIL,
                                     "Vulnerability still present")
```

2. Register your test in the `PLUGIN_TESTS` dictionary:

```python
PLUGIN_TESTS = {
    # ... existing entries ...
    'YOUR_PLUGIN_ID': YourNewTest,
}
```

## Submitting Changes

1. Ensure your code follows the style guidelines
2. Test your changes thoroughly
3. Update documentation if needed
4. Commit with clear, descriptive messages
5. Push to your fork
6. Open a Pull Request

## Pull Request Guidelines

- Provide a clear description of the changes
- Reference any related issues
- Include screenshots for UI changes
- Ensure all tests pass

## Reporting Issues

When reporting issues, please include:

- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages or screenshots

## Questions?

Feel free to open an issue for questions or discussions.
