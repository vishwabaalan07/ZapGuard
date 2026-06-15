"""
HTTP client with SSL bypass and retry logic for vulnerability testing.
"""

import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse


class HTTPClient:
    """HTTP client with SSL certificate bypass for testing."""

    def __init__(self, base_url: str, timeout: int = 20):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def get_full_url(self, endpoint: str) -> str:
        """Convert endpoint to full URL."""
        if endpoint.startswith('http://') or endpoint.startswith('https://'):
            parsed = urllib.parse.urlparse(endpoint)
            if parsed.query:
                return f"{self.base_url}{parsed.path}?{parsed.query}"
            return f"{self.base_url}{parsed.path}"
        return f"{self.base_url}{endpoint}"

    def extract_path(self, url: str) -> str:
        """Extract path from URL."""
        if url.startswith('http://') or url.startswith('https://'):
            parsed = urllib.parse.urlparse(url)
            path = parsed.path
            if parsed.query:
                path += f"?{parsed.query}"
            return path
        return url

    def request(self, url: str, method: str = "GET", headers: dict = None,
                data: bytes = None, follow_redirects: bool = True,
                retries: int = 2) -> dict:
        """Make HTTP request and return response details with retry logic."""
        last_error = None

        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, method=method, data=data)
                req.add_header('User-Agent', 'ZAP-Verification-Tool/1.0')

                if headers:
                    for key, value in headers.items():
                        req.add_header(key, value)

                if not follow_redirects:
                    class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                        def redirect_request(self, req, fp, code, msg, headers, newurl):
                            return None

                    opener = urllib.request.build_opener(
                        NoRedirectHandler(),
                        urllib.request.HTTPSHandler(context=self.ssl_context)
                    )
                else:
                    opener = urllib.request.build_opener(
                        urllib.request.HTTPSHandler(context=self.ssl_context)
                    )

                # Use longer timeout on retry attempts
                current_timeout = self.timeout if attempt == 0 else self.timeout * 2
                response = opener.open(req, timeout=current_timeout)

                return {
                    'status_code': response.status,
                    'headers': dict(response.headers),
                    'content': response.read().decode('utf-8', errors='ignore'),
                    'url': response.url
                }

            except urllib.error.HTTPError as e:
                return {
                    'status_code': e.code,
                    'headers': dict(e.headers) if e.headers else {},
                    'content': e.read().decode('utf-8', errors='ignore') if e.fp else '',
                    'url': url,
                    'error': str(e)
                }
            except (urllib.error.URLError, TimeoutError, socket.timeout) as e:
                last_error = str(e.reason) if hasattr(e, 'reason') else str(e)
                if attempt < retries:
                    continue
                return {
                    'status_code': 0,
                    'headers': {},
                    'content': '',
                    'url': url,
                    'error': last_error
                }
            except Exception as e:
                last_error = str(e)
                if attempt < retries and 'timed out' in str(e).lower():
                    continue
                return {
                    'status_code': 0,
                    'headers': {},
                    'content': '',
                    'url': url,
                    'error': last_error
                }

    def head(self, url: str) -> dict:
        """Make HEAD request."""
        result = self.request(url, method="HEAD")
        if result.get('error') or result['status_code'] == 0:
            return self.request(url, method="GET")
        return result

    def get(self, url: str) -> dict:
        """Make GET request."""
        return self.request(url, method="GET")
