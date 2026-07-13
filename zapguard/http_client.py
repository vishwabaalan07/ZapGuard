"""
HTTP client with SSL bypass and retry logic for vulnerability testing.
Uses the requests library for better performance and reliability.
"""

import urllib.parse
import urllib3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress SSL warnings since we intentionally bypass certificate verification for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class HTTPClient:
    """HTTP client with SSL certificate bypass for testing."""

    def __init__(self, base_url: str, timeout: int = 20, stop_event=None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.stop_event = stop_event

        # Create session with connection pooling
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZAP-Verification-Tool/1.0'
        })

        # Configure retry strategy
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=20
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

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

    def is_stopped(self) -> bool:
        """Check if stop was requested."""
        return self.stop_event is not None and self.stop_event.is_set()

    def request(self, url: str, method: str = "GET", headers: dict = None,
                data: bytes = None, follow_redirects: bool = True) -> dict:
        """Make HTTP request and return response details."""
        if self.is_stopped():
            return {'status_code': 0, 'headers': {}, 'content': '', 'url': url, 'error': 'Cancelled'}

        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=self.timeout,
                allow_redirects=follow_redirects,
                verify=False  # Skip SSL verification for testing
            )

            if self.is_stopped():
                return {'status_code': 0, 'headers': {}, 'content': '', 'url': url, 'error': 'Cancelled'}

            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content': response.text,
                'url': response.url
            }

        except requests.exceptions.Timeout as e:
            return {
                'status_code': 0,
                'headers': {},
                'content': '',
                'url': url,
                'error': 'Cancelled' if self.is_stopped() else f'Timeout: {str(e)}'
            }
        except requests.exceptions.ConnectionError as e:
            return {
                'status_code': 0,
                'headers': {},
                'content': '',
                'url': url,
                'error': 'Cancelled' if self.is_stopped() else f'Connection error: {str(e)}'
            }
        except requests.exceptions.RequestException as e:
            return {
                'status_code': 0,
                'headers': {},
                'content': '',
                'url': url,
                'error': 'Cancelled' if self.is_stopped() else str(e)
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

    def post(self, url: str, data: bytes = None, headers: dict = None) -> dict:
        """Make POST request."""
        return self.request(url, method="POST", data=data, headers=headers)

    def close(self):
        """Close the session and release connections."""
        self.session.close()
