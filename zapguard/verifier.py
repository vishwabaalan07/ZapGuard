"""
Vulnerability verification orchestrator with parallel processing.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

from .models import Alert, Instance, TestResult, TestStatus
from .http_client import HTTPClient
from .vulnerability_tests import get_test_class

logger = logging.getLogger(__name__)

DEFAULT_MAX_WORKERS = 10


class VulnerabilityVerifier:
    """Main class for verifying ZAP vulnerabilities."""

    def __init__(self, base_url: str, timeout: int = 20):
        self.client = HTTPClient(base_url, timeout)
        self.results: List[TestResult] = []

    def _test_instance(self, alert: Alert, instance: Instance) -> TestResult:
        """Test a single instance (for parallel execution)."""
        test_class = get_test_class(alert.plugin_id)
        test = test_class(self.client)
        try:
            return test.test(alert, instance)
        except Exception as e:
            return TestResult(
                alert_name=alert.name,
                plugin_id=alert.plugin_id,
                risk_level=alert.risk_level,
                status=TestStatus.ERROR,
                endpoint=instance.url,
                method=instance.method,
                details=f"Test error: {str(e)}"
            )

    def verify_all(self, alerts: List[Alert], max_workers: int = DEFAULT_MAX_WORKERS) -> List[TestResult]:
        """Verify all alerts using parallel processing."""
        self.results = []

        # Sort by risk level (high first)
        sorted_alerts = sorted(alerts, key=lambda a: a.risk_level.value, reverse=True)

        # Build list of all (alert, instance) pairs for parallel processing
        test_tasks: List[Tuple[Alert, Instance]] = []
        for alert in sorted_alerts:
            for instance in alert.instances:
                test_tasks.append((alert, instance))

        logger.info(f"\nRunning {len(test_tasks)} tests with {max_workers} parallel workers...")

        # Execute tests in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {
                executor.submit(self._test_instance, alert, instance): (alert, instance)
                for alert, instance in test_tasks
            }

            for future in as_completed(future_to_task):
                result = future.result()
                self.results.append(result)
                self._log_result(result)

        # Sort results by risk level for consistent output
        self.results.sort(key=lambda r: r.risk_level.value, reverse=True)

        return self.results

    def _log_result(self, result: TestResult):
        """Log a test result."""
        status_colors = {
            TestStatus.PASS: '\033[92m',
            TestStatus.FAIL: '\033[91m',
            TestStatus.NOT_TESTABLE: '\033[93m',
            TestStatus.ERROR: '\033[95m'
        }
        reset = '\033[0m'
        color = status_colors.get(result.status, reset)

        logger.info(f"[{color}{result.status.value}{reset}] {result.endpoint}")
        if result.details:
            logger.info(f"        Details: {result.details[:100]}")
