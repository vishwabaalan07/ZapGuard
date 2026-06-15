#!/usr/bin/env python3
"""
ZAP Vulnerability Fix Verification Tool - CLI Entry Point
Parses ZAP reports and verifies if vulnerabilities have been fixed.
"""

import argparse
import logging
import sys
from pathlib import Path

from .models import TestStatus
from .parsers import parse_zap_report
from .verifier import VulnerabilityVerifier
from .reports import generate_html_report, generate_csv_report
from .config import REQUEST_TIMEOUT, MAX_WORKERS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def cleanup_old_reports(output_dir: Path):
    """Remove old verification report files from output directory."""
    patterns = ['*_verification_report.html', '*_verification_results.csv']
    for pattern in patterns:
        for old_file in output_dir.glob(pattern):
            try:
                old_file.unlink()
                logger.info(f"Removed old report: {old_file.name}")
            except Exception as e:
                logger.warning(f"Could not remove {old_file}: {e}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='ZAP Vulnerability Fix Verification Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  zapguard-cli -u http://example.com -r zap_report.html
  zapguard-cli -u http://10.0.0.1 -r scan.xml -o ./reports -w 20
        '''
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL to verify against')
    parser.add_argument('-r', '--report', required=True, help='Path to ZAP report file (HTML, XML, or JSON)')
    parser.add_argument('-o', '--output', default='.', help='Output directory for reports (default: current directory)')
    parser.add_argument('-t', '--timeout', type=int, default=REQUEST_TIMEOUT, help=f'Request timeout in seconds (default: {REQUEST_TIMEOUT})')
    parser.add_argument('-w', '--workers', type=int, default=MAX_WORKERS, help=f'Number of parallel workers (default: {MAX_WORKERS})')
    parser.add_argument('--no-cleanup', action='store_true', help='Do not remove old report files')

    args = parser.parse_args()

    base_url = args.url
    report_path = Path(args.report)
    output_dir = Path(args.output)
    timeout = args.timeout
    max_workers = args.workers

    print("=" * 60)
    print("  ZAP Vulnerability Fix Verification Tool")
    print("=" * 60)
    print(f"  Target URL:   {base_url}")
    print(f"  ZAP Report:   {report_path}")
    print(f"  Timeout:      {timeout}s")
    print(f"  Workers:      {max_workers}")
    print(f"  Output Dir:   {output_dir}")
    print("=" * 60)
    print()

    # Validate inputs
    if not report_path.exists():
        logger.error(f"Report file not found: {report_path}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Clean up old reports
    if not args.no_cleanup:
        cleanup_old_reports(output_dir)

    # Parse report
    logger.info(f"Parsing ZAP report: {report_path}")
    try:
        alerts = parse_zap_report(str(report_path))
    except FileNotFoundError:
        logger.error(f"Report file not found: {report_path}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to parse report: {e}")
        sys.exit(1)

    if not alerts:
        logger.warning("No alerts found in the report")
        sys.exit(0)

    # Summary of parsed alerts
    total_instances = sum(len(a.instances) for a in alerts)
    logger.info(f"\nParsed {len(alerts)} alert types with {total_instances} total instances:")

    for alert in sorted(alerts, key=lambda a: a.risk_level.value, reverse=True):
        logger.info(f"  [{alert.risk_level.name:12}] {alert.name} "
                   f"(Plugin: {alert.plugin_id}) - {len(alert.instances)} instances")

    # Verify vulnerabilities
    logger.info(f"\nStarting verification against: {base_url}")
    verifier = VulnerabilityVerifier(base_url, timeout)
    results = verifier.verify_all(alerts, max_workers)

    # Generate reports
    base_name = report_path.stem + "_verification"

    html_path = output_dir / f"{base_name}_report.html"
    csv_path = output_dir / f"{base_name}_results.csv"

    generate_html_report(results, alerts, base_url, str(report_path), str(html_path))
    generate_csv_report(results, str(csv_path))

    # Print summary
    total = len(results)
    passed = sum(1 for r in results if r.status == TestStatus.PASS)
    failed = sum(1 for r in results if r.status == TestStatus.FAIL)
    not_testable = sum(1 for r in results if r.status == TestStatus.NOT_TESTABLE)
    errors = sum(1 for r in results if r.status == TestStatus.ERROR)

    testable = total - not_testable
    pass_rate = (passed / testable * 100) if testable > 0 else 0

    print("\n" + "="*60)
    print("                    VERIFICATION SUMMARY")
    print("="*60)
    print(f"  PASSED:       {passed:4d}  {'✓' if passed == testable else ''}")
    print(f"  FAILED:       {failed:4d}  {'!' if failed > 0 else ''}")
    print(f"  NOT TESTABLE: {not_testable:4d}")
    print(f"  ERRORS:       {errors:4d}")
    print("-"*60)
    print(f"  TOTAL:        {total:4d}")
    print(f"  PASS RATE:    {pass_rate:.1f}% (of testable)")
    print("="*60)

    if failed == 0 and errors == 0:
        print("\n✅ All testable checks passed!")
    elif failed > 0:
        print(f"\n⚠️  {failed} checks failed - review required")

    print(f"\nReports generated:")
    print(f"  HTML: {html_path}")
    print(f"  CSV:  {csv_path}")

    # Return non-zero exit code if there are failures
    sys.exit(1 if failed > 0 else 0)


if __name__ == '__main__':
    main()
