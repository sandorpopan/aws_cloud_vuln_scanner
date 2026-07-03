#!/usr/bin/env python3
"""
AWS Vulnerability Scanner — CLI entrypoint.

Examples:
  python -m scanner.main --profile default --region us-east-1
  python -m scanner.main --services iam,s3,ec2 --all-regions --format html
  python -m scanner.main --services iam --format json --output findings.json
"""

from __future__ import annotations

import argparse
import sys
import time

from .aws_client import AWSClientFactory
from .engine import ScanEngine
from .report import write_html_report, write_json_report
from .rules import ALL_SERVICES

SEVERITY_COLORS = {
    "CRITICAL": "\033[41m\033[97m",  # white on red
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "INFO": "\033[90m",
}
RESET = "\033[0m"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan an AWS account for common security vulnerabilities.")
    parser.add_argument("--profile", default=None, help="AWS CLI profile to use (default: default credential chain).")
    parser.add_argument("--region", default="us-east-1", help="Primary region for global/API calls (default: us-east-1).")
    parser.add_argument(
        "--regions",
        default=None,
        help="Comma-separated list of regions to scan for regional services. Default: --region only.",
    )
    parser.add_argument("--all-regions", action="store_true", help="Scan all enabled regions (slower).")
    parser.add_argument(
        "--services",
        default=",".join(ALL_SERVICES),
        help=f"Comma-separated services to scan. Available: {', '.join(ALL_SERVICES)}",
    )
    parser.add_argument("--format", choices=["json", "html", "both"], default="both", help="Report format(s) to write.")
    parser.add_argument("--output", default="scan_report", help="Output file base name (without extension).")
    parser.add_argument("--min-severity", default="INFO", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                         help="Only print findings at or above this severity to the console.")
    parser.add_argument("--max-workers", type=int, default=8, help="Thread pool size for concurrent checks.")
    return parser.parse_args(argv)


def print_console_summary(result, min_severity: str) -> None:
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    threshold = severity_order.index(min_severity)

    print(f"\nAccount: {result.account_id}")
    print(f"Regions: {', '.join(result.regions_scanned)}")
    print(f"Services: {', '.join(result.services_scanned)}")
    print(f"Duration: {result.duration_seconds:.1f}s")
    print(f"Total findings: {len(result.findings)}\n")

    by_sev = result.summary_by_severity()
    for sev in severity_order:
        count = by_sev.get(sev, 0)
        if count:
            color = SEVERITY_COLORS.get(sev, "")
            print(f"  {color}{sev:<10}{RESET} {count}")
    print()

    for finding in result.findings:
        if severity_order.index(str(finding.severity)) > threshold:
            continue
        color = SEVERITY_COLORS.get(str(finding.severity), "")
        print(f"{color}[{finding.severity}]{RESET} {finding.rule_id} — {finding.title}")
        print(f"    resource: {finding.resource_id}  region: {finding.region}")
        print(f"    fix: {finding.remediation}\n")


def main(argv=None) -> int:
    args = parse_args(argv)
    services = [s.strip() for s in args.services.split(",") if s.strip()]

    unknown = set(services) - set(ALL_SERVICES)
    if unknown:
        print(f"Unknown service(s): {', '.join(unknown)}. Available: {', '.join(ALL_SERVICES)}", file=sys.stderr)
        return 1

    factory = AWSClientFactory(profile=args.profile, region=args.region)

    try:
        factory.caller_identity()
    except Exception as exc:  # noqa: BLE001
        print(f"Could not authenticate to AWS: {exc}", file=sys.stderr)
        print("Check your --profile / credentials / region.", file=sys.stderr)
        return 1

    if args.all_regions:
        regions = factory.enabled_regions()
    elif args.regions:
        regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    else:
        regions = [args.region]

    print(f"Starting scan of services=[{', '.join(services)}] across regions={regions} ...")
    start = time.time()

    engine = ScanEngine(factory, max_workers=args.max_workers)
    result = engine.run(services=services, regions=regions)

    print_console_summary(result, args.min_severity)

    if args.format in ("json", "both"):
        json_path = f"{args.output}.json"
        write_json_report(result, json_path)
        print(f"JSON report written to {json_path}")

    if args.format in ("html", "both"):
        html_path = f"{args.output}.html"
        write_html_report(result, html_path)
        print(f"HTML report written to {html_path}")

    print(f"\nDone in {time.time() - start:.1f}s.")

    # Non-zero exit if CRITICAL findings exist — useful for CI pipelines.
    if any(str(f.severity) == "CRITICAL" for f in result.findings):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
