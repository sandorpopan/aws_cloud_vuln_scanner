"""
Scan engine: given a list of services/regions, instantiate every applicable
Rule and run it, collecting Finding objects into a single ScanResult.
"""

from __future__ import annotations

import concurrent.futures
import time
from dataclasses import dataclass, field

from .aws_client import GLOBAL_SERVICES, AWSClientFactory
from .rules import Rule, rules_for_services
from .rules.base import Finding


@dataclass
class ScanResult:
    account_id: str
    regions_scanned: list[str]
    services_scanned: list[str]
    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at or time.time()) - self.started_at

    def summary_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
        return counts

    def summary_by_service(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.service] = counts.get(f.service, 0) + 1
        return counts


class ScanEngine:
    def __init__(self, factory: AWSClientFactory, max_workers: int = 8):
        self.factory = factory
        self.max_workers = max_workers

    def run(self, services: list[str], regions: list[str]) -> ScanResult:
        identity = self.factory.caller_identity()
        result = ScanResult(
            account_id=identity.get("Account", "unknown"),
            regions_scanned=list(regions),
            services_scanned=list(services),
        )

        # Global services (IAM, account-wide CloudTrail state) only need one pass.
        global_services = [s for s in services if s in GLOBAL_SERVICES or s == "cloudtrail"]
        regional_services = [s for s in services if s not in global_services]

        jobs: list[tuple[type[Rule], dict, str]] = []

        if global_services:
            clients = self.factory.get_clients(self.factory.default_region, global_services)
            for rule_cls in rules_for_services(global_services):
                jobs.append((rule_cls, clients, self.factory.default_region))

        region_client_cache: dict[str, dict] = {}
        for region in regions:
            if not regional_services:
                continue
            region_client_cache[region] = self.factory.get_clients(region, regional_services)
            for rule_cls in rules_for_services(regional_services):
                jobs.append((rule_cls, region_client_cache[region], region))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(self._run_rule, rule_cls, clients, region) for rule_cls, clients, region in jobs]
            for future in concurrent.futures.as_completed(futures):
                result.findings.extend(future.result())

        result.findings.sort(key=lambda f: (-int(f.severity), f.service, f.resource_id))
        result.finished_at = time.time()
        return result

    @staticmethod
    def _run_rule(rule_cls: type[Rule], clients: dict, region: str) -> list[Finding]:
        rule = rule_cls(clients=clients, region=region)
        return rule.safe_run()
