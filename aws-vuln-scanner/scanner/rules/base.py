"""
Base classes for the rule engine.

Every check in the scanner is implemented as a subclass of `Rule`.
A rule inspects one AWS service/resource type and yields zero or more
`Finding` objects describing vulnerabilities or misconfigurations.

This mirrors the pattern used by tools like Prowler / ScoutSuite:
a flat, pluggable list of independent checks that are auto-discovered
and run against a live AWS account (or against injected boto3 clients
in unit tests).
"""

from __future__ import annotations

import abc
import enum
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional


class Severity(enum.IntEnum):
    """Ordered so findings can be sorted worst-first."""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:
        return self.name


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    service: str
    resource_id: str
    region: str
    description: str
    remediation: str
    evidence: dict = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": str(self.severity),
            "severity_score": int(self.severity),
            "service": self.service,
            "resource_id": self.resource_id,
            "region": self.region,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "references": self.references,
            "timestamp": self.timestamp,
        }
        return d


class Rule(abc.ABC):
    """
    Subclass this for every check. Keep each rule focused on a single
    control so results map cleanly onto a CIS-style checklist.
    """

    #: unique, stable identifier, e.g. "S3-001"
    rule_id: str = "UNSET-000"
    title: str = "Unset rule"
    severity: Severity = Severity.MEDIUM
    service: str = "generic"
    description: str = ""
    remediation: str = ""
    references: list[str] = []

    def __init__(self, clients: dict[str, Any], region: str):
        """
        clients: dict of service_name -> boto3 client, pre-built by the
                 engine so rules never construct their own sessions
                 (makes rules trivially unit-testable with fakes/mocks).
        region:  the AWS region this rule instance is scanning.
        """
        self.clients = clients
        self.region = region

    def make_finding(self, resource_id: str, evidence: Optional[dict] = None, **overrides) -> Finding:
        return Finding(
            rule_id=overrides.get("rule_id", self.rule_id),
            title=overrides.get("title", self.title),
            severity=overrides.get("severity", self.severity),
            service=overrides.get("service", self.service),
            resource_id=resource_id,
            region=self.region,
            description=overrides.get("description", self.description),
            remediation=overrides.get("remediation", self.remediation),
            evidence=evidence or {},
            references=overrides.get("references", self.references),
        )

    @abc.abstractmethod
    def run(self) -> Iterable[Finding]:
        """Execute the check. Must return an iterable (possibly empty) of Finding."""
        raise NotImplementedError

    def safe_run(self) -> list[Finding]:
        """
        Wraps run() so that one failing check (e.g. missing permission,
        region not supporting a service) never crashes the whole scan.
        """
        try:
            return list(self.run())
        except Exception as exc:  # noqa: BLE001 - deliberately broad, this is a scan-safety boundary
            return [
                Finding(
                    rule_id=self.rule_id,
                    title=f"{self.title} (check failed to run)",
                    severity=Severity.INFO,
                    service=self.service,
                    resource_id="N/A",
                    region=self.region,
                    description=f"This check could not complete: {exc}",
                    remediation="Verify the scanning role has the required read-only "
                                "permissions (see README: IAM policy).",
                    evidence={"exception": str(exc)},
                )
            ]
