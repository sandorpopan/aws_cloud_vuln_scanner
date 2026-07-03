"""
Builds boto3 clients for the scanner.

Centralized here so the engine/rules never touch boto3.Session directly,
which keeps rules testable with injected fake clients.
"""

from __future__ import annotations

import boto3
from botocore.config import Config

# Some checks (IAM, CloudTrail account-level state) are global/account-wide
# and only need to be evaluated once regardless of how many regions are scanned.
GLOBAL_SERVICES = {"iam"}

DEFAULT_CLIENT_CONFIG = Config(retries={"max_attempts": 5, "mode": "adaptive"})


class AWSClientFactory:
    def __init__(self, profile: str | None = None, region: str = "us-east-1"):
        session_kwargs = {}
        if profile:
            session_kwargs["profile_name"] = profile
        self.session = boto3.Session(**session_kwargs)
        self.default_region = region

    def get_clients(self, region: str, services: list[str]) -> dict[str, object]:
        clients = {}
        for service in services:
            svc_region = "us-east-1" if service in GLOBAL_SERVICES else region
            clients[service] = self.session.client(service, region_name=svc_region, config=DEFAULT_CLIENT_CONFIG)
        return clients

    def caller_identity(self) -> dict:
        sts = self.session.client("sts", config=DEFAULT_CLIENT_CONFIG)
        return sts.get_caller_identity()

    def enabled_regions(self) -> list[str]:
        ec2 = self.session.client("ec2", region_name=self.default_region, config=DEFAULT_CLIENT_CONFIG)
        resp = ec2.describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
