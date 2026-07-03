"""
Rule registry.

Adding a new check = adding a Rule subclass to the relevant module and
appending it to that module's ALL_RULES list. Nothing else needs to change;
the engine discovers rules from REGISTRY below.
"""

from . import cloudtrail_rules, ec2_rules, iam_rules, rds_rules, s3_rules
from .base import Finding, Rule, Severity  # noqa: F401  (re-exported)

# service_name -> list[Rule subclass]
REGISTRY: dict[str, list[type]] = {
    "iam": iam_rules.ALL_RULES,
    "s3": s3_rules.ALL_RULES,
    "ec2": ec2_rules.ALL_RULES,
    "rds": rds_rules.ALL_RULES,
    "cloudtrail": cloudtrail_rules.ALL_RULES,
}

ALL_SERVICES = list(REGISTRY.keys())


def rules_for_services(services: list[str]) -> list[type]:
    rules: list[type] = []
    for service in services:
        rules.extend(REGISTRY.get(service, []))
    return rules
