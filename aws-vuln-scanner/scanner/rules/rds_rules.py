"""RDS checks: public accessibility, encryption, backups, multi-AZ."""

from __future__ import annotations

from typing import Iterable

from .base import Finding, Rule, Severity


class RDSPubliclyAccessibleRule(Rule):
    rule_id = "RDS-001"
    title = "RDS instance is publicly accessible"
    severity = Severity.CRITICAL
    service = "rds"
    description = "This database instance has a publicly resolvable endpoint reachable from the internet."
    remediation = "Set PubliclyAccessible to false and access the database through a VPN/bastion/private subnet."
    references = ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"]

    def run(self) -> Iterable[Finding]:
        rds = self.clients["rds"]
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                if db.get("PubliclyAccessible"):
                    yield self.make_finding(db["DBInstanceIdentifier"], evidence={"engine": db.get("Engine")})


class RDSEncryptionRule(Rule):
    rule_id = "RDS-002"
    title = "RDS instance storage is not encrypted"
    severity = Severity.MEDIUM
    service = "rds"
    description = "Data at rest on this RDS instance is not encrypted."
    remediation = "Enable storage encryption. Note: existing unencrypted instances must be recreated via snapshot copy."
    references = ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"]

    def run(self) -> Iterable[Finding]:
        rds = self.clients["rds"]
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                if not db.get("StorageEncrypted", False):
                    yield self.make_finding(db["DBInstanceIdentifier"])


class RDSBackupRetentionRule(Rule):
    rule_id = "RDS-003"
    title = "RDS instance has automated backups disabled or a short retention window"
    severity = Severity.LOW
    service = "rds"
    description = "Automated backups are disabled or retained for fewer than 7 days, limiting recovery options."
    remediation = "Set BackupRetentionPeriod to 7 days or more."
    references = ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"]

    MIN_RETENTION_DAYS = 7

    def run(self) -> Iterable[Finding]:
        rds = self.clients["rds"]
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                retention = db.get("BackupRetentionPeriod", 0)
                if retention < self.MIN_RETENTION_DAYS:
                    yield self.make_finding(
                        db["DBInstanceIdentifier"], evidence={"backup_retention_days": retention}
                    )


class RDSMultiAZRule(Rule):
    rule_id = "RDS-004"
    title = "RDS instance does not have Multi-AZ enabled"
    severity = Severity.INFO
    service = "rds"
    description = "This instance has no standby replica, so an AZ outage causes downtime."
    remediation = "Enable Multi-AZ deployment for production databases."
    references = ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"]

    def run(self) -> Iterable[Finding]:
        rds = self.clients["rds"]
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                if not db.get("MultiAZ", False):
                    yield self.make_finding(db["DBInstanceIdentifier"])


ALL_RULES = [
    RDSPubliclyAccessibleRule,
    RDSEncryptionRule,
    RDSBackupRetentionRule,
    RDSMultiAZRule,
]
