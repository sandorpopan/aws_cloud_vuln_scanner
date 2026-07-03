"""S3 bucket checks: public access, encryption, logging, versioning."""

from __future__ import annotations

from typing import Iterable

from .base import Finding, Rule, Severity


class S3PublicAccessRule(Rule):
    rule_id = "S3-001"
    title = "S3 bucket is publicly accessible"
    severity = Severity.CRITICAL
    service = "s3"
    description = "This bucket's ACL or bucket policy allows access from anyone on the internet."
    remediation = ("Enable S3 Block Public Access at the bucket (and account) level, "
                    "and remove any public grants from the ACL/policy.")
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]

    PUBLIC_GRANTEES = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }

    def run(self) -> Iterable[Finding]:
        s3 = self.clients["s3"]
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]

            # 1) Block Public Access setting
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                fully_blocked = all(pab.values())
            except s3.exceptions.ClientError:
                fully_blocked = False

            if fully_blocked:
                continue  # can't be public regardless of ACL/policy

            # 2) ACL grants
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl.get("Grants", []):
                    grantee = grant.get("Grantee", {})
                    if grantee.get("URI") in self.PUBLIC_GRANTEES:
                        yield self.make_finding(
                            name, evidence={"via": "ACL", "permission": grant.get("Permission")}
                        )
                        break
            except s3.exceptions.ClientError:
                pass

            # 3) Bucket policy with Principal: "*"
            try:
                policy_status = s3.get_bucket_policy_status(Bucket=name)
                if policy_status["PolicyStatus"]["IsPublic"]:
                    yield self.make_finding(name, evidence={"via": "bucket_policy"})
            except s3.exceptions.ClientError:
                pass


class S3EncryptionRule(Rule):
    rule_id = "S3-002"
    title = "S3 bucket does not have default encryption enabled"
    severity = Severity.MEDIUM
    service = "s3"
    description = "Objects written to this bucket are not encrypted at rest by default."
    remediation = "Enable default server-side encryption (SSE-S3 or SSE-KMS) on the bucket."
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"]

    def run(self) -> Iterable[Finding]:
        s3 = self.clients["s3"]
        for bucket in s3.list_buckets()["Buckets"]:
            name = bucket["Name"]
            try:
                s3.get_bucket_encryption(Bucket=name)
            except s3.exceptions.ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    yield self.make_finding(name)


class S3VersioningRule(Rule):
    rule_id = "S3-003"
    title = "S3 bucket does not have versioning enabled"
    severity = Severity.LOW
    service = "s3"
    description = "Without versioning, accidental deletion or ransomware-style overwrite is unrecoverable."
    remediation = "Enable versioning on buckets holding important data."
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"]

    def run(self) -> Iterable[Finding]:
        s3 = self.clients["s3"]
        for bucket in s3.list_buckets()["Buckets"]:
            name = bucket["Name"]
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                yield self.make_finding(name, evidence={"status": versioning.get("Status", "Disabled")})


class S3LoggingRule(Rule):
    rule_id = "S3-004"
    title = "S3 bucket does not have access logging enabled"
    severity = Severity.LOW
    service = "s3"
    description = "Without access logging, requests to this bucket cannot be audited after an incident."
    remediation = "Enable server access logging or use CloudTrail S3 data events."
    references = ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"]

    def run(self) -> Iterable[Finding]:
        s3 = self.clients["s3"]
        for bucket in s3.list_buckets()["Buckets"]:
            name = bucket["Name"]
            logging_cfg = s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in logging_cfg:
                yield self.make_finding(name)


ALL_RULES = [
    S3PublicAccessRule,
    S3EncryptionRule,
    S3VersioningRule,
    S3LoggingRule,
]
