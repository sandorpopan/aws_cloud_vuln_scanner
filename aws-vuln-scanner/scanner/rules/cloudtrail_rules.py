"""CloudTrail / account-level logging and password-policy checks."""

from __future__ import annotations

from typing import Iterable

from .base import Finding, Rule, Severity


class CloudTrailEnabledRule(Rule):
    rule_id = "CT-001"
    title = "No multi-region CloudTrail trail is enabled and logging"
    severity = Severity.HIGH
    service = "cloudtrail"
    description = "Without an active multi-region trail, API activity in some or all regions goes unlogged."
    remediation = "Create a trail with IsMultiRegionTrail=true and confirm logging is turned on."
    references = ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-a-trail-using-the-console-first-time.html"]

    def run(self) -> Iterable[Finding]:
        ct = self.clients["cloudtrail"]
        trails = ct.describe_trails(includeShadowTrails=True)["trailList"]
        multi_region_active = False
        for trail in trails:
            if not trail.get("IsMultiRegionTrail"):
                continue
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging"):
                multi_region_active = True
                break

        if not multi_region_active:
            yield self.make_finding("account", evidence={"trail_count": len(trails)})


class CloudTrailLogFileValidationRule(Rule):
    rule_id = "CT-002"
    title = "CloudTrail log file validation is disabled"
    severity = Severity.LOW
    service = "cloudtrail"
    description = "Without log file validation, tampering with delivered log files cannot be detected."
    remediation = "Enable log file validation on the trail (EnableLogFileValidation=true)."
    references = ["https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html"]

    def run(self) -> Iterable[Finding]:
        ct = self.clients["cloudtrail"]
        trails = ct.describe_trails()["trailList"]
        for trail in trails:
            if not trail.get("LogFileValidationEnabled", False):
                yield self.make_finding(trail["Name"])


class IAMPasswordPolicyRule(Rule):
    rule_id = "CT-003"
    title = "Account password policy does not meet minimum strength requirements"
    severity = Severity.MEDIUM
    service = "iam"
    description = "The account-wide password policy is missing or too weak (length, complexity, or reuse rules)."
    remediation = "Set a password policy requiring >=14 chars, upper/lower/number/symbol, and reuse prevention."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"]

    MIN_LENGTH = 14

    def run(self) -> Iterable[Finding]:
        iam = self.clients["iam"]
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except iam.exceptions.NoSuchEntityException:
            yield self.make_finding("account", evidence={"reason": "no password policy configured"})
            return

        problems = []
        if policy.get("MinimumPasswordLength", 0) < self.MIN_LENGTH:
            problems.append("min_length")
        if not policy.get("RequireSymbols"):
            problems.append("require_symbols")
        if not policy.get("RequireNumbers"):
            problems.append("require_numbers")
        if not policy.get("RequireUppercaseCharacters"):
            problems.append("require_uppercase")
        if not policy.get("RequireLowercaseCharacters"):
            problems.append("require_lowercase")
        if not policy.get("PasswordReusePrevention"):
            problems.append("reuse_prevention")

        if problems:
            yield self.make_finding("account", evidence={"weak_settings": problems, "policy": policy})


ALL_RULES = [
    CloudTrailEnabledRule,
    CloudTrailLogFileValidationRule,
    IAMPasswordPolicyRule,
]
