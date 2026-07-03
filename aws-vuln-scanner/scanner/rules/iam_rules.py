"""
IAM checks.

These map closely to the CIS AWS Foundations Benchmark section 1
(Identity and Access Management).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Iterable

from .base import Finding, Rule, Severity

ADMIN_ACTIONS = {"*"}


class RootAccountMFARule(Rule):
    rule_id = "IAM-001"
    title = "Root account does not have MFA enabled"
    severity = Severity.CRITICAL
    service = "iam"
    description = ("The AWS root account has full, unrestricted access to the account. "
                    "Without MFA, a leaked root password is a total account compromise.")
    remediation = "Enable a hardware or virtual MFA device on the root account immediately."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"]

    def run(self) -> Iterable[Finding]:
        iam = self.clients["iam"]
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 0:
            yield self.make_finding("root-account", evidence={"AccountMFAEnabled": 0})


class IAMUserMFARule(Rule):
    rule_id = "IAM-002"
    title = "IAM user with console access does not have MFA enabled"
    severity = Severity.HIGH
    service = "iam"
    description = "Console-enabled IAM users without MFA are vulnerable to password-only compromise."
    remediation = "Require MFA for all IAM users, ideally enforced via an IAM policy condition."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html"]

    def run(self) -> Iterable[Finding]:
        iam = self.clients["iam"]
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                try:
                    iam.get_login_profile(UserName=username)
                    has_console_access = True
                except iam.exceptions.NoSuchEntityException:
                    has_console_access = False

                if not has_console_access:
                    continue

                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
                if not mfa_devices:
                    yield self.make_finding(username, evidence={"console_access": True, "mfa_devices": 0})


class IAMUnusedCredentialsRule(Rule):
    rule_id = "IAM-003"
    title = "IAM user has unused credentials (>90 days)"
    severity = Severity.MEDIUM
    service = "iam"
    description = "Stale access keys or passwords increase the attack surface with no operational benefit."
    remediation = "Deactivate or remove access keys and console passwords unused for more than 90 days."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html"]

    STALE_DAYS = 90

    def run(self) -> Iterable[Finding]:
        iam = self.clients["iam"]
        now = datetime.now(timezone.utc)
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] != "Active":
                        continue
                    last_used = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])
                    last_used_date = last_used.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    reference_date = last_used_date or key["CreateDate"]
                    age_days = (now - reference_date).days
                    if age_days > self.STALE_DAYS:
                        yield self.make_finding(
                            f"{username}:{key['AccessKeyId']}",
                            evidence={"age_days": age_days, "last_used": str(last_used_date)},
                        )


class IAMWildcardPolicyRule(Rule):
    rule_id = "IAM-004"
    title = "IAM policy grants wildcard (Action:* / Resource:*) permissions"
    severity = Severity.HIGH
    service = "iam"
    description = ("A customer-managed policy allows all actions on all resources. "
                    "This violates least-privilege and is a common privilege-escalation vector.")
    remediation = "Scope the policy down to the specific actions and resource ARNs actually required."
    references = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"]

    def run(self) -> Iterable[Finding]:
        iam = self.clients["iam"]
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local"):  # customer-managed only
            for policy in page["Policies"]:
                version = iam.get_policy_version(
                    PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"]
                )
                doc = version["PolicyVersion"]["Document"]
                statements = doc["Statement"]
                if isinstance(statements, dict):
                    statements = [statements]

                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]

                    if "*" in actions and "*" in resources:
                        yield self.make_finding(
                            policy["PolicyName"],
                            evidence={"policy_arn": policy["Arn"], "statement": stmt},
                        )
                        break


class IAMPrivilegeEscalationRule(Rule):
    """
    Simplified privilege-escalation detector.

    Flags principals whose *effective inline+attached* permissions include
    combinations known to allow escalation to full admin, e.g.:
      - iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion (rewrite own policy)
      - iam:AttachUserPolicy / iam:AttachRolePolicy (attach AdministratorAccess)
      - iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction
      - iam:PassRole + ec2:RunInstances

    This is intentionally a heuristic, not an exhaustive graph analysis like
    PMapper — it is meant to catch the most common escalation primitives.
    """

    rule_id = "IAM-005"
    title = "IAM identity has a known privilege-escalation permission combination"
    severity = Severity.CRITICAL
    service = "iam"
    description = ("This principal holds a combination of permissions that is a well-documented "
                    "path to privilege escalation to full account admin.")
    remediation = "Remove the escalation-enabling permissions or scope them to specific resources/roles."
    references = ["https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"]

    ESCALATION_COMBOS = [
        {"iam:CreatePolicyVersion"},
        {"iam:SetDefaultPolicyVersion"},
        {"iam:AttachUserPolicy"},
        {"iam:AttachRolePolicy"},
        {"iam:PutUserPolicy"},
        {"iam:PutRolePolicy"},
        {"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
        {"iam:PassRole", "ec2:RunInstances"},
        {"iam:CreateAccessKey"},
        {"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"},
    ]

    def _collect_actions_for_user(self, iam, username: str) -> set[str]:
        actions: set[str] = set()

        for policy_name in iam.list_user_policies(UserName=username)["PolicyNames"]:
            doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)["PolicyDocument"]
            actions |= self._extract_actions(doc)

        for attached in iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]:
            version = iam.get_policy(PolicyArn=attached["PolicyArn"])["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(
                PolicyArn=attached["PolicyArn"], VersionId=version
            )["PolicyVersion"]["Document"]
            actions |= self._extract_actions(doc)

        return actions

    @staticmethod
    def _extract_actions(doc: dict) -> set[str]:
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        actions: set[str] = set()
        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            actions.update(stmt_actions)
        return actions

    def run(self) -> Iterable[Finding]:
        iam = self.clients["iam"]
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                actions = self._collect_actions_for_user(iam, username)
                if "*" in actions:
                    continue  # already caught by wildcard rule

                for combo in self.ESCALATION_COMBOS:
                    if combo.issubset(actions):
                        yield self.make_finding(
                            username,
                            evidence={"matched_permissions": sorted(combo)},
                        )
                        break


ALL_RULES = [
    RootAccountMFARule,
    IAMUserMFARule,
    IAMUnusedCredentialsRule,
    IAMWildcardPolicyRule,
    IAMPrivilegeEscalationRule,
]
