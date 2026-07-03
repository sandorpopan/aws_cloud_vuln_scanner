"""
Unit tests for individual rules using moto to mock AWS.

Run with:  pytest -v
"""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from scanner.rules.ec2_rules import OpenSecurityGroupRule, UnencryptedEBSVolumeRule
from scanner.rules.iam_rules import IAMWildcardPolicyRule, RootAccountMFARule
from scanner.rules.s3_rules import S3EncryptionRule, S3PublicAccessRule


REGION = "us-east-1"


@mock_aws
def test_root_mfa_rule_flags_missing_mfa():
    iam = boto3.client("iam", region_name=REGION)
    rule = RootAccountMFARule(clients={"iam": iam}, region=REGION)
    findings = list(rule.run())
    assert len(findings) == 1
    assert findings[0].rule_id == "IAM-001"


@mock_aws
def test_iam_wildcard_policy_rule_detects_star_star():
    iam = boto3.client("iam", region_name=REGION)
    iam.create_policy(
        PolicyName="TooPermissive",
        PolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }""",
    )
    rule = IAMWildcardPolicyRule(clients={"iam": iam}, region=REGION)
    findings = list(rule.run())
    assert len(findings) == 1
    assert findings[0].resource_id == "TooPermissive"


@mock_aws
def test_iam_wildcard_policy_rule_ignores_scoped_policy():
    iam = boto3.client("iam", region_name=REGION)
    iam.create_policy(
        PolicyName="ScopedPolicy",
        PolicyDocument="""{
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]
        }""",
    )
    rule = IAMWildcardPolicyRule(clients={"iam": iam}, region=REGION)
    findings = list(rule.run())
    assert findings == []


@mock_aws
def test_s3_public_access_rule_flags_public_acl():
    s3 = boto3.client("s3", region_name=REGION)
    bucket = "test-public-bucket"
    s3.create_bucket(Bucket=bucket)
    s3.put_bucket_acl(
        Bucket=bucket,
        AccessControlPolicy={
            "Grants": [
                {
                    "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
                    "Permission": "READ",
                }
            ],
            "Owner": s3.get_bucket_acl(Bucket=bucket)["Owner"],
        },
    )
    rule = S3PublicAccessRule(clients={"s3": s3}, region=REGION)
    findings = list(rule.run())
    assert len(findings) == 1
    assert findings[0].resource_id == bucket


@mock_aws
def test_s3_public_access_rule_ignores_private_bucket():
    s3 = boto3.client("s3", region_name=REGION)
    bucket = "test-private-bucket"
    s3.create_bucket(Bucket=bucket)
    rule = S3PublicAccessRule(clients={"s3": s3}, region=REGION)
    findings = list(rule.run())
    assert findings == []


@mock_aws
def test_s3_encryption_rule_flags_missing_encryption():
    s3 = boto3.client("s3", region_name=REGION)
    bucket = "unencrypted-bucket"
    s3.create_bucket(Bucket=bucket)
    rule = S3EncryptionRule(clients={"s3": s3}, region=REGION)
    findings = list(rule.run())
    assert len(findings) == 1


@mock_aws
def test_open_security_group_rule_flags_ssh_open_to_world():
    ec2 = boto3.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="open-ssh", Description="test", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    rule = OpenSecurityGroupRule(clients={"ec2": ec2}, region=REGION)
    findings = list(rule.run())
    assert any(f.resource_id == sg for f in findings)


@mock_aws
def test_unencrypted_ebs_volume_rule():
    ec2 = boto3.client("ec2", region_name=REGION)
    vol = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, Encrypted=False)
    rule = UnencryptedEBSVolumeRule(clients={"ec2": ec2}, region=REGION)
    findings = list(rule.run())
    assert any(f.resource_id == vol["VolumeId"] for f in findings)


def test_safe_run_catches_exceptions():
    class ExplodingRule(RootAccountMFARule):
        def run(self):
            raise RuntimeError("boom")

    rule = ExplodingRule(clients={"iam": None}, region=REGION)
    findings = rule.safe_run()
    assert len(findings) == 1
    assert "boom" in findings[0].evidence["exception"]
