"""EC2 / networking checks: security groups, EBS encryption, public IPs, default VPC."""

from __future__ import annotations

from typing import Iterable

from .base import Finding, Rule, Severity

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


class OpenSecurityGroupRule(Rule):
    rule_id = "EC2-001"
    title = "Security group allows unrestricted inbound access on a sensitive port"
    severity = Severity.CRITICAL
    service = "ec2"
    description = "A security group permits inbound traffic from 0.0.0.0/0 (or ::/0) on a sensitive port."
    remediation = "Restrict the source CIDR to known IP ranges (office/VPN) or remove the rule entirely."
    references = ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"]

    def run(self) -> Iterable[Finding]:
        ec2 = self.clients["ec2"]
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page["SecurityGroups"]:
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    open_ranges = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") in ("0.0.0.0/0",)]
                    open_ranges += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in ("::/0",)]
                    if not open_ranges:
                        continue

                    if from_port is None and to_port is None:
                        # all ports / all protocols
                        yield self.make_finding(
                            sg["GroupId"],
                            evidence={"port_range": "ALL", "cidrs": open_ranges, "group_name": sg.get("GroupName")},
                        )
                        continue

                    for port, name in SENSITIVE_PORTS.items():
                        if from_port <= port <= to_port:
                            yield self.make_finding(
                                sg["GroupId"],
                                evidence={
                                    "port": port,
                                    "service": name,
                                    "cidrs": open_ranges,
                                    "group_name": sg.get("GroupName"),
                                },
                            )


class UnencryptedEBSVolumeRule(Rule):
    rule_id = "EC2-002"
    title = "EBS volume is not encrypted"
    severity = Severity.MEDIUM
    service = "ec2"
    description = "Data on this EBS volume is stored unencrypted at rest."
    remediation = "Enable EBS encryption by default at the account/region level, and re-create existing volumes encrypted."
    references = ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"]

    def run(self) -> Iterable[Finding]:
        ec2 = self.clients["ec2"]
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page["Volumes"]:
                if not vol.get("Encrypted", False):
                    yield self.make_finding(vol["VolumeId"], evidence={"state": vol.get("State")})


class PublicEC2InstanceRule(Rule):
    rule_id = "EC2-003"
    title = "EC2 instance has a public IP address"
    severity = Severity.LOW
    service = "ec2"
    description = "This instance is directly reachable from the internet. Confirm this is intentional."
    remediation = "Move instances that don't need to be internet-facing behind a private subnet / load balancer / bastion."
    references = ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html"]

    def run(self) -> Iterable[Finding]:
        ec2 = self.clients["ec2"]
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    if instance.get("State", {}).get("Name") == "terminated":
                        continue
                    if instance.get("PublicIpAddress"):
                        yield self.make_finding(
                            instance["InstanceId"],
                            evidence={"public_ip": instance["PublicIpAddress"]},
                        )


class DefaultVPCInUseRule(Rule):
    rule_id = "EC2-004"
    title = "Default VPC is present and in use"
    severity = Severity.INFO
    service = "ec2"
    description = "The default VPC has permissive default settings and is often used accidentally in production."
    remediation = "Use custom VPCs with intentional subnetting/routing; consider deleting unused default VPCs."
    references = ["https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html"]

    def run(self) -> Iterable[Finding]:
        ec2 = self.clients["ec2"]
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])["Vpcs"]
        for vpc in vpcs:
            yield self.make_finding(vpc["VpcId"])


ALL_RULES = [
    OpenSecurityGroupRule,
    UnencryptedEBSVolumeRule,
    PublicEC2InstanceRule,
    DefaultVPCInUseRule,
]
