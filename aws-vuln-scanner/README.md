# AWS Vulnerability Scanner

A read-only, rule-based security scanner for AWS accounts. It checks IAM,
S3, EC2/networking, RDS, and CloudTrail against common misconfigurations
and vulnerability patterns drawn from the **CIS AWS Foundations Benchmark**
and well-documented cloud attack techniques, then produces a JSON and/or
HTML report ranked by severity.

Inspired by (and a good companion to read alongside) tools like
[Prowler](https://github.com/prowler-cloud/prowler),
[ScoutSuite](https://github.com/nccgroup/ScoutSuite), and
[Cloudsplaining](https://github.com/salesforce/cloudsplaining) — this project
reimplements a focused subset of their checks with a simple, extensible
rule-engine architecture designed to be easy to read, test, and extend.

## Sample report

![Sample HTML report](examples/sample_output.png)

See [`examples/sample_output.json`](examples/sample_output.json) and
[`examples/sample_output.html`](examples/sample_output.html) for full
sample output (synthetic data — no scan was run against a real account
to produce it).

## What it checks

| Category | Rule ID | Check | Severity |
|---|---|---|---|
| IAM | IAM-001 | Root account has no MFA | Critical |
| IAM | IAM-002 | Console-enabled user has no MFA | High |
| IAM | IAM-003 | Access key / credential unused > 90 days | Medium |
| IAM | IAM-004 | Policy grants `Action:*` + `Resource:*` | High |
| IAM | IAM-005 | Known privilege-escalation permission combo | Critical |
| S3 | S3-001 | Bucket is publicly accessible (ACL or policy) | Critical |
| S3 | S3-002 | Bucket has no default encryption | Medium |
| S3 | S3-003 | Bucket versioning disabled | Low |
| S3 | S3-004 | Bucket access logging disabled | Low |
| EC2 | EC2-001 | Security group open to 0.0.0.0/0 on a sensitive port (SSH/RDP/DB ports) | Critical |
| EC2 | EC2-002 | EBS volume not encrypted | Medium |
| EC2 | EC2-003 | Instance has a public IP | Low |
| EC2 | EC2-004 | Default VPC present/in use | Info |
| RDS | RDS-001 | DB instance publicly accessible | Critical |
| RDS | RDS-002 | DB storage not encrypted | Medium |
| RDS | RDS-003 | Automated backups disabled / retention < 7 days | Low |
| RDS | RDS-004 | Multi-AZ disabled | Info |
| CloudTrail | CT-001 | No active multi-region trail | High |
| CloudTrail | CT-002 | Log file validation disabled | Low |
| CloudTrail | CT-003 | Weak/missing account password policy | Medium |

The rule-engine architecture (see below) makes adding a new check a
20–30 line addition, not a refactor.

## Architecture

```
scanner/
├── main.py              # CLI entrypoint (argparse)
├── aws_client.py         # boto3 client/session factory
├── engine.py              # ScanEngine: runs rules concurrently, collects findings
├── rules/
│   ├── base.py            # Rule / Finding / Severity base classes
│   ├── iam_rules.py
│   ├── s3_rules.py
│   ├── ec2_rules.py
│   ├── rds_rules.py
│   └── cloudtrail_rules.py
└── report/
    ├── json_report.py
    ├── html_report.py
    └── templates/report_template.html
```

Each check is an independent `Rule` subclass with a `run()` method that
yields `Finding` objects. The `ScanEngine`:

1. Authenticates and resolves the target account/regions.
2. Builds one boto3 client per AWS service (shared across rules to avoid
   redundant client construction).
3. Runs every applicable rule concurrently via a thread pool (I/O-bound
   AWS API calls benefit significantly from this).
4. Wraps each rule in `safe_run()` so one failing check (e.g. a missing
   permission) never aborts the whole scan — it's downgraded to an
   `INFO` finding explaining what to fix.
5. Sorts findings worst-first and hands them to the JSON/HTML report
   writers.

This mirrors the plugin-style architecture used in the
[Cheat Detection System](../cheat-detection-system) project: independent,
declarative "rules" evaluated by a shared engine, rather than one large
procedural script.

## Installation

```bash
git clone <this-repo>
cd aws-vuln-scanner
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## AWS permissions required

The scanner is strictly **read-only**. Create an IAM user/role with the
policy in [`iam/scanner-policy.json`](iam/scanner-policy.json) — it's a
tightly scoped subset of the AWS-managed `SecurityAudit` policy, listing
only the specific `Describe`/`Get`/`List` actions the checks actually call.

```bash
aws iam create-policy \
  --policy-name AWSVulnScannerReadOnly \
  --policy-document file://iam/scanner-policy.json
```

Attach it to whichever user/role you'll run the scanner as, then configure
credentials normally (`aws configure --profile scanner`, environment
variables, or an assumed role).

## Usage

```bash
# Scan everything in one region using the default AWS credential chain
python -m scanner.main --region us-east-1

# Scan specific services only
python -m scanner.main --services iam,s3 --format json --output iam-s3-findings

# Scan every enabled region (slower, but comprehensive for regional resources)
python -m scanner.main --all-regions --format html

# Use a specific named profile, only show High/Critical in the console
python -m scanner.main --profile scanner --min-severity HIGH
```

Full options:

```
--profile         AWS CLI profile to use
--region          Primary region for global API calls (default: us-east-1)
--regions         Comma-separated regions to scan (default: --region only)
--all-regions     Scan all enabled regions
--services        Comma-separated: iam,s3,ec2,rds,cloudtrail (default: all)
--format          json | html | both (default: both)
--output          Output file base name (default: scan_report)
--min-severity    Console print threshold: CRITICAL|HIGH|MEDIUM|LOW|INFO
--max-workers     Thread pool size (default: 8)
```

The CLI exits with status code `2` if any `CRITICAL` findings were found,
so it can be wired into a CI pipeline as a gate:

```yaml
# example GitHub Actions step
- run: python -m scanner.main --format json --min-severity CRITICAL
```

## Testing

Checks are unit-tested against [moto](https://github.com/getmoto/moto)
(a mock AWS backend), so the test suite runs without touching real AWS
resources or requiring credentials:

```bash
pip install -r requirements.txt   # includes moto + pytest
pytest -v
```

## Extending the scanner

Add a new check by dropping a `Rule` subclass into the relevant module
(or a new module) and registering it:

```python
# scanner/rules/s3_rules.py
class S3MFADeleteRule(Rule):
    rule_id = "S3-005"
    title = "MFA Delete is not enabled on a versioned bucket"
    severity = Severity.LOW
    service = "s3"
    description = "..."
    remediation = "..."

    def run(self):
        s3 = self.clients["s3"]
        for bucket in s3.list_buckets()["Buckets"]:
            versioning = s3.get_bucket_versioning(Bucket=bucket["Name"])
            if versioning.get("Status") == "Enabled" and versioning.get("MFADelete") != "Enabled":
                yield self.make_finding(bucket["Name"])

ALL_RULES = [..., S3MFADeleteRule]
```

Nothing else needs to change — `scanner/rules/__init__.py` auto-registers
every module's `ALL_RULES` list, and the CLI/engine pick it up automatically.

## Limitations & scope notes

This is a portfolio/learning project, not a production compliance tool.
Notably:

- **IAM-005** (privilege escalation) is a heuristic pattern-matcher, not a
  full policy-graph resolver like [PMapper](https://github.com/nccgroup/PMapper) —
  it does not resolve permissions granted indirectly through group
  membership or resource-based policies.
- Checks cover a representative slice of CIS controls, not the full
  benchmark (no Config, GuardDuty, WAF, or Organizations checks yet).
- No remediation is performed automatically — findings are informational
  only, by design, to avoid an automated tool making changes to production
  infrastructure without human review.

## License

MIT — see [LICENSE](LICENSE).
