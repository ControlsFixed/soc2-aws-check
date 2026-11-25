# soc2-aws-check

By [ControlsFixed](https://controlsfixed.com).

A read-only check of an AWS account against the settings that most often fail
during SOC 2 preparation: sign-in, logging, encryption, network exposure and
backups. It tells you what passes, what fails, which resources are involved,
and how to fix each one.

It is a readiness check, not an audit. Passing it does not make an account
SOC 2 compliant: an independent CPA firm decides that.

## What it checks

| Area | Checks |
|---|---|
| Sign-in (IAM) | Root MFA · no root access keys · console users have MFA · password policy · access keys rotated within 90 days |
| Logging and monitoring | CloudTrail in every region · log file validation · VPC flow logs · GuardDuty · AWS Config |
| Encryption | EBS encryption by default · S3 buckets · RDS at rest · KMS key rotation |
| Network exposure | S3 public access blocked · no admin or database port open to the internet · no public database |
| Backups | RDS keeps at least 7 days |

Each check shows the SOC 2 criteria it is usually mapped to (for example
CC6.1 or CC7.2). Your auditor decides the final mapping.

## Run it

```
pip install boto3
python -m soc2_check --profile my-readonly-profile
```

Options:

```
--regions eu-west-1,us-east-1   only these regions (default: every enabled region)
--markdown report.md            also write a report you can hand to an auditor
--json report.json              also write the results as JSON
```

The exit code is 1 when anything fails, so it can run in CI.

See [docs/sample-report.md](docs/sample-report.md) for what a report looks like.

## It only reads

Every call is a Describe, Get or List, plus generating the IAM credential
report. Nothing is created, changed or deleted.

Use a role or user with the AWS managed policy **SecurityAudit** and nothing
else. If a permission is missing, that check is reported as `??` (could not
be checked) and the rest still run. A missing permission is never shown as a
pass.

## Tests

```
python -m unittest discover -s tests -t .
```

The tests need no AWS account.

## Need the failing checks fixed?

ControlsFixed fixes them at a published price per check, delivered as code,
with a full refund for any fix that does not pass: https://controlsfixed.com

## Licence

MIT.
