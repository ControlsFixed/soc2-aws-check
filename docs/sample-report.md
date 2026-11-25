# SOC 2 readiness check — AWS

- **Account:** 111122223333 (example)
- **Run:** 2026-11-22 10:00 UTC
- **Result:** 8 passed · 10 failed · 0 could not be checked

> This is a readiness check of common AWS settings. It is not an audit, and passing it does not make an account SOC 2 compliant: an independent CPA firm decides that.

| Check | What | Usually mapped to | Result |
|---|---|---|---|
| IAM-1 | Root user has MFA | CC6.1 | PASS |
| IAM-2 | Root user has no access keys | CC6.1 | PASS |
| IAM-3 | Console users have MFA | CC6.1 | FAIL |
| IAM-4 | Password policy is set | CC6.1 | FAIL |
| IAM-5 | Access keys are rotated within 90 days | CC6.1 | FAIL |
| LOG-1 | CloudTrail logs every region | CC7.2 | PASS |
| LOG-2 | CloudTrail log file validation is on | CC7.2 | PASS |
| LOG-3 | VPC flow logs are on | CC7.2 | FAIL |
| LOG-4 | GuardDuty is on | CC7.2 | FAIL |
| LOG-5 | AWS Config is recording | CC7.1 | FAIL |
| ENC-1 | EBS encryption by default | CC6.1 | PASS |
| ENC-2 | S3 buckets are encrypted | CC6.1 | PASS |
| ENC-3 | Databases are encrypted at rest | CC6.1 | FAIL |
| ENC-4 | KMS keys rotate | CC6.1 | PASS |
| NET-1 | S3 public access is blocked | CC6.6 | PASS |
| NET-2 | No admin or database port open to the internet | CC6.6 | FAIL |
| NET-3 | Databases are not public | CC6.6 | FAIL |
| BAK-1 | Databases keep 7+ days of backups | A1.2 | FAIL |

## To fix or review

### IAM-3 · Console users have MFA

**FAIL** — 1 user(s) can sign in to the console without MFA.

- `amine`

**Fix:** Require MFA for every console user, or move sign-in to IAM Identity Center with MFA enforced.

### IAM-4 · Password policy is set

**FAIL** — No account password policy is set.


**Fix:** Set an account password policy with a minimum length of at least 8 (14 is the common recommendation).

### IAM-5 · Access keys are rotated within 90 days

**FAIL** — 1 active access key(s) are older than 90 days.

- `amine (key 1, 690 days)`

**Fix:** Rotate or delete the listed keys. Prefer roles over long-lived keys.

### LOG-3 · VPC flow logs are on

**FAIL** — 1 VPC(s) without flow logs.

- `vpc-1 (eu-west-1)`

**Fix:** Enable flow logs on each listed VPC (to CloudWatch Logs or S3).

### LOG-4 · GuardDuty is on

**FAIL** — GuardDuty is off in 1 region(s).

- `eu-west-1`

**Fix:** Enable GuardDuty in each listed region.

### LOG-5 · AWS Config is recording

**FAIL** — AWS Config is not recording in 1 region(s).

- `eu-west-1`

**Fix:** Turn on the AWS Config recorder in each listed region.

### ENC-3 · Databases are encrypted at rest

**FAIL** — 1 database(s) not encrypted at rest.

- `app-db (eu-west-1)`

**Fix:** RDS encryption cannot be switched on in place: snapshot, copy the snapshot with encryption, restore, and cut over.

### NET-2 · No admin or database port open to the internet

**FAIL** — 2 rule(s) open admin or database ports to the internet.

- `sg-all (eu-west-1): all ports open to the internet`
- `sg-ssh (eu-west-1): SSH open to the internet`

**Fix:** Restrict each listed rule to known addresses, or use Session Manager or a VPN instead.

### NET-3 · Databases are not public

**FAIL** — 1 database(s) publicly accessible.

- `app-db (eu-west-1)`

**Fix:** Set each listed database to not publicly accessible and reach it through the VPC.

### BAK-1 · Databases keep 7+ days of backups

**FAIL** — 1 database(s) keep backups for less than 7 days.

- `app-db (eu-west-1)`

**Fix:** Set the backup retention period to at least 7 days on each listed database.
