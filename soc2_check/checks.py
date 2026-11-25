"""The checks. Each one looks at data already collected from the account and
returns a Result. Nothing here talks to AWS, so every check can be tested
with plain dictionaries.

The "criteria" on each check is the SOC 2 Trust Services Criteria it is
usually mapped to. Your auditor decides the final mapping, not this tool.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone

PASS, FAIL, UNKNOWN = 'PASS', 'FAIL', 'UNKNOWN'
KEY_MAX_AGE_DAYS = 90
MIN_BACKUP_DAYS = 7
MIN_PASSWORD_LENGTH = 8
# Ports that should never be open to the whole internet.
SENSITIVE_PORTS = {22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'SQL Server', 27017: 'MongoDB', 6379: 'Redis'}


@dataclass
class Result:
    id: str
    title: str
    criteria: str
    status: str
    detail: str
    fix: str = ''
    resources: list = field(default_factory=list)


def _result(check, status, detail, resources=None):
    return Result(check['id'], check['title'], check['criteria'], status, detail,
                  check['fix'] if status == FAIL else '', sorted(resources or []))


def _missing(check, data, *sections):
    """UNKNOWN when a section could not be read, with the reason."""
    for section in sections:
        if section in data.get('errors', {}):
            return _result(check, UNKNOWN, f"Could not read {section}: {data['errors'][section]}")
        if data.get(section) is None:
            return _result(check, UNKNOWN, f'No data for {section}.')
    return None


def _regions(data):
    return data.get('regions') or {}


def _parse_time(value):
    if not value or value in ('N/A', 'no_information', 'not_supported'):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- IAM

def root_mfa(check, data):
    return _missing(check, data, 'account_summary') or (
        _result(check, PASS, 'The root user has MFA.') if data['account_summary'].get('AccountMFAEnabled') == 1
        else _result(check, FAIL, 'The root user has no MFA device.'))


def root_keys(check, data):
    return _missing(check, data, 'account_summary') or (
        _result(check, PASS, 'The root user has no access keys.') if data['account_summary'].get('AccountAccessKeysPresent') == 0
        else _result(check, FAIL, 'The root user has access keys.'))


def console_mfa(check, data):
    gone = _missing(check, data, 'credential_report')
    if gone:
        return gone
    without = [row['user'] for row in data['credential_report']
               if row.get('user') != '<root_account>' and row.get('password_enabled') == 'true' and row.get('mfa_active') != 'true']
    if without:
        return _result(check, FAIL, f'{len(without)} user(s) can sign in to the console without MFA.', without)
    return _result(check, PASS, 'Every user with a console password has MFA.')


def password_policy(check, data):
    if 'password_policy' in data.get('errors', {}):
        return _result(check, UNKNOWN, f"Could not read password_policy: {data['errors']['password_policy']}")
    policy = data.get('password_policy')
    if not policy:
        return _result(check, FAIL, 'No account password policy is set.')
    length = int(policy.get('MinimumPasswordLength', 0))
    if length < MIN_PASSWORD_LENGTH:
        return _result(check, FAIL, f'Minimum password length is {length}.')
    return _result(check, PASS, f'A password policy is set (minimum length {length}).')


def key_rotation(check, data, now=None):
    gone = _missing(check, data, 'credential_report')
    if gone:
        return gone
    now = now or datetime.now(timezone.utc)
    old = []
    for row in data['credential_report']:
        for n in ('1', '2'):
            if row.get(f'access_key_{n}_active') != 'true':
                continue
            rotated = _parse_time(row.get(f'access_key_{n}_last_rotated'))
            if rotated and (now - rotated).days > KEY_MAX_AGE_DAYS:
                old.append(f"{row['user']} (key {n}, {(now - rotated).days} days)")
    if old:
        return _result(check, FAIL, f'{len(old)} active access key(s) are older than {KEY_MAX_AGE_DAYS} days.', old)
    return _result(check, PASS, f'No active access key is older than {KEY_MAX_AGE_DAYS} days.')


# ---------------------------------------------------------------- Logging and monitoring

def cloudtrail_on(check, data):
    gone = _missing(check, data, 'trails')
    if gone:
        return gone
    good = [t['Name'] for t in data['trails'] if t.get('IsMultiRegionTrail') and t.get('IsLogging')]
    if good:
        return _result(check, PASS, f'Multi-region trail logging: {", ".join(sorted(good))}.')
    return _result(check, FAIL, 'No multi-region CloudTrail trail is logging.' if data['trails'] else 'CloudTrail has no trails.')


def cloudtrail_validation(check, data):
    gone = _missing(check, data, 'trails')
    if gone:
        return gone
    if not data['trails']:
        return _result(check, FAIL, 'CloudTrail has no trails.')
    off = [t['Name'] for t in data['trails'] if not t.get('LogFileValidationEnabled')]
    if off:
        return _result(check, FAIL, f'{len(off)} trail(s) without log file validation.', off)
    return _result(check, PASS, 'Every trail has log file validation.')


def _per_region(check, data, key, ok_text, bad_text):
    gone = _missing(check, data, 'regions')
    if gone:
        return gone
    regions = _regions(data)
    unknown = [name for name, info in regions.items() if info.get(key) is None]
    off = [name for name, info in regions.items() if info.get(key) is False]
    if off:
        return _result(check, FAIL, f'{bad_text} in {len(off)} region(s).', off)
    if unknown:
        return _result(check, UNKNOWN, f'Could not read this in: {", ".join(sorted(unknown))}.')
    return _result(check, PASS, f'{ok_text} in all {len(regions)} region(s) checked.')


def guardduty(check, data):
    return _per_region(check, data, 'guardduty', 'GuardDuty is on', 'GuardDuty is off')


def config_recording(check, data):
    return _per_region(check, data, 'config_recording', 'AWS Config is recording', 'AWS Config is not recording')


def ebs_default_encryption(check, data):
    return _per_region(check, data, 'ebs_default_encryption', 'EBS encryption by default is on', 'EBS encryption by default is off')


def _collect(data, key):
    """All items of one kind across regions, or None if any region could not be read."""
    items = []
    for name, info in _regions(data).items():
        if info.get(key) is None:
            return None
        items += [dict(item, region=name) for item in info[key]]
    return items


def _resource_check(check, data, key, is_bad, label, ok_text, bad_text):
    gone = _missing(check, data, 'regions')
    if gone:
        return gone
    items = _collect(data, key)
    if items is None:
        return _result(check, UNKNOWN, f'Could not read {label} in every region.')
    bad = [f"{item['id']} ({item['region']})" for item in items if is_bad(item)]
    if bad:
        return _result(check, FAIL, f'{len(bad)} {bad_text}.', bad)
    return _result(check, PASS, ok_text if items else f'No {label} found.')


def vpc_flow_logs(check, data):
    return _resource_check(check, data, 'vpcs', lambda v: not v.get('flow_logs'), 'VPCs',
                           'Every VPC has flow logs.', 'VPC(s) without flow logs')


# ---------------------------------------------------------------- Encryption

def s3_encryption(check, data):
    gone = _missing(check, data, 'buckets')
    if gone:
        return gone
    unknown = [b['Name'] for b in data['buckets'] if b.get('encryption') is None]
    off = [b['Name'] for b in data['buckets'] if b.get('encryption') is False]
    if off:
        return _result(check, FAIL, f'{len(off)} bucket(s) without default encryption.', off)
    if unknown:
        return _result(check, UNKNOWN, f'Could not read encryption on {len(unknown)} bucket(s).', unknown)
    return _result(check, PASS, f'All {len(data["buckets"])} bucket(s) have default encryption.' if data['buckets'] else 'No buckets found.')


def rds_encryption(check, data):
    return _resource_check(check, data, 'rds', lambda d: not d.get('encrypted'), 'databases',
                           'Every database is encrypted at rest.', 'database(s) not encrypted at rest')


def kms_rotation(check, data):
    return _resource_check(check, data, 'kms_keys', lambda k: not k.get('rotation'), 'customer-managed keys',
                           'Every customer-managed key rotates.', 'customer-managed key(s) without rotation')


# ---------------------------------------------------------------- Network exposure

def s3_public_block(check, data):
    if 's3_account_pab' in data.get('errors', {}):
        return _result(check, UNKNOWN, f"Could not read s3_account_pab: {data['errors']['s3_account_pab']}")
    block = data.get('s3_account_pab')
    if not block:
        return _result(check, FAIL, 'Account-level S3 Block Public Access is not configured.')
    off = [name for name in ('BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets') if not block.get(name)]
    if off:
        return _result(check, FAIL, 'Account-level S3 Block Public Access is only partly on.', off)
    return _result(check, PASS, 'Account-level S3 Block Public Access is fully on.')


def open_security_groups(check, data):
    gone = _missing(check, data, 'regions')
    if gone:
        return gone
    groups = _collect(data, 'security_groups')
    if groups is None:
        return _result(check, UNKNOWN, 'Could not read security groups in every region.')
    bad = []
    for group in groups:
        for rule in group.get('open_rules', []):
            low, high = rule.get('from'), rule.get('to')
            if low is None:
                bad.append(f"{group['id']} ({group['region']}): all ports open to the internet")
                continue
            hit = [p for p in sorted(SENSITIVE_PORTS) if low <= p <= high]
            if hit:
                bad.append(f"{group['id']} ({group['region']}): {', '.join(SENSITIVE_PORTS[p] for p in hit)} open to the internet")
    if bad:
        return _result(check, FAIL, f'{len(bad)} rule(s) open admin or database ports to the internet.', bad)
    return _result(check, PASS, 'No security group opens admin or database ports to the internet.')


def rds_public(check, data):
    return _resource_check(check, data, 'rds', lambda d: d.get('public'), 'databases',
                           'No database is publicly accessible.', 'database(s) publicly accessible')


# ---------------------------------------------------------------- Backups

def rds_backups(check, data):
    return _resource_check(check, data, 'rds', lambda d: int(d.get('backup_retention') or 0) < MIN_BACKUP_DAYS, 'databases',
                           f'Every database keeps backups for at least {MIN_BACKUP_DAYS} days.',
                           f'database(s) keep backups for less than {MIN_BACKUP_DAYS} days')


CHECKS = [
    {'id': 'IAM-1', 'title': 'Root user has MFA', 'criteria': 'CC6.1', 'run': root_mfa,
     'fix': 'Sign in as root and add an MFA device under Security credentials.'},
    {'id': 'IAM-2', 'title': 'Root user has no access keys', 'criteria': 'CC6.1', 'run': root_keys,
     'fix': 'Delete the root access keys. Use IAM roles or IAM Identity Center instead.'},
    {'id': 'IAM-3', 'title': 'Console users have MFA', 'criteria': 'CC6.1', 'run': console_mfa,
     'fix': 'Require MFA for every console user, or move sign-in to IAM Identity Center with MFA enforced.'},
    {'id': 'IAM-4', 'title': 'Password policy is set', 'criteria': 'CC6.1', 'run': password_policy,
     'fix': f'Set an account password policy with a minimum length of at least {MIN_PASSWORD_LENGTH} (14 is the common recommendation).'},
    {'id': 'IAM-5', 'title': f'Access keys are rotated within {KEY_MAX_AGE_DAYS} days', 'criteria': 'CC6.1', 'run': key_rotation,
     'fix': 'Rotate or delete the listed keys. Prefer roles over long-lived keys.'},
    {'id': 'LOG-1', 'title': 'CloudTrail logs every region', 'criteria': 'CC7.2', 'run': cloudtrail_on,
     'fix': 'Create a multi-region trail that delivers to a dedicated S3 bucket, and start logging.'},
    {'id': 'LOG-2', 'title': 'CloudTrail log file validation is on', 'criteria': 'CC7.2', 'run': cloudtrail_validation,
     'fix': 'Turn on log file validation for each trail.'},
    {'id': 'LOG-3', 'title': 'VPC flow logs are on', 'criteria': 'CC7.2', 'run': vpc_flow_logs,
     'fix': 'Enable flow logs on each listed VPC (to CloudWatch Logs or S3).'},
    {'id': 'LOG-4', 'title': 'GuardDuty is on', 'criteria': 'CC7.2', 'run': guardduty,
     'fix': 'Enable GuardDuty in each listed region.'},
    {'id': 'LOG-5', 'title': 'AWS Config is recording', 'criteria': 'CC7.1', 'run': config_recording,
     'fix': 'Turn on the AWS Config recorder in each listed region.'},
    {'id': 'ENC-1', 'title': 'EBS encryption by default', 'criteria': 'CC6.1', 'run': ebs_default_encryption,
     'fix': 'Enable EBS encryption by default in each listed region.'},
    {'id': 'ENC-2', 'title': 'S3 buckets are encrypted', 'criteria': 'CC6.1', 'run': s3_encryption,
     'fix': 'Set default encryption (SSE-S3 or SSE-KMS) on each listed bucket.'},
    {'id': 'ENC-3', 'title': 'Databases are encrypted at rest', 'criteria': 'CC6.1', 'run': rds_encryption,
     'fix': 'RDS encryption cannot be switched on in place: snapshot, copy the snapshot with encryption, restore, and cut over.'},
    {'id': 'ENC-4', 'title': 'KMS keys rotate', 'criteria': 'CC6.1', 'run': kms_rotation,
     'fix': 'Enable automatic rotation on each listed customer-managed key.'},
    {'id': 'NET-1', 'title': 'S3 public access is blocked', 'criteria': 'CC6.6', 'run': s3_public_block,
     'fix': 'Turn on all four account-level S3 Block Public Access settings.'},
    {'id': 'NET-2', 'title': 'No admin or database port open to the internet', 'criteria': 'CC6.6', 'run': open_security_groups,
     'fix': 'Restrict each listed rule to known addresses, or use Session Manager or a VPN instead.'},
    {'id': 'NET-3', 'title': 'Databases are not public', 'criteria': 'CC6.6', 'run': rds_public,
     'fix': 'Set each listed database to not publicly accessible and reach it through the VPC.'},
    {'id': 'BAK-1', 'title': f'Databases keep {MIN_BACKUP_DAYS}+ days of backups', 'criteria': 'A1.2', 'run': rds_backups,
     'fix': f'Set the backup retention period to at least {MIN_BACKUP_DAYS} days on each listed database.'},
]


def run_all(data):
    return [check['run'](check, data) for check in CHECKS]
