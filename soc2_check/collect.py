"""Reads the account. Read-only: every call here is a Describe, Get or List,
plus generating the IAM credential report. Nothing is created, changed or
deleted. Each section is read on its own, so one missing permission never
stops the rest: it is recorded in data['errors'] and shown as UNKNOWN.
"""
import csv
import io
import time

WORLD = ('0.0.0.0/0', '::/0')


def _short(error):
    code = getattr(error, 'response', {}).get('Error', {}).get('Code')
    return code or type(error).__name__


def _credential_report(iam):
    for _ in range(10):
        if iam.generate_credential_report().get('State') == 'COMPLETE':
            break
        time.sleep(2)
    content = iam.get_credential_report()['Content']
    return list(csv.DictReader(io.StringIO(content.decode('utf-8'))))


def _buckets(s3):
    out = []
    for bucket in s3.list_buckets().get('Buckets', []):
        name = bucket['Name']
        try:
            s3.get_bucket_encryption(Bucket=name)
            encrypted = True
        except Exception as error:
            encrypted = False if _short(error) == 'ServerSideEncryptionConfigurationNotFoundError' else None
        out.append({'Name': name, 'encryption': encrypted})
    return out


def _trails(session, home_region):
    cloudtrail = session.client('cloudtrail', region_name=home_region)
    out = []
    for trail in cloudtrail.describe_trails(includeShadowTrails=False).get('trailList', []):
        client = session.client('cloudtrail', region_name=trail.get('HomeRegion') or home_region)
        status = client.get_trail_status(Name=trail['TrailARN'])
        out.append({'Name': trail['Name'], 'IsMultiRegionTrail': trail.get('IsMultiRegionTrail', False),
                    'LogFileValidationEnabled': trail.get('LogFileValidationEnabled', False), 'IsLogging': status.get('IsLogging', False)})
    return out


def _open_rules(group):
    rules = []
    for permission in group.get('IpPermissions', []):
        world = any(r.get('CidrIp') in WORLD for r in permission.get('IpRanges', [])) or \
                any(r.get('CidrIpv6') in WORLD for r in permission.get('Ipv6Ranges', []))
        if world:
            all_ports = permission.get('IpProtocol') == '-1'
            rules.append({'from': None if all_ports else permission.get('FromPort'), 'to': None if all_ports else permission.get('ToPort')})
    return rules


def _region(session, region):
    """One region. Each value is None when it could not be read."""
    info = {}

    def read(key, fn):
        try:
            info[key] = fn()
        except Exception:
            info[key] = None

    ec2 = session.client('ec2', region_name=region)
    read('ebs_default_encryption', lambda: bool(ec2.get_ebs_encryption_by_default().get('EbsEncryptionByDefault')))

    def vpcs():
        logged = {log['ResourceId'] for page in ec2.get_paginator('describe_flow_logs').paginate() for log in page.get('FlowLogs', [])}
        return [{'id': vpc['VpcId'], 'flow_logs': vpc['VpcId'] in logged}
                for page in ec2.get_paginator('describe_vpcs').paginate() for vpc in page.get('Vpcs', [])]
    read('vpcs', vpcs)

    read('security_groups', lambda: [{'id': group['GroupId'], 'open_rules': _open_rules(group)}
                                     for page in ec2.get_paginator('describe_security_groups').paginate()
                                     for group in page.get('SecurityGroups', [])])

    read('guardduty', lambda: bool(session.client('guardduty', region_name=region).list_detectors().get('DetectorIds')))

    read('config_recording', lambda: any(status.get('recording') for status in
                                         session.client('config', region_name=region)
                                         .describe_configuration_recorder_status().get('ConfigurationRecordersStatus', [])))

    def databases():
        rds = session.client('rds', region_name=region)
        return [{'id': db['DBInstanceIdentifier'], 'encrypted': db.get('StorageEncrypted', False),
                 'backup_retention': db.get('BackupRetentionPeriod', 0), 'public': db.get('PubliclyAccessible', False)}
                for page in rds.get_paginator('describe_db_instances').paginate() for db in page.get('DBInstances', [])]
    read('rds', databases)

    def keys():
        kms = session.client('kms', region_name=region)
        out = []
        for page in kms.get_paginator('list_keys').paginate():
            for key in page.get('Keys', []):
                meta = kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']
                if meta.get('KeyManager') != 'CUSTOMER' or meta.get('KeyState') != 'Enabled' or meta.get('KeySpec', 'SYMMETRIC_DEFAULT') != 'SYMMETRIC_DEFAULT':
                    continue
                out.append({'id': key['KeyId'], 'rotation': bool(kms.get_key_rotation_status(KeyId=key['KeyId']).get('KeyRotationEnabled'))})
        return out
    read('kms_keys', keys)
    return info


def collect(session, regions=None, progress=lambda text: None):
    data = {'errors': {}}

    def read(section, fn):
        progress(section)
        try:
            data[section] = fn()
        except Exception as error:
            data[section] = None
            data['errors'][section] = _short(error)

    home = session.region_name or 'us-east-1'
    iam = session.client('iam')
    read('account_id', lambda: session.client('sts').get_caller_identity()['Account'])
    read('account_summary', lambda: iam.get_account_summary()['SummaryMap'])

    def policy():
        try:
            return iam.get_account_password_policy()['PasswordPolicy']
        except Exception as error:
            if _short(error) == 'NoSuchEntity':
                return {}
            raise
    read('password_policy', policy)
    read('credential_report', lambda: _credential_report(iam))
    read('trails', lambda: _trails(session, home))
    read('buckets', lambda: _buckets(session.client('s3')))

    def account_block():
        try:
            return session.client('s3control').get_public_access_block(AccountId=data['account_id'])['PublicAccessBlockConfiguration']
        except Exception as error:
            if _short(error) == 'NoSuchPublicAccessBlockConfiguration':
                return {}
            raise
    read('s3_account_pab', account_block)

    if not regions:
        try:
            regions = sorted(r['RegionName'] for r in session.client('ec2', region_name=home).describe_regions()['Regions'])
        except Exception as error:
            data['errors']['regions'] = _short(error)
            regions = []
    data['regions'] = {}
    for region in regions:
        progress(f'region {region}')
        data['regions'][region] = _region(session, region)
    if not data['regions'] and 'regions' not in data['errors']:
        data['errors']['regions'] = 'no regions to check'
    return data
