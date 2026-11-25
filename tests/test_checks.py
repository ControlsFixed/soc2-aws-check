import json
import unittest
from datetime import datetime, timezone

from soc2_check.checks import CHECKS, FAIL, PASS, UNKNOWN, key_rotation, run_all
from soc2_check.collect import collect
from soc2_check.report import as_json, as_markdown, as_text

NOW = datetime(2026, 11, 22, tzinfo=timezone.utc)


def healthy():
    return {
        'errors': {}, 'account_id': '111122223333',
        'account_summary': {'AccountMFAEnabled': 1, 'AccountAccessKeysPresent': 0},
        'password_policy': {'MinimumPasswordLength': 14},
        'credential_report': [
            {'user': '<root_account>', 'password_enabled': 'not_supported', 'mfa_active': 'true', 'access_key_1_active': 'false', 'access_key_2_active': 'false'},
            {'user': 'amine', 'password_enabled': 'true', 'mfa_active': 'true', 'access_key_1_active': 'true',
             'access_key_1_last_rotated': '2026-10-20T10:00:00+00:00', 'access_key_2_active': 'false'},
        ],
        'trails': [{'Name': 'org-trail', 'IsMultiRegionTrail': True, 'LogFileValidationEnabled': True, 'IsLogging': True}],
        'buckets': [{'Name': 'app-data', 'encryption': True}],
        's3_account_pab': {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True},
        'regions': {'eu-west-1': {
            'ebs_default_encryption': True, 'guardduty': True, 'config_recording': True,
            'vpcs': [{'id': 'vpc-1', 'flow_logs': True}],
            'security_groups': [{'id': 'sg-web', 'open_rules': [{'from': 443, 'to': 443}]}],
            'rds': [{'id': 'app-db', 'encrypted': True, 'backup_retention': 14, 'public': False}],
            'kms_keys': [{'id': 'key-1', 'rotation': True}],
        }},
    }


def broken():
    data = healthy()
    data['account_summary'] = {'AccountMFAEnabled': 0, 'AccountAccessKeysPresent': 1}
    data['password_policy'] = {}
    data['credential_report'][1].update({'mfa_active': 'false', 'access_key_1_last_rotated': '2025-01-01T00:00:00+00:00'})
    data['trails'] = [{'Name': 'old', 'IsMultiRegionTrail': False, 'LogFileValidationEnabled': False, 'IsLogging': True}]
    data['buckets'] = [{'Name': 'app-data', 'encryption': False}]
    data['s3_account_pab'] = {'BlockPublicAcls': True}
    data['regions']['eu-west-1'] = {
        'ebs_default_encryption': False, 'guardduty': False, 'config_recording': False,
        'vpcs': [{'id': 'vpc-1', 'flow_logs': False}],
        'security_groups': [{'id': 'sg-all', 'open_rules': [{'from': None, 'to': None}]}, {'id': 'sg-ssh', 'open_rules': [{'from': 22, 'to': 22}]}],
        'rds': [{'id': 'app-db', 'encrypted': False, 'backup_retention': 1, 'public': True}],
        'kms_keys': [{'id': 'key-1', 'rotation': False}],
    }
    return data


def by_id(results):
    return {r.id: r for r in results}


class Checks(unittest.TestCase):
    def test_a_well_set_up_account_passes_everything(self):
        results = run_all(healthy())
        self.assertEqual(len(results), len(CHECKS))
        self.assertEqual([r.id for r in results if r.status != PASS], [])
        self.assertTrue(all(not r.fix for r in results), 'a passing check offers no fix')

    def test_a_badly_set_up_account_fails_everything_and_names_what_to_fix(self):
        results = by_id(run_all(broken()))
        self.assertEqual([r.id for r in results.values() if r.status != FAIL], [])
        self.assertTrue(all(r.fix for r in results.values()))
        self.assertEqual(results['IAM-3'].resources, ['amine'])
        self.assertIn('app-db (eu-west-1)', results['ENC-3'].resources)
        self.assertIn('vpc-1 (eu-west-1)', results['LOG-3'].resources)
        self.assertEqual(results['LOG-4'].resources, ['eu-west-1'])

    def test_open_ports_only_count_when_they_are_sensitive(self):
        data = healthy()
        self.assertEqual(by_id(run_all(data))['NET-2'].status, PASS, '443 open to the world is a web server, not a finding')
        data['regions']['eu-west-1']['security_groups'] = [{'id': 'sg-range', 'open_rules': [{'from': 5000, 'to': 6000}]}]
        result = by_id(run_all(data))['NET-2']
        self.assertEqual(result.status, FAIL)
        self.assertIn('PostgreSQL', result.resources[0])

    def test_all_ports_open_is_reported_once_per_group(self):
        result = by_id(run_all(broken()))['NET-2']
        self.assertEqual(len(result.resources), 2)
        self.assertIn('all ports', result.resources[0])
        self.assertIn('SSH', result.resources[1])

    def test_old_keys_are_measured_in_days(self):
        check = next(c for c in CHECKS if c['id'] == 'IAM-5')
        self.assertEqual(key_rotation(check, healthy(), NOW).status, PASS)
        result = key_rotation(check, broken(), NOW)
        self.assertEqual(result.status, FAIL)
        self.assertIn('amine (key 1, 690 days)', result.resources)

    def test_a_missing_permission_is_unknown_not_a_false_pass(self):
        data = healthy()
        data['account_summary'] = None
        data['errors']['account_summary'] = 'AccessDenied'
        data['regions']['eu-west-1']['guardduty'] = None
        data['regions']['eu-west-1']['rds'] = None
        results = by_id(run_all(data))
        for check_id in ('IAM-1', 'IAM-2', 'LOG-4', 'ENC-3', 'NET-3', 'BAK-1'):
            self.assertEqual(results[check_id].status, UNKNOWN, check_id)
        self.assertIn('AccessDenied', results['IAM-1'].detail)
        self.assertEqual(results['IAM-3'].status, PASS, 'other checks still run')

    def test_a_failure_in_one_region_beats_unknown_in_another(self):
        data = healthy()
        data['regions']['us-east-1'] = dict(data['regions']['eu-west-1'], guardduty=False)
        data['regions']['eu-west-1']['guardduty'] = None
        result = by_id(run_all(data))['LOG-4']
        self.assertEqual(result.status, FAIL)
        self.assertEqual(result.resources, ['us-east-1'])

    def test_an_account_with_nothing_in_it_is_not_a_failure(self):
        data = healthy()
        data['buckets'] = []
        data['regions']['eu-west-1'].update({'rds': [], 'kms_keys': [], 'vpcs': []})
        results = by_id(run_all(data))
        for check_id in ('ENC-2', 'ENC-3', 'ENC-4', 'LOG-3', 'BAK-1'):
            self.assertEqual(results[check_id].status, PASS, check_id)
        self.assertIn('No databases found', results['ENC-3'].detail)

    def test_no_trails_at_all_fails_both_trail_checks(self):
        data = healthy()
        data['trails'] = []
        results = by_id(run_all(data))
        self.assertEqual((results['LOG-1'].status, results['LOG-2'].status), (FAIL, FAIL))


class Reports(unittest.TestCase):
    def test_text_report_counts_and_never_claims_compliance(self):
        text = as_text(run_all(broken()), '111122223333')
        self.assertIn('0 passed · 18 failed · 0 could not be checked', text)
        self.assertIn('It is not an audit', text)
        self.assertIn('Fix:', text)

    def test_markdown_and_json_carry_the_same_results(self):
        results = run_all(broken())
        markdown = as_markdown(results, '111122223333', when='2026-11-22 10:00 UTC')
        self.assertIn('| IAM-1 | Root user has MFA | CC6.1 | FAIL |', markdown)
        self.assertIn('## To fix or review', markdown)
        payload = json.loads(as_json(results, '111122223333'))
        self.assertEqual(payload['summary'], {'PASS': 0, 'FAIL': 18, 'UNKNOWN': 0})
        self.assertNotIn('To fix or review', as_markdown(run_all(healthy())))


# ---- collecting, against a stand-in for boto3 (no AWS account needed)

class Denied(Exception):
    response = {'Error': {'Code': 'AccessDenied'}}


class Pages:
    def __init__(self, page):
        self.page = page

    def paginate(self):
        return [self.page]


class FakeClient:
    def __init__(self, service, deny):
        self.service, self.deny = service, deny

    def _guard(self, name):
        if f'{self.service}.{name}' in self.deny:
            raise Denied()

    def __getattr__(self, name):
        answers = {
            'sts.get_caller_identity': {'Account': '111122223333'},
            'iam.get_account_summary': {'SummaryMap': {'AccountMFAEnabled': 1, 'AccountAccessKeysPresent': 0}},
            'iam.get_account_password_policy': {'PasswordPolicy': {'MinimumPasswordLength': 14}},
            'iam.generate_credential_report': {'State': 'COMPLETE'},
            'iam.get_credential_report': {'Content': b'user,password_enabled,mfa_active,access_key_1_active,access_key_2_active\nsara,true,true,false,false\n'},
            'cloudtrail.describe_trails': {'trailList': [{'Name': 't', 'TrailARN': 'arn:t', 'HomeRegion': 'eu-west-1', 'IsMultiRegionTrail': True, 'LogFileValidationEnabled': True}]},
            'cloudtrail.get_trail_status': {'IsLogging': True},
            's3.list_buckets': {'Buckets': [{'Name': 'b1'}]},
            's3.get_bucket_encryption': {'ServerSideEncryptionConfiguration': {}},
            's3control.get_public_access_block': {'PublicAccessBlockConfiguration': {'BlockPublicAcls': True, 'IgnorePublicAcls': True, 'BlockPublicPolicy': True, 'RestrictPublicBuckets': True}},
            'ec2.describe_regions': {'Regions': [{'RegionName': 'eu-west-1'}]},
            'ec2.get_ebs_encryption_by_default': {'EbsEncryptionByDefault': True},
            'guardduty.list_detectors': {'DetectorIds': ['d1']},
            'config.describe_configuration_recorder_status': {'ConfigurationRecordersStatus': [{'recording': True}]},
            'kms.describe_key': {'KeyMetadata': {'KeyManager': 'CUSTOMER', 'KeyState': 'Enabled', 'KeySpec': 'SYMMETRIC_DEFAULT'}},
            'kms.get_key_rotation_status': {'KeyRotationEnabled': True},
        }
        key = f'{self.service}.{name}'
        if name == 'get_paginator':
            return self._paginator
        if key not in answers:
            raise AttributeError(key)

        def call(**kwargs):
            self._guard(name)
            return answers[key]
        return call

    def _paginator(self, name):
        self._guard(name)
        pages = {
            'ec2.describe_flow_logs': {'FlowLogs': [{'ResourceId': 'vpc-1'}]},
            'ec2.describe_vpcs': {'Vpcs': [{'VpcId': 'vpc-1'}]},
            'ec2.describe_security_groups': {'SecurityGroups': [{'GroupId': 'sg-1', 'IpPermissions': [
                {'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
                {'IpProtocol': 'tcp', 'FromPort': 5432, 'ToPort': 5432, 'IpRanges': [{'CidrIp': '10.0.0.0/16'}]}]}]},
            'rds.describe_db_instances': {'DBInstances': [{'DBInstanceIdentifier': 'db1', 'StorageEncrypted': True, 'BackupRetentionPeriod': 7, 'PubliclyAccessible': False}]},
            'kms.list_keys': {'Keys': [{'KeyId': 'k1'}]},
        }
        return Pages(pages[f'{self.service}.{name}'])


class FakeSession:
    region_name = 'eu-west-1'

    def __init__(self, deny=()):
        self.deny = set(deny)

    def client(self, service, region_name=None):
        return FakeClient(service, self.deny)


class Collecting(unittest.TestCase):
    def test_it_reads_an_account_into_the_shape_the_checks_use(self):
        data = collect(FakeSession())
        self.assertEqual(data['errors'], {})
        self.assertEqual(data['account_id'], '111122223333')
        self.assertEqual(data['credential_report'][0]['user'], 'sara')
        region = data['regions']['eu-west-1']
        self.assertEqual(region['vpcs'], [{'id': 'vpc-1', 'flow_logs': True}])
        self.assertEqual(region['security_groups'][0]['open_rules'], [{'from': 22, 'to': 22}], 'only rules open to the world are kept')
        results = by_id(run_all(data))
        self.assertEqual(results['NET-2'].status, FAIL)
        self.assertEqual([r.id for r in results.values() if r.status == UNKNOWN], [])

    def test_one_denied_call_does_not_stop_the_rest(self):
        data = collect(FakeSession(deny=['iam.get_account_summary', 'guardduty.list_detectors']))
        self.assertEqual(data['errors'], {'account_summary': 'AccessDenied'})
        self.assertIsNone(data['regions']['eu-west-1']['guardduty'])
        results = by_id(run_all(data))
        self.assertEqual(results['IAM-1'].status, UNKNOWN)
        self.assertEqual(results['LOG-4'].status, UNKNOWN)
        self.assertEqual(results['ENC-3'].status, PASS)

    def test_only_the_regions_asked_for_are_read(self):
        data = collect(FakeSession(), regions=['us-east-1'])
        self.assertEqual(list(data['regions']), ['us-east-1'])


if __name__ == '__main__':
    unittest.main()
