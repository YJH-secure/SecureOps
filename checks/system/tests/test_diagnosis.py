"""Synthetic data only. Never chmod/chown /etc/passwd to create a test case."""
import copy
import json
import os
import stat
import subprocess
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from checks.system.common import PolicyError, load_policy
from checks.system.file_check import (aggregate, collect_file_info, run, run_from_policy,
                                      validate_file_policy, main)

POLICY_PATH = Path(__file__).parents[1] / 'policies/file_policy.json'
from checks.system.tests.fixtures import singlefile_policy
POLICY = singlefile_policy()


def observation(mode='0644', uid=0, gid=0):
    bits = int(mode, 8)
    permissions = []
    for shift in (6, 3, 0):
        n = (bits >> shift) & 7
        permissions.append(''.join(c if n & b else '-' for c, b in zip('rwx', (4, 2, 1))))
    raw = ''.join(kind + '::' + perms + '\n'
                  for kind, perms in zip(('user', 'group', 'other'), permissions))
    return dict(path='/etc/passwd', uid=uid, gid=gid, owner='fixture', group='fixture',
                mode=mode, file_type='regular', acl={'state': 'collected', 'raw': raw})


def diagnose(data):
    return run(copy.deepcopy(POLICY), collector=lambda path: data,
               environment={'id': 'fixture-os', 'version_id': 'test-only'})


class DiagnosisTests(unittest.TestCase):
    def test_wrong_or_missing_collector_path_cannot_pass(self):
        for path in ('/tmp/other', None):
            data = observation()
            data['path'] = path
            self.assertEqual(diagnose(data)['status'], 'error')

    def test_malformed_observation_returns_error(self):
        for data in (None, [], 'invalid observation'):
            self.assertEqual(diagnose(data)['status'], 'error')

    def test_malformed_acl_preserves_owner_violation(self):
        for acl in (None, [], {'state': 'collected', 'raw': None}):
            data = observation(uid=1000)
            data['acl'] = acl
            result = diagnose(data)
            self.assertEqual(result['status'], 'vulnerable')
            self.assertIn('error', [c['status'] for c in result['details']['files'][0]['checks']])

    def test_unknown_status_cannot_be_hidden_by_pass(self):
        with self.assertRaises(ValueError):
            aggregate(['pass', 'typo'])

    def test_normal_and_more_restrictive_modes(self):
        for mode in ('0644', '0600', '0400', '0000'):
            self.assertEqual(diagnose(observation(mode))['status'], 'pass')

    def test_permission_violations_including_special_bits(self):
        for mode in ('0664', '0646', '0744', '1644', '2644', '4644'):
            self.assertEqual(diagnose(observation(mode))['status'], 'vulnerable')

    def test_uid_violation(self):
        result = diagnose(observation(uid=1000))
        self.assertEqual(result['status'], 'vulnerable')
        check = result['details']['files'][0]['checks'][0]
        self.assertEqual((check['actual'], check['expected']), (1000, 0))

    def test_gid_is_reference_not_violation(self):
        self.assertEqual(diagnose(observation(gid=42))['status'], 'needs_review')

    def test_basic_acl_missing_or_inconsistent(self):
        data = observation()
        data['acl'] = {'state': 'error', 'detail': 'fixture missing getfacl'}
        self.assertEqual(diagnose(data)['status'], 'error')
        data['acl'] = {'state': 'collected', 'raw': 'user::rw-\ngroup::rw-\nother::r--\n'}
        self.assertEqual(diagnose(data)['status'], 'error')

    def test_extended_acl_not_automatically_pass_or_vulnerable(self):
        for effective in ('---', 'rw-'):
            data = observation()
            data['acl']['raw'] += 'user:1234:rw- #effective:' + effective + '\nmask::r--\n'
            self.assertEqual(diagnose(data)['status'], 'needs_review')

    def test_vulnerable_and_error_both_preserved(self):
        data = observation(uid=1000)
        data['acl'] = {'state': 'error', 'detail': 'fixture permission denied'}
        result = diagnose(data)
        self.assertEqual(result['status'], 'vulnerable')
        checks = result['details']['files'][0]['checks']
        self.assertIn('error', [c['status'] for c in checks])
        self.assertIn('vulnerable', [c['status'] for c in checks])
        self.assertIn('fixture permission denied', json.dumps(result))

    def test_vulnerable_and_review_preserved(self):
        self.assertEqual(diagnose(observation(uid=1000, gid=42))['status'], 'vulnerable')

    def test_unstable_snapshot_not_evaluated(self):
        data = observation(uid=1000)
        data['snapshot_error'] = 'fixture race'
        self.assertEqual(diagnose(data)['status'], 'error')

    def test_symlink_not_evaluated_as_target(self):
        data = dict(path='/etc/passwd', file_type='symlink', uid=999, mode='0777',
                    link_target='/fixture/target')
        self.assertEqual(diagnose(data)['status'], 'needs_review')
        data['link_read_error'] = 'fixture readlink failure'
        self.assertEqual(diagnose(data)['status'], 'error')

    def test_missing_file(self):
        result = run(POLICY, collector=Mock(side_effect=FileNotFoundError('fixture')),
                     environment={'id': 'fixture'})
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['files'][0]['path'], '/etc/passwd')

    def test_results_match_v11_fields(self):
        result = diagnose(observation())
        self.assertEqual(set(result), {'check_id', 'status', 'severity', 'evidence', 'recommendation', 'details'})
        self.assertIsInstance(result['evidence'], str)
        self.assertTrue(result['recommendation'].strip())
        self.assertEqual(json.loads(json.dumps(result)), result)

    def test_priority_and_no_exclusions(self):
        self.assertEqual(aggregate(['error', 'vulnerable']), 'vulnerable')
        self.assertEqual(aggregate(['needs_review', 'error']), 'error')
        self.assertEqual(aggregate(['needs_review', 'pass']), 'needs_review')
        self.assertEqual(aggregate([]), 'needs_review')

    def test_file_policy_validation(self):
        for key, value in [('expected_uid', True), ('expected_uid', -1),
                           ('allowed_permission_bits', '644'), ('allowed_permission_bits', '0888'),
                           ('reference_gid', '0'), ('path', '/tmp/unsupported')]:
            policy = copy.deepcopy(POLICY)
            policy['criteria']['files'][0][key] = value
            with self.assertRaises(PolicyError):
                validate_file_policy(policy)
        policy = copy.deepcopy(POLICY)
        policy['criteria']['files'][0]['unknown'] = True
        with self.assertRaises(PolicyError):
            validate_file_policy(policy)

    @patch('checks.system.file_check.environment_info', return_value={'id': 'fixture'})
    @patch('checks.system.file_check.collect_file_info', return_value=observation())
    def test_policy_load_through_result(self, collector, environment):
        collector.side_effect = lambda path: dict(observation(), path=path)
        result = run_from_policy(POLICY_PATH)
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(result['details']['policy_version'], 'file-01-v1.1-candidate-20261106')

    @patch('checks.system.file_check.os.lstat')
    @patch('checks.system.file_check._names', return_value=('fixture', 'fixture'))
    @patch('checks.system.file_check.subprocess.run', side_effect=FileNotFoundError('getfacl'))
    def test_acl_failure_does_not_erase_metadata(self, command, names, lstat):
        lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o664, st_uid=0,
                                            st_gid=0, st_dev=1, st_ino=2, st_ctime_ns=3)
        data = collect_file_info()
        self.assertEqual(data['mode'], '0664')
        result = diagnose(data)
        self.assertEqual(result['status'], 'vulnerable')
        self.assertIn('error', [c['status'] for c in result['details']['files'][0]['checks']])

    @patch('checks.system.link_check.os.path.realpath', side_effect=os.path.abspath)
    @patch('checks.system.file_check.os.readlink', return_value='/fixture/target')
    @patch('checks.system.file_check.os.lstat')
    @patch('checks.system.file_check._names', return_value=(None, None))
    @patch('checks.system.file_check.subprocess.run')
    def test_link_outside_scope_does_not_query_target(self, command, names, lstat, readlink, realpath):
        # Isolate native realpath: on Linux it calls os.lstat internally and must
        # not see this unit test's synthetic all-symlink filesystem.
        lstat.return_value = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
        data = collect_file_info()
        self.assertEqual(data['link_target'], '/fixture/target')
        command.assert_not_called()
        lstat.assert_called_once_with('/etc/passwd')
        self.assertEqual(data['link_inspection']['state'], 'needs_review')
        self.assertEqual(data['link_inspection']['reason'], 'target_outside_inspection_scope')

    @patch('sys.argv', ['file_check', '--policy', '/fixture/policy.json'])
    @patch('checks.system.file_check.run_from_policy', side_effect=PolicyError('fixture'))
    @patch('sys.stderr')
    def test_cli_policy_failure(self, stderr, loader):
        self.assertEqual(main(), 2)


if __name__ == '__main__':
    unittest.main()
