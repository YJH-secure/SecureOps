"""Multi-file tests use synthetic metadata; no shadow content or SSH access."""
import copy
import json
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from checks.system.common import load_policy
from checks.system.file_check import DEFAULT_POLICY, collect_file_info, run
from checks.system.tests.test_diagnosis import observation
from checks.system.tests.fixtures import multifile_policy


class MultifileTests(unittest.TestCase):
    def setUp(self):
        self.policy = multifile_policy()

    def execute(self, collector):
        return run(self.policy, collector=collector, environment={'id': 'fixture'})

    def test_shadow_pending_cannot_make_whole_result_pass(self):
        result = self.execute(lambda path: dict(observation(), path=path))
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual([f['status'] for f in result['details']['files']], ['pass', 'needs_review'])

    def test_shadow_failure_retains_passwd_result(self):
        def collector(path):
            if path == '/etc/shadow':
                raise PermissionError('fixture metadata denied')
            return observation()
        result = self.execute(collector)
        self.assertEqual(result['status'], 'error')
        self.assertEqual([f['status'] for f in result['details']['files']], ['pass', 'error'])

    def test_passwd_vulnerable_shadow_error_details_retained(self):
        def collector(path):
            if path == '/etc/shadow':
                raise FileNotFoundError('fixture missing shadow')
            return observation('0664')
        result = self.execute(collector)
        self.assertEqual(result['status'], 'vulnerable')
        self.assertEqual([f['status'] for f in result['details']['files']], ['vulnerable', 'error'])

    def test_error_does_not_stop_later_file(self):
        collector = Mock(side_effect=[PermissionError('fixture'), dict(observation(), path='/etc/shadow')])
        result = self.execute(collector)
        self.assertEqual(collector.call_count, 2)
        self.assertEqual(len(result['details']['files']), 2)

    def test_future_approved_values_are_applied_not_hardcoded(self):
        # TEST ONLY. These values are not the distributed shadow approval criteria.
        self.policy['criteria']['files'][1].update(expected_uid=123, reference_gid=456,
                                                  allowed_permission_bits='0600', approval_status='approved')
        def collector(path):
            return (observation() if path == '/etc/passwd' else
                    dict(observation('0600', uid=123, gid=456), path=path))
        self.assertEqual(self.execute(collector)['status'], 'pass')

    @patch('checks.system.file_check.os.lstat')
    @patch('checks.system.file_check._names', return_value=('fixture', 'fixture'))
    @patch('checks.system.file_check.subprocess.run')
    def test_shadow_collection_only_metadata_and_getfacl(self, command, names, lstat):
        lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                                            st_gid=0, st_dev=1, st_ino=2, st_ctime_ns=3)
        command.return_value = SimpleNamespace(stdout='user::rw-\ngroup::---\nother::---\n')
        data = collect_file_info('/etc/shadow')
        self.assertEqual(data['path'], '/etc/shadow')
        self.assertEqual(command.call_args[0][0][-1], '/etc/shadow')
        self.assertNotIn('content', data)

    def test_extended_acl_mask_is_applied_not_effective_comment(self):
        data = observation()
        data['acl']['raw'] = ('user::rw-\nuser:42:rwx #effective:rwx\n'
                              'group::rwx\nmask::r--\nother::r--\n')
        result = self.execute(lambda path: dict(copy.deepcopy(data), path=path))
        acl = next(c for c in result['details']['files'][0]['checks'] if c['name'] == 'acl')
        self.assertEqual(acl['status'], 'needs_review')
        named = next(e for e in acl['actual']['effective_entries'] if e['qualifier'] == '42')
        self.assertEqual(named['declared_bits'], 7)
        self.assertEqual(named['effective_bits'], 4)

    def test_extended_acl_mode_mask_inconsistency_is_error(self):
        data = observation()
        data['acl']['raw'] += 'user:42:r--\nmask::rw-\n'
        result = self.execute(lambda path: dict(copy.deepcopy(data), path=path))
        self.assertEqual(result['status'], 'error')

    def test_policy_contains_no_invented_shadow_values(self):
        shadow = self.policy['criteria']['files'][1]
        for key in ('expected_uid', 'allowed_permission_bits', 'reference_gid'):
            self.assertIsNone(shadow[key])


if __name__ == '__main__':
    unittest.main()
