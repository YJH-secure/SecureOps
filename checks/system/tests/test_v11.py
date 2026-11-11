"""(MOCK) v1.1 candidate policies: no real file permission changes or SSH."""
import copy
import json
import posixpath
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from checks.system.common import PolicyError, load_policy
from checks.system.file_check import (DEFAULT_POLICY, run, run_from_policy, evaluate_file,
                                      validate_file_policy)
from checks.system.link_check import inspect_link
from checks.system.tests.fixtures import singlefile_policy
from checks.system.tests.test_diagnosis import observation


def profile(name):
    return copy.deepcopy(load_policy(DEFAULT_POLICY.parent / name)['policies'][0])


def shadow_only(name='file_policy.ubuntu-24.04.json'):
    policy = profile(name)
    policy['criteria']['files'] = policy['criteria']['files'][1:]
    return policy


def execute(policy, data, environment=None):
    return run(policy, collector=lambda path: dict(copy.deepcopy(data), path=path),
               environment=environment or {'id': 'ubuntu', 'version_id': '24.04',
                                             'named_groups': {'shadow': 777}})


class ApprovalAndOSTests(unittest.TestCase):
    def test_candidate_compliant_not_pass(self):
        result = execute(shadow_only(), observation('0640', gid=777))
        self.assertEqual(result['status'], 'needs_review')
        checks = result['details']['files'][0]['checks']
        self.assertEqual(next(c for c in checks if c['name'] == 'group')['candidate_comparison'], 'pass')

    def test_candidate_mismatch_not_confirmed_vulnerability(self):
        result = execute(shadow_only(), observation('0666', uid=123, gid=888))
        self.assertEqual(result['status'], 'needs_review')
        checks = result['details']['files'][0]['checks']
        self.assertIn('vulnerable', [c.get('candidate_comparison') for c in checks])

    def test_candidate_collection_error_not_hidden(self):
        result = run(shadow_only(), collector=Mock(side_effect=PermissionError('fixture')),
                     environment={'id': 'ubuntu'})
        self.assertEqual(result['status'], 'error')

    def test_dynamic_shadow_group_identity(self):
        policy = shadow_only()
        policy['criteria']['files'][0]['approval_status'] = 'approved'  # MOCK ONLY
        self.assertEqual(execute(policy, observation('0640', gid=777))['status'], 'pass')
        self.assertEqual(execute(policy, observation('0640', gid=42))['status'], 'vulnerable')

    def test_unresolved_name_is_review_not_false_violation(self):
        policy = shadow_only()
        policy['criteria']['files'][0]['approval_status'] = 'approved'
        result = execute(policy, observation('0640', gid=777), {'id': 'ubuntu', 'named_groups': {}})
        self.assertEqual(result['status'], 'needs_review')

    def test_root_gid_does_not_require_shadow_lookup(self):
        policy = shadow_only()
        policy['criteria']['files'][0]['approval_status'] = 'approved'
        self.assertEqual(execute(policy, observation('0640', gid=0), {'id': 'ubuntu'})['status'], 'pass')

    def test_rocky_zero_mode_is_candidate(self):
        policy = shadow_only('file_policy.rocky-9.8.json')
        self.assertEqual(execute(policy, observation('0000'))['status'], 'needs_review')
        result = execute(policy, observation('0600'))
        check = next(c for c in result['details']['files'][0]['checks'] if c['name'] == 'permissions')
        self.assertEqual(check['candidate_comparison'], 'vulnerable')
        self.assertEqual(result['status'], 'needs_review')

    def test_passwd_group_held_even_gid_zero(self):
        policy = profile('file_policy.ubuntu-24.04.json')
        policy['criteria']['files'] = policy['criteria']['files'][:1]
        result = execute(policy, observation())
        self.assertEqual(result['status'], 'needs_review')

    @patch('checks.system.file_check.environment_info')
    @patch('checks.system.file_check.collect_file_info')
    def test_auto_selection_ubuntu_and_rocky(self, collector, environment):
        collector.side_effect = lambda path: dict(observation('0640'), path=path)
        for os_id, version, expected in [('ubuntu','24.04','0640'), ('rocky','9.8','0000')]:
            environment.return_value = {'id': os_id, 'version_id': version, 'named_groups': {'shadow': 777}}
            result = run_from_policy()
            self.assertEqual(result['details']['files'][1]['expected']['allowed_permission_bits'], expected)
            self.assertEqual(result['status'], 'needs_review')

    @patch('checks.system.file_check.environment_info', return_value={'id': 'unknown', 'version_id': '1'})
    @patch('checks.system.file_check.collect_file_info')
    def test_unknown_os_fallback_never_selects_candidate(self, collector, env):
        collector.side_effect = lambda path: dict(observation(), path=path)
        result = run_from_policy()
        self.assertIsNone(result['details']['files'][1]['expected']['expected_uid'])
        self.assertEqual(result['status'], 'needs_review')

    @patch('checks.system.file_check.environment_info', return_value={'id': 'rocky', 'version_id': '9.8'})
    def test_wrong_explicit_os_policy_is_error(self, env):
        with self.assertRaises(PolicyError):
            run_from_policy(DEFAULT_POLICY.parent / 'file_policy.ubuntu-24.04.json')

    def test_new_schema_rejects_implicit_acl_approval(self):
        policy = profile('file_policy.ubuntu-24.04.json')
        policy['criteria']['files'][0]['acl_policy']['approval_status'] = 'approved'
        with self.assertRaises(PolicyError):
            validate_file_policy(policy)


class ACLAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.policy = singlefile_policy()
        self.policy['criteria']['files'][0]['acl_policy'] = dict(
            approval_status='approved', users=[dict(id=0,max_bits=6)],
            groups=[dict(id=0,max_bits=4)], other_max_bits=4)

    def named_data(self, perms, mask='r--'):
        data = observation()
        data['acl']['raw'] += 'user:777:' + perms + '\nmask::' + mask + '\n'
        return data

    def test_unauthorized_effective_read_is_vulnerable(self):
        result = execute(self.policy, self.named_data('r--'))
        self.assertEqual(result['status'], 'vulnerable')

    def test_masked_out_permission_is_not_violation(self):
        self.assertEqual(execute(self.policy, self.named_data('-w-'))['status'], 'pass')

    def test_explicitly_approved_named_user_can_pass(self):
        self.policy['criteria']['files'][0]['acl_policy']['users'].append(dict(id=777,max_bits=4))
        self.assertEqual(execute(self.policy, self.named_data('rwx'))['status'], 'pass')

    def test_pending_principal_list_stays_review(self):
        self.policy['criteria']['files'][0]['acl_policy']['approval_status'] = 'candidate'
        self.assertEqual(execute(self.policy, self.named_data('r--'))['status'], 'needs_review')

    def test_unapproved_named_group_effective_read(self):
        data = observation()
        data['acl']['raw'] += 'group:777:r--\nmask::r--\n'
        self.assertEqual(execute(self.policy, data)['status'], 'vulnerable')

    def test_owner_entry_takes_priority_over_named_entry_for_owner(self):
        self.policy['criteria']['files'][0]['acl_policy']['users'] = [dict(id=0,max_bits=6)]
        data = self.named_data('rwx')
        data['acl']['raw'] = data['acl']['raw'].replace('user:777:', 'user:0:')
        self.assertEqual(execute(self.policy, data)['status'], 'pass')


class LinkTests(unittest.TestCase):
    def inspect(self, mapping, fail=None, path='/etc/passwd', root='/etc'):
        fakepath = SimpleNamespace(abspath=posixpath.abspath, realpath=posixpath.normpath,
                                   commonpath=posixpath.commonpath, normpath=posixpath.normpath,
                                   isabs=posixpath.isabs, join=posixpath.join,
                                   dirname=posixpath.dirname, basename=posixpath.basename)
        def lstat(path):
            if fail:
                raise fail
            return SimpleNamespace(st_mode=stat.S_IFLNK if path in mapping else stat.S_IFREG)
        fakeos = SimpleNamespace(path=fakepath, lstat=Mock(side_effect=lstat),
                                 readlink=Mock(side_effect=lambda path: mapping[path]))
        collector = Mock(side_effect=lambda path: dict(observation(), path=path))
        with patch('checks.system.link_check.os', fakeos):
            result = inspect_link(path, SimpleNamespace(st_mode=stat.S_IFLNK), collector,
                                  inspection_root=root)
        return result, fakeos, collector

    def test_isolated_fixture_root_is_injected_explicitly(self):
        root = '/tmp/fixture-root'
        result, _, collector = self.inspect({root+'/link':'target'},
                                            path=root+'/link', root=root)
        self.assertEqual(result['target_path'], root+'/target')
        collector.assert_called_once_with(root+'/target')

    def test_default_etc_scope_does_not_expand_to_fixture_root(self):
        result, _, collector = self.inspect({'/etc/passwd':'/tmp/fixture-root/target'})
        self.assertEqual(result['reason'], 'target_outside_inspection_scope')
        collector.assert_not_called()

    def test_relative_link_target_metadata(self):
        result, osmock, collector = self.inspect({'/etc/passwd':'real-passwd'})
        self.assertEqual(result['state'], 'collected')
        self.assertEqual(result['target_path'], '/etc/real-passwd')
        collector.assert_called_once_with('/etc/real-passwd')

    def test_cycle(self):
        result, _, collector = self.inspect({'/etc/passwd':'next', '/etc/next':'passwd'})
        self.assertEqual(result['reason'], 'symlink_cycle')
        collector.assert_not_called()

    def test_broken_link(self):
        result, _, collector = self.inspect({'/etc/passwd':'missing'}, FileNotFoundError('fixture'))
        self.assertEqual(result['state'], 'error')
        self.assertTrue(result['chain'])

    def test_scope_escape_stops_before_target_lookup(self):
        result, osmock, collector = self.inspect({'/etc/passwd':'/tmp/other'})
        self.assertEqual(result['state'], 'needs_review')
        osmock.lstat.assert_not_called()
        collector.assert_not_called()

    def test_depth_limit(self):
        mapping = {'/etc/passwd':'n0'}
        mapping.update({'/etc/n'+str(i): 'n'+str(i+1) for i in range(10)})
        result, _, collector = self.inspect(mapping)
        self.assertEqual(result['reason'], 'symlink_hop_limit')

    def test_target_inspection_does_not_approve_link(self):
        result, _, _ = self.inspect({'/etc/passwd':'real'})
        data = dict(path='/etc/passwd',file_type='symlink',link_inspection=result)
        policy = singlefile_policy()
        self.assertEqual(execute(policy, data)['status'], 'needs_review')

    def test_approved_link_evaluates_target(self):
        result, _, _ = self.inspect({'/etc/passwd':'real'})
        data = dict(path='/etc/passwd',file_type='symlink',link_inspection=result)
        policy = singlefile_policy()
        policy['criteria']['files'][0]['link_policy'] = dict(approval_status='approved',allowed_targets=['/etc/real'])
        actual = execute(policy, data)
        self.assertEqual(actual['status'], 'pass')
        self.assertIn('target_result', actual['details']['files'][0])

    def test_approved_link_target_violation_preserved(self):
        result, _, _ = self.inspect({'/etc/passwd':'real'})
        result['target_observation']['uid'] = 777
        data = dict(path='/etc/passwd',file_type='symlink',link_inspection=result)
        policy = singlefile_policy()
        policy['criteria']['files'][0]['link_policy'] = dict(approval_status='approved',allowed_targets=['/etc/real'])
        self.assertEqual(execute(policy, data)['status'], 'vulnerable')


if __name__ == '__main__':
    unittest.main()
