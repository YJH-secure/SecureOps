"""MOCK: distinguish absent optional groups from failed required lookups."""
import unittest
from unittest.mock import Mock, patch

from checks.system.file_check import environment_info
from checks.system.policy_rules import group_check


class GroupLookupStateTests(unittest.TestCase):
    def lookup(self, **kwargs):
        with patch.dict('sys.modules', {'grp': Mock(**kwargs)}):
            return environment_info()

    def test_missing_group_is_absent_not_lookup_error(self):
        info = self.lookup(**{'getgrnam.side_effect': KeyError('shadow')})
        self.assertEqual(info['group_lookup_state'], 'absent')
        self.assertNotIn('group_lookup_error', info)

    def test_lookup_io_failure_is_error(self):
        info = self.lookup(**{'getgrnam.side_effect': OSError('(MOCK) NSS failed')})
        self.assertEqual(info['group_lookup_state'], 'error')
        self.assertIn('NSS failed', info['group_lookup_error'])

    def test_success_records_target_numeric_gid(self):
        info = self.lookup(**{'getgrnam.return_value': Mock(gr_gid=777)})
        self.assertEqual(info['group_lookup_state'], 'collected')
        self.assertEqual(info['named_groups'], {'shadow': 777})

    def test_required_name_lookup_failure_is_error(self):
        criteria = {'allowed_groups': [{'kind': 'name', 'value': 'shadow'}]}
        state, expected, _ = group_check(criteria, {'gid': 777},
            {'named_groups': {}, 'group_lookup_state': 'error', 'group_lookup_error': '(MOCK) NSS failed'})
        self.assertEqual(state, 'error')
        self.assertIn('lookup_error', expected)

    def test_absent_group_is_review_not_false_violation(self):
        criteria = {'allowed_groups': [{'kind': 'name', 'value': 'shadow'}]}
        self.assertEqual(group_check(criteria, {'gid': 777},
            {'named_groups': {}, 'group_lookup_state': 'absent'})[0], 'needs_review')

    def test_rocky_numeric_root_policy_does_not_require_shadow_group(self):
        criteria = {'allowed_groups': [{'kind': 'gid', 'value': 0}]}
        self.assertEqual(group_check(criteria, {'gid': 0},
            {'named_groups': {}, 'group_lookup_state': 'absent'})[0], 'pass')

    def test_satisfied_alternative_does_not_require_unused_name(self):
        criteria = {'allowed_groups': [{'kind': 'gid', 'value': 0}, {'kind': 'name', 'value': 'shadow'}]}
        self.assertEqual(group_check(criteria, {'gid': 0},
            {'named_groups': {}, 'group_lookup_state': 'error'})[0], 'pass')


if __name__ == '__main__':
    unittest.main()
