import copy
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, Mock

from checks.system.common import (PolicyError, STATUSES, SEVERITIES, load_policy,
                                  validate_document, make_result)
from checks.system.file_check import collect_file_info, parse_acl, run

# Synthetic observations only; policy criteria are loaded from the delivered policy.
from checks.system.tests.fixtures import singlefile_policy
POLICY = singlefile_policy()
ACL = 'user::rw-\nuser:1234:r--\ngroup::r--\nmask::r--\nother::r--\n'


def document():
    return dict(policy_version='test-only', policies=[copy.deepcopy(POLICY)])


def metadata(mode=stat.S_IFREG | 0o640):
    return SimpleNamespace(st_mode=mode, st_uid=1234, st_gid=5678,
                           st_dev=1, st_ino=2, st_ctime_ns=3)


class CommonTests(unittest.TestCase):
    def test_policy_load_and_io_failures(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            with self.assertRaises(PolicyError):
                load_policy(path)
            for text in ('{', '{"policy_version":"a","policy_version":"b","policies":[]}',
                         '\ufeff{}'):
                path.write_text(text, encoding='utf-8')
                with self.assertRaises(PolicyError):
                    load_policy(path)
            path.write_text(json.dumps(document()), encoding='utf-8')
            self.assertEqual(load_policy(path), document())

    def test_required_fields_and_types(self):
        for key in ('check_id', 'description', 'severity', 'criteria'):
            data = document()
            del data['policies'][0][key]
            with self.assertRaises(PolicyError):
                validate_document(data)
        for key, value in [('policy_version', 1), ('policy_version', ''), ('policies', {})]:
            data = document()
            data[key] = value
            with self.assertRaises(PolicyError):
                validate_document(data)
        for key, value in [('check_id', 1), ('description', []), ('severity', 'HIGH'),
                           ('severity', []), ('criteria', []), ('criteria', None)]:
            data = document()
            data['policies'][0][key] = value
            with self.assertRaises(PolicyError):
                validate_document(data)
        data = document()
        data['policies'].append(copy.deepcopy(POLICY))
        with self.assertRaises(PolicyError):
            validate_document(data)

    def test_all_result_enums_and_exact_keys(self):
        for status in STATUSES:
            for severity in SEVERITIES:
                result = make_result('FILE-01', status, severity, '(MOCK) evidence', '(MOCK) follow-up', {})
                self.assertEqual(set(result), {'check_id', 'status', 'severity', 'evidence', 'recommendation', 'details'})
                self.assertEqual(json.loads(json.dumps(result)), result)
        for status, severity in [('ok', 'high'), ('pass', 'HIGH'), ([], 'high')]:
            with self.assertRaises(ValueError):
                make_result('FILE-01', status, severity, '(MOCK) evidence', '(MOCK) follow-up')

    def test_unimplemented_policies_are_empty(self):
        folder = Path(__file__).parents[1] / 'policies'
        for path in folder.glob('*.json'):
            if path.name in ('service_policy.json', 'firewall_policy.json', 'log_policy.json'):
                self.assertEqual(load_policy(path)['policies'], [])


class FileTests(unittest.TestCase):
    def test_acl_parser(self):
        self.assertEqual(len(parse_acl('# file: fixture\n' + ACL)), 5)
        extended = ACL.replace('user:1234:r--', 'user:1234:rwx\t#effective:r--')
        self.assertIn('user:1234:rwx\t#effective:r--', parse_acl(extended))
        for value in ('', 'nonsense', 'user::abc', 'other:named:rwx',
                      'user::rw-\nother::r--', ACL + 'other::r--'):
            with self.assertRaises(ValueError):
                parse_acl(value)

    @patch('checks.system.file_check.subprocess.run')
    @patch('checks.system.file_check._names', return_value=('fixture-user', 'fixture-group'))
    @patch('checks.system.file_check.os.lstat', return_value=metadata())
    def test_read_only_collection(self, lstat, names, command):
        command.return_value = SimpleNamespace(stdout=ACL)
        result = collect_file_info()
        self.assertEqual(result['mode'], '0640')
        self.assertEqual(result['uid'], 1234)
        self.assertEqual(result['owner'], 'fixture-user')
        self.assertEqual(result['file_type'], 'regular')
        self.assertEqual(result['acl']['state'], 'collected')
        self.assertEqual(command.call_args[0][0],
                         ['getfacl', '-n', '-p', '-P', '--', '/etc/passwd'])
        self.assertEqual(lstat.call_count, 2)

    @patch('checks.system.file_check.subprocess.run')
    @patch('checks.system.file_check._names', return_value=(None, None))
    @patch('checks.system.file_check.os.lstat', return_value=metadata(stat.S_IFLNK | 0o777))
    def test_symlink_not_followed(self, lstat, names, command):
        with patch('checks.system.file_check.os.readlink', return_value='/fixture/target'):
            result = collect_file_info()
        self.assertEqual(result['file_type'], 'symlink')
        self.assertEqual(result['acl']['state'], 'not_collected')
        command.assert_not_called()

    @patch('checks.system.file_check.subprocess.run', return_value=SimpleNamespace(stdout=ACL))
    @patch('checks.system.file_check._names', return_value=(None, None))
    @patch('checks.system.file_check.os.lstat')
    def test_changed_file_rejected(self, lstat, names, command):
        changed = metadata()
        changed.st_ino = 99
        lstat.side_effect = [metadata(), changed]
        self.assertIn('snapshot_error', collect_file_info())

    def test_pending_policy_never_security_verdict(self):
        for criteria in ({}, {'forbidden_permission_bits': 'fixture-unapproved'}):
            policy = dict(POLICY, criteria=criteria)
            collector = Mock()
            with self.assertRaises(PolicyError):
                run(policy, collector=collector)
            collector.assert_not_called()

    def test_collection_failures(self):
        for error in (FileNotFoundError('fixture'), PermissionError('fixture'),
                      ValueError('invalid ACL'), subprocess.TimeoutExpired('getfacl', 5),
                      subprocess.CalledProcessError(1, 'getfacl')):
            self.assertEqual(run(POLICY, collector=Mock(side_effect=error))['status'], 'error')

    def test_invalid_policy_does_not_collect(self):
        collector = Mock()
        with self.assertRaises(PolicyError):
            run(dict(POLICY, check_id='OTHER'), collector)
        collector.assert_not_called()
        with self.assertRaises(ValueError):
            collect_file_info('/tmp/other')


if __name__ == '__main__':
    unittest.main()
