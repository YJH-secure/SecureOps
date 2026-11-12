import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from checks.system import log_check as log


ACTIVE = 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'
JOURNAL = '# /etc/systemd/journald.conf\n[Journal]\nStorage=auto\nSystemMaxUse=200M\n'
USAGE = 'Archived and active journals take up 8.0M in the file system.\n'


class LogCheckTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.etc = Path(folder.name)
        os_reader = patch.object(log, 'read_target_os', return_value={'id': 'ubuntu', 'version_id': '24.04'})
        self.os_reader = os_reader.start()
        self.addCleanup(os_reader.stop)
        self.commands = {log.unit_command(unit): ACTIVE for unit in log.UNITS}
        self.commands.update({log.JOURNAL_CONFIG: JOURNAL, log.JOURNAL_USAGE: USAGE})
        self.path_reader = Mock(side_effect=lambda path: {'path': str(path), 'state': 'missing'})

    def collect(self, command):
        output = self.commands[command]
        if isinstance(output, Exception):
            raise output
        return output

    def run_check(self):
        return log.run_from_policy(command_runner=self.collect, config_root=self.etc,
                                   metadata_reader=self.path_reader)

    def write(self, path, content):
        file = self.etc / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding='utf-8')

    def test_ubuntu_logs_are_observed_by_metadata_without_a_verdict(self):
        result = self.run_check()
        details = result['details']
        observed = details['observations']
        self.assertEqual((result['check_id'], result['status'], result['severity']), ('LOG-01', 'needs_review', 'medium'))
        self.assertEqual(set(result), {'check_id', 'status', 'severity', 'evidence', 'recommendation', 'details'})
        self.assertEqual(observed['journal_disk_usage'], '8.0M')
        self.assertEqual(observed['journald_settings']['Storage'], 'auto')
        self.assertEqual(observed['path:/var/log/auth.log']['state'], 'missing')
        self.assertEqual([item[0][0] for item in self.path_reader.call_args_list],
                         [Path(path) for path in log.JOURNAL_PATHS + log.LOG_PATHS['ubuntu']])

    def test_rocky_selects_its_known_paths_and_preserves_missing_rsyslog(self):
        self.os_reader.return_value = {'id': 'rocky', 'version_id': '9.8'}
        self.commands[log.unit_command('rsyslog.service')] = 'LoadState=not-found\nActiveState=inactive\nUnitFileState=\n'
        result = self.run_check()
        observed = result['details']['observations']
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(observed['unit:rsyslog.service']['LoadState'], 'not-found')
        self.assertIn('path:/var/log/secure', observed)
        self.assertIn('path:/var/log/messages', observed)
        self.assertNotIn('path:/var/log/auth.log', observed)

    def test_dropin_value_overrides_main_and_blank_is_recorded(self):
        output = JOURNAL + ('# /etc/systemd/journald.conf.d/60-retention.conf\n'
                            '[Journal]\nStorage=persistent\nMaxRetentionSec=2 weeks\nSystemMaxUse=\n'
                            '[Unrelated]\nStorage=none\n')
        self.assertEqual(log.parse_journal_settings(output),
                         {'Storage': 'persistent', 'SystemMaxUse': None, 'MaxRetentionSec': '2 weeks'})

    def test_only_selected_config_hints_are_reported(self):
        self.write('rsyslog.conf', '# /var/log/syslog\nauthpriv.* /var/log/auth.log\n'
                   'action(type="omfwd" target="private.example")\n')
        self.write('rsyslog.d/50-example.conf', 'action(type="omfile" file="/var/log/syslog")\n')
        self.write('logrotate.d/rsyslog', '/var/log/auth.log\n{\n  weekly\n  rotate 4\n  compress\n'
                   '  postrotate\n    rotate 999\n    sensitive command\n  endscript\n}\n')
        result = self.run_check()
        observed = result['details']['observations']
        self.assertEqual(observed['rsyslog_config_hints'][0]['mentioned_log_paths'], ['/var/log/auth.log'])
        self.assertEqual(observed['rsyslog_config_hints'][1]['mentioned_log_paths'], ['/var/log/syslog'])
        self.assertEqual(observed['logrotate_config_hints'][0]['observed_directives'],
                         [{'name': 'weekly'}, {'name': 'rotate', 'value': '4'}, {'name': 'compress'}])
        self.assertNotIn('private.example', json.dumps(result))
        self.assertNotIn('sensitive command', json.dumps(result))

    def test_journal_permission_failure_retains_other_stages(self):
        self.commands[log.JOURNAL_USAGE] = subprocess.CalledProcessError(
            1, log.JOURNAL_USAGE, stderr='permission denied with private context')
        result = self.run_check()
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['stage'], 'journal_disk_usage')
        self.assertIn('journald_settings', result['details']['observations'])
        self.assertNotIn('private context', json.dumps(result))

    def test_malformed_unit_output_is_not_an_inactive_service(self):
        self.commands[log.unit_command('systemd-journald.service')] = 'UnitFileState=enabled'
        result = self.run_check()
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['stage'], 'unit:systemd-journald.service')

    def test_malformed_usage_is_error_not_zero_usage(self):
        self.commands[log.JOURNAL_USAGE] = 'unexpected empty database message'
        result = self.run_check()
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('journal_disk_usage', result['details']['observations'])

    def test_file_metadata_permission_error_is_distinct_from_missing(self):
        self.path_reader.side_effect = PermissionError('fixture')
        result = self.run_check()
        self.assertEqual(result['status'], 'error')
        self.assertTrue(all(error['kind'] == 'PermissionError' for error in result['details']['errors']))

    def test_metadata_does_not_follow_symlinks(self):
        candidate = Mock()
        candidate.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_gid=0)
        self.assertEqual(log.path_metadata(candidate)['type'], 'symlink')
        candidate.stat.assert_not_called()
        candidate.read_text.assert_not_called()

    def test_unknown_os_does_not_borrow_ubuntu_or_rocky_paths(self):
        self.os_reader.return_value = {'id': 'other', 'version_id': '1'}
        result = self.run_check()
        self.assertEqual(result['status'], 'needs_review')
        self.assertIn('os_log_paths_unconfirmed', result['details']['review'])
        self.assertEqual(self.path_reader.call_count, 2)

    def test_config_read_failure_preserves_successful_fragments(self):
        self.write('rsyslog.conf', 'authpriv.* /var/log/auth.log\n')
        broken = self.etc / 'rsyslog.d/broken.conf'
        broken.parent.mkdir()
        broken.write_bytes(b'\xff')
        result = self.run_check()
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['config'], 'rsyslog.d/broken.conf')
        self.assertEqual(result['details']['observations']['rsyslog_config_hints'][0]['mentioned_log_paths'],
                         ['/var/log/auth.log'])

    def test_cli_emits_diagnostic_error_json_with_exit_zero(self):
        missing = self.etc / 'missing-policy.json'
        with patch.object(log.sys, 'argv', ['log_check', '--policy', str(missing)]), \
                patch('builtins.print') as output:
            self.assertEqual(log.main(), 0)
        self.assertEqual(json.loads(output.call_args[0][0])['status'], 'error')


if __name__ == '__main__':
    unittest.main()
