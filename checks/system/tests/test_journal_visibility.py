"""Approved journal notice classification: failure semantics and privacy stay intact."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from checks.system import firewall_check as fw, log_check as log, service_check as svc
from checks.system.result_adapter import adapt_result

USAGE = 'Archived and active journals take up 38.3M in the file system.\n'
NOTICE = ("Hint: You are currently not seeing messages from other users and the system.\n"
          "      Users in groups 'adm', 'systemd-journal' can see all messages.\n"
          "      Pass -q to turn off this notice.\n")
ACTIVE = 'LoadState=loaded\nActiveState=active\nUnitFileState=enabled\n'


class JournalVisibilityTests(unittest.TestCase):
    def reader_error(self, command=log.JOURNAL_USAGE, stdout=USAGE, stderr=NOTICE):
        with patch.object(svc.subprocess, 'run', return_value=subprocess.CompletedProcess(
                command, 0, stdout, stderr)) as execute:
            with self.assertRaisesRegex(ValueError, '^command reported a diagnostic on stderr$') as caught:
                svc._read_command(command)
        self.assertIs(type(caught.exception), ValueError)
        self.assertEqual(execute.call_args.kwargs['env']['LC_ALL'], 'C')
        self.assertEqual(execute.call_args.kwargs['env']['SYSTEMD_COLORS'], '0')
        self.assertTrue(execute.call_args.kwargs['check'])
        self.assertEqual(execute.call_args.kwargs['timeout'], 10)
        return caught.exception

    def run_log(self, usage=USAGE):
        outputs = {log.unit_command(unit): ACTIVE for unit in log.UNITS}
        outputs.update({log.JOURNAL_CONFIG: '[Journal]\nStorage=auto\n', log.JOURNAL_USAGE: usage})
        def runner(command):
            value = outputs[command]
            if isinstance(value, BaseException):
                raise value
            return value
        with tempfile.TemporaryDirectory() as folder, patch.object(
                log, 'read_target_os', return_value={'id': 'ubuntu', 'version_id': '24.04'}):
            return log.run_from_policy(command_runner=runner, config_root=Path(folder),
                metadata_reader=lambda path: {'path': str(path), 'state': 'missing'})

    def test_observed_notice_preserves_exception_and_adds_safe_metadata(self):
        error = self.reader_error()
        self.assertEqual(vars(error), {'collection_reason': 'journal_visibility_limited',
                                     'command_exit_code': 0, 'visibility': 'partial'})

    def test_normal_output_without_stderr_returns_original_text(self):
        with patch.object(svc.subprocess, 'run', return_value=subprocess.CompletedProcess(
                log.JOURNAL_USAGE, 0, USAGE, '')):
            self.assertEqual(svc._read_command(log.JOURNAL_USAGE), USAGE)

    def test_ss_systemctl_and_firewall_commands_are_not_classified(self):
        for command in (svc.LISTENERS_COMMAND, svc.ACTIVE_COMMAND, fw.NFT_RULESET, fw.UFW_STATUS, fw.FIREWALLD_STATE):
            with self.subTest(command=command):
                self.assertEqual(vars(self.reader_error(command)), {})

    def test_extra_arguments_and_absolute_path_are_not_assumed_approved(self):
        for command in (log.JOURNAL_USAGE + ('-q',), ('/usr/bin/journalctl',) + log.JOURNAL_USAGE[1:]):
            with self.subTest(command=command):
                self.assertEqual(vars(self.reader_error(command)), {})

    def test_mixed_warning_is_not_classified(self):
        self.assertEqual(vars(self.reader_error(stderr=NOTICE + 'Permission denied for private-user\n')), {})

    def test_unknown_localized_and_truncated_notices_are_not_classified(self):
        for notice in ('권한 안내', 'Permission denied', NOTICE.splitlines()[0], NOTICE.replace('adm', 'other')):
            with self.subTest(notice=notice):
                self.assertEqual(vars(self.reader_error(stderr=notice)), {})

    def test_length_bound_rejects_oversized_notice(self):
        self.assertEqual(vars(self.reader_error(stderr=' ' * 513 + NOTICE)), {})

    def test_whitespace_only_stderr_keeps_existing_success(self):
        with patch.object(svc.subprocess, 'run', return_value=subprocess.CompletedProcess(
                log.JOURNAL_USAGE, 0, USAGE, ' \n')):
            self.assertEqual(svc._read_command(log.JOURNAL_USAGE), USAGE)

    def test_real_exit_failure_keeps_original_exception(self):
        failure = subprocess.CalledProcessError(1, log.JOURNAL_USAGE, output='0', stderr=NOTICE)
        with patch.object(svc.subprocess, 'run', side_effect=failure):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                svc._read_command(log.JOURNAL_USAGE)
        self.assertIs(caught.exception, failure)
        result = self.run_log(failure)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'], [
            {'stage': 'journal_disk_usage', 'kind': 'CalledProcessError', 'exit_code': 1}])

    def test_permission_failure_does_not_create_exit_code(self):
        result = self.run_log(PermissionError('sensitive-user'))
        self.assertEqual(result['details']['errors'], [
            {'stage': 'journal_disk_usage', 'kind': 'PermissionError'}])
        self.assertEqual(result['status'], 'error')

    def test_timeout_is_still_an_error(self):
        result = self.run_log(subprocess.TimeoutExpired(log.JOURNAL_USAGE, 10, stderr=NOTICE))
        self.assertEqual(result['details']['errors'], [
            {'stage': 'journal_disk_usage', 'kind': 'TimeoutExpired'}])

    def test_normal_log_output_remains_review_not_pass(self):
        result = self.run_log()
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(result['details']['observations']['journal_disk_usage'], '38.3M')

    def test_malformed_output_is_not_visibility_or_zero_usage(self):
        for output in ('', '0', 'unexpected'):
            with self.subTest(output=output):
                result = self.run_log(output)
                self.assertEqual(result['status'], 'error')
                self.assertEqual(result['details']['errors'], [
                    {'stage': 'journal_disk_usage', 'kind': 'ValueError'}])
                self.assertNotIn('journal_disk_usage', result['details']['observations'])

    def test_known_notice_does_not_claim_malformed_stdout_was_parsed(self):
        result = self.run_log(self.reader_error(stdout='invalid private-data'))
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('journal_disk_usage', result['details']['observations'])

    def test_only_journal_stage_copies_validated_metadata(self):
        error = self.reader_error()
        for stage in ('unit:rsyslog.service', 'journald_settings'):
            details = {'observations': {}, 'errors': []}
            def fail():
                raise error
            log._observe(details, stage, fail)
            self.assertEqual(details['errors'], [{'stage': stage, 'kind': 'ValueError'}])

    def test_unannotated_runner_error_is_not_guessed(self):
        result = self.run_log(ValueError('command reported a diagnostic on stderr'))
        self.assertEqual(result['details']['errors'], [{'stage': 'journal_disk_usage', 'kind': 'ValueError'}])

    def test_invalid_metadata_is_not_exported(self):
        for exit_code in (True, '0', None, 1):
            with self.subTest(exit_code=exit_code):
                error = self.reader_error()
                error.command_exit_code = exit_code
                self.assertEqual(self.run_log(error)['details']['errors'], [
                    {'stage': 'journal_disk_usage', 'kind': 'ValueError'}])

    def test_existing_results_preserved_except_selected_error_fields(self):
        before = self.run_log(ValueError('command reported a diagnostic on stderr'))
        after = self.run_log(self.reader_error())
        expected = deepcopy(before)
        expected['details']['errors'][0].update(reason='journal_visibility_limited', command_exit_code=0, visibility='partial')
        self.assertEqual(after, expected)
        self.assertEqual(after['status'], 'error')
        self.assertIn('journald_settings', after['details']['observations'])
        self.assertNotIn('journal_disk_usage', after['details']['observations'])
        for version in ('1.1', '1.2'):
            exported = adapt_result(after, version)
            self.assertEqual(exported['status'], 'error')
            self.assertEqual(exported['details'], after['details'])
            self.assertEqual(exported['evidence'], before['evidence'])
            self.assertEqual(exported['recommendation'], before['recommendation'])

    def test_raw_output_never_attached_to_exception_or_result(self):
        error = self.reader_error(stdout='secret-user 192.0.2.99 raw journal text')
        rendered = json.dumps(self.run_log(error), ensure_ascii=False) + repr(vars(error))
        for forbidden in ('secret-user', '192.0.2.99', 'raw journal text', NOTICE, USAGE):
            self.assertNotIn(forbidden, rendered)

    def test_default_log_runner_integration_still_raises_and_classifies(self):
        def execute(command, **kwargs):
            if command == log.JOURNAL_USAGE:
                return subprocess.CompletedProcess(command, 0, USAGE, NOTICE)
            output = '[Journal]\nStorage=auto\n' if command == log.JOURNAL_CONFIG else ACTIVE
            return subprocess.CompletedProcess(command, 0, output, '')
        with tempfile.TemporaryDirectory() as folder, patch.object(svc.subprocess, 'run', side_effect=execute), \
                patch.object(log, 'read_target_os', return_value={'id': 'ubuntu', 'version_id': '24.04'}):
            result = log.run_from_policy(config_root=Path(folder),
                metadata_reader=lambda path: {'path': str(path), 'state': 'missing'})
        self.assertEqual(result['details']['errors'], [{'stage': 'journal_disk_usage', 'kind': 'ValueError',
            'reason': 'journal_visibility_limited', 'command_exit_code': 0, 'visibility': 'partial'}])
        self.assertEqual(result['status'], 'error')
