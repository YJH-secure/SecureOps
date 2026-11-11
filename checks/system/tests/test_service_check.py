import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from checks.system import service_check as svc


ACTIVE = 'example.service loaded active running Example service\n'
UNIT_FILES = 'example.service enabled enabled\nunused.service enabled disabled\n'
LISTENERS = 'tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("example",pid=100,fd=9))\n'
LOCAL_HTTP = {'protocol': 'tcp', 'address': '127.0.0.1', 'port': 8080}
SCOPE = {'target_id': 'rocky-mock', 'role': 'service-mock', 'network_context': 'vmware-nat'}


class ServiceCheckTests(unittest.TestCase):
    def setUp(self):
        self.read_os_release = svc.read_target_os
        os_reader = patch.object(svc, 'read_target_os', return_value={'id': 'rocky', 'version_id': '9.8'})
        self.os_reader = os_reader.start()
        self.addCleanup(os_reader.stop)
        self.outputs = {svc.ACTIVE_COMMAND: ACTIVE, svc.UNIT_FILES_COMMAND: UNIT_FILES,
                        svc.LISTENERS_COMMAND: LISTENERS}
        self.profile = {
            'os_id': 'rocky', 'os_version': '9.8', 'role': SCOPE['role'],
            'network_context': SCOPE['network_context'], 'approval_status': 'approved',
            'unit_rules': {'example.service': 'required'},
            'listener_rules': [{'protocol': 'tcp', 'port': 8080,
                                'allowed_addresses': ['127.0.0.1'], 'deny_unlisted_bindings': False}],
        }
        self.document = {'policy_version': 'mock', 'policies': [{
            'check_id': 'SVC-01', 'severity': 'medium', 'description': 'MOCK fixture',
            'criteria': {'profiles': [self.profile]},
        }]}

    def collect(self, command):
        output = self.outputs[command]
        if isinstance(output, Exception):
            raise output
        return output

    def diagnose(self, **overrides):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'policy.json'
            path.write_text(json.dumps(self.document), encoding='utf-8')
            return svc.run_from_policy(path, self.collect, **dict(SCOPE, **overrides))

    def test_default_policy_preserves_inventory_and_returns_review(self):
        result = svc.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(result['severity'], 'medium')
        self.assertEqual(set(result), {'check_id', 'status', 'severity', 'evidence', 'recommendation', 'details'})
        self.assertEqual(result['details']['observations']['listeners'],
                         [dict(LOCAL_HTTP, process_names=['example'])])
        self.assertEqual(result['details']['target']['os']['version_id'], '9.8')
        self.assertNotIn('pid=', json.dumps(result))

    def test_candidate_does_not_enforce_allowlists(self):
        self.profile.update(approval_status='candidate', unit_rules={'example.service': 'forbidden'})
        self.assertEqual(self.diagnose()['status'], 'needs_review')

    def test_approved_inventory_passes_with_inactive_enabled_unit(self):
        result = self.diagnose()
        self.assertEqual(result['status'], 'pass')
        self.assertIn({'unit': 'unused.service', 'state': 'enabled'},
                      result['details']['observations']['unit_files'])

    def test_unlisted_active_unit_is_inventory_only(self):
        self.outputs[svc.ACTIVE_COMMAND] += 'unexpected.service loaded active running Unexpected\n'
        result = self.diagnose()
        self.assertEqual(result['status'], 'pass')
        self.assertIn('unexpected.service', result['details']['observations']['active_units'])

    def test_explicitly_forbidden_unit_is_a_violation(self):
        self.profile['unit_rules'] = {'example.service': 'forbidden'}
        result = self.diagnose()
        self.assertEqual(result['status'], 'vulnerable')
        self.assertEqual(result['details']['violations'][0]['unit'], 'example.service')

    def test_unlisted_wildcard_requires_review_without_explicit_restriction(self):
        self.outputs[svc.LISTENERS_COMMAND] = LISTENERS.replace('127.0.0.1:8080', '0.0.0.0:8080')
        result = self.diagnose()
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(result['details']['review'][0]['address'], '0.0.0.0')
        self.assertEqual(result['details']['review'][0]['reason'], 'binding_not_approved')

    def test_approved_wildcard_still_requires_network_access_evidence(self):
        self.profile['listener_rules'][0]['allowed_addresses'] = ['::']
        self.outputs[svc.LISTENERS_COMMAND] = LISTENERS.replace('127.0.0.1:8080', '[::]:8080')
        result = self.diagnose()
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(result['details']['review'][0]['reason'], 'network_access_unverified')

    def test_explicit_binding_restriction_is_scoped_to_its_port(self):
        self.profile['listener_rules'][0]['deny_unlisted_bindings'] = True
        outside_port = LISTENERS.replace(':8080', ':8081')
        self.outputs[svc.LISTENERS_COMMAND] = LISTENERS.replace('127.0.0.1:8080', '0.0.0.0:8080') + outside_port
        result = self.diagnose()
        self.assertEqual(result['status'], 'vulnerable')
        self.assertEqual(result['details']['violations'][0]['reason'], 'binding_explicitly_forbidden')
        self.assertEqual(result['details']['review'][0]['port'], 8081)
        self.assertEqual(result['details']['review'][0]['reason'], 'listener_policy_missing')

    def test_role_network_context_and_os_mismatch_do_not_enforce_profile(self):
        self.profile['unit_rules'] = {'example.service': 'forbidden'}
        for values in ({'role': None}, {'role': 'another-role'}, {'network_context': 'gns3'}, {'target_id': None}):
            with self.subTest(values=values):
                result = self.diagnose(**values)
                self.assertEqual(result['status'], 'needs_review')
                self.assertEqual(result['details']['violations'], [])
        self.os_reader.return_value = {'id': 'ubuntu', 'version_id': '24.04'}
        self.assertEqual(self.diagnose()['status'], 'needs_review')

    def test_selects_only_matching_os_role_and_network_profile(self):
        self.profile['unit_rules'] = {'example.service': 'forbidden'}
        alternate = dict(self.profile, os_id='ubuntu', os_version='24.04', role='central',
                         network_context='gns3', unit_rules={'example.service': 'required'})
        self.document['policies'][0]['criteria']['profiles'].append(alternate)
        self.os_reader.return_value = {'id': 'ubuntu', 'version_id': '24.04'}
        self.assertEqual(self.diagnose(role='central', network_context='gns3')['status'], 'pass')

    def test_failed_os_lookup_preserves_observations_and_reports_error(self):
        self.os_reader.side_effect = FileNotFoundError('os-release')
        result = self.diagnose()
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['stage'], 'os')
        self.assertIn('listeners', result['details']['observations'])

    def test_udp_ipv6_scope_and_duplicate_tcp_rows(self):
        output = LISTENERS * 2 + 'udp UNCONN 0 0 [fe80:0::1%eth0]:5353 [::]:*\n'
        self.assertEqual(svc.parse_listeners(output),
                         {('tcp', '127.0.0.1', 8080): ['example'], ('udp', 'fe80::1%eth0', 5353): []})

    def test_malformed_socket_output_is_error_not_empty_inventory(self):
        self.outputs[svc.LISTENERS_COMMAND] = 'tcp LISTEN 0 128 127.0.0.1:http 0.0.0.0:*\n'
        result = self.diagnose()
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('listeners', result['details']['observations'])

    def test_timeout_wins_over_missing_policy(self):
        self.outputs[svc.ACTIVE_COMMAND] = subprocess.TimeoutExpired(svc.ACTIVE_COMMAND, 10)
        result = svc.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['stage'], 'active_units')

    def test_violation_and_independent_collection_error_are_preserved(self):
        self.profile['unit_rules'] = {'example.service': 'forbidden'}
        self.outputs[svc.LISTENERS_COMMAND] = FileNotFoundError('ss')
        result = self.diagnose()
        self.assertEqual(result['status'], 'vulnerable')
        self.assertEqual(result['details']['violations'][0]['unit'], 'example.service')
        self.assertEqual(result['details']['errors'][0]['stage'], 'listeners')

    def test_empty_successful_inventory_and_explicit_empty_approval(self):
        self.outputs = dict.fromkeys(self.outputs, '')
        self.profile.update(unit_rules={}, listener_rules=[])
        self.assertEqual(self.diagnose()['status'], 'pass')

    def test_invalid_policy_does_not_collect(self):
        self.profile['listener_rules'][0]['port'] = True
        self.outputs = {}
        result = self.diagnose()
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['stage'], 'policy')

    def test_os_release_reads_quoted_values_and_rejects_missing_version(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'os-release'
            path.write_text('ID="rocky"\nVERSION_ID="9.8"\n', encoding='utf-8')
            self.assertEqual(self.read_os_release(path), {'id': 'rocky', 'version_id': '9.8'})
            path.write_text('ID="rocky"\n', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'requires ID and VERSION_ID'):
                self.read_os_release(path)

    def test_stderr_marks_incomplete_collection(self):
        with patch.object(svc.subprocess, 'run', return_value=subprocess.CompletedProcess(
                svc.LISTENERS_COMMAND, 0, stdout=LISTENERS, stderr='Cannot open netlink socket')) as run:
            with self.assertRaisesRegex(ValueError, 'stderr'):
                svc._read_command(svc.LISTENERS_COMMAND)
        self.assertTrue(run.call_args[1]['check'])
        self.assertEqual(run.call_args[1]['timeout'], 10)


class ServiceCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, '-B', '-m', 'checks.system.service_check', *args],
            cwd=Path(__file__).resolve().parents[3], capture_output=True,
            encoding='utf-8', env=dict(os.environ, PYTHONIOENCODING='utf-8'), timeout=10,
        )

    def test_diagnostic_error_json_exits_successfully(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / 'missing-policy.json'
            completed = self.run_cli('--policy', str(missing))
        result = json.loads(completed.stdout)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stderr, '')
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['stage'], 'policy')

    def test_invalid_invocation_exits_nonzero_without_diagnostic_json(self):
        completed = self.run_cli('--unsupported-option')
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, '')
        self.assertIn('--unsupported-option', completed.stderr)


if __name__ == '__main__':
    unittest.main()
