import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from checks.system import firewall_check as fw


RULESET = json.dumps({'nftables': [
    {'metainfo': {'json_schema_version': 1}},
    {'table': {'family': 'inet', 'name': 'filter'}},
    {'chain': {'family': 'inet', 'table': 'filter', 'name': 'input',
               'type': 'filter', 'hook': 'input', 'prio': 0, 'policy': 'drop'}},
    {'rule': {'family': 'inet', 'table': 'filter', 'chain': 'input', 'expr': [
        {'match': {'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}},
                   'op': '==', 'right': {'prefix': {'addr': '192.0.2.0', 'len': 24}}}},
        {'match': {'left': {'payload': {'protocol': 'tcp', 'field': 'dport'}},
                   'op': '==', 'right': 22}}, {'accept': None}]}},
]})
LISTENERS = 'tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=10,fd=9))\n'
ZONE_PUBLIC = ('firewall-cmd', '--info-zone=public')
SERVICE_SSH = ('firewall-cmd', '--info-service=ssh')


class FirewallCheckTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'ubuntu', 'version_id': '24.04'}
        os_reader = patch.object(fw, 'read_target_os', return_value=self.target)
        self.os_reader = os_reader.start()
        self.addCleanup(os_reader.stop)
        self.commands = []
        self.outputs = {
            fw.UFW_STATUS: 'Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n',
            fw.FIREWALLD_STATE: 'running\n',
            fw.FIREWALLD_ZONES: 'public\n  interfaces: ens33\n  sources: 192.0.2.0/24\n',
            fw.FIREWALLD_DEFAULT: 'public\n',
            ZONE_PUBLIC: ('public (active)\n  target: default\n  interfaces: ens33\n  sources: 192.0.2.0/24\n'
                          '  services: ssh\n  ports: 8000-8002/tcp 5353/udp\n  rich rules:\n'
                          '    rule family="ipv4" source address="192.0.2.0/24" reject\n'),
            SERVICE_SSH: 'ssh\n  ports: 22/tcp\n  destination: ipv4:192.0.2.10\n',
            fw.NFT_RULESET: RULESET,
            fw.LISTENERS_COMMAND: LISTENERS,
        }

    def collect(self, command):
        self.commands.append(command)
        output = self.outputs[command]
        if isinstance(output, Exception):
            raise output
        return output

    def test_ubuntu_collects_runtime_state_without_a_policy_verdict(self):
        result = fw.run_from_policy(command_runner=self.collect)
        observed = result['details']['observations']
        self.assertEqual((result['check_id'], result['status'], result['severity']), ('FW-01', 'needs_review', 'high'))
        self.assertEqual(self.commands, [fw.UFW_STATUS, fw.NFT_RULESET, fw.LISTENERS_COMMAND])
        self.assertEqual(observed['ufw']['default_policies']['incoming'], 'deny')
        self.assertEqual(observed['nftables']['base_chains'][0]['direct_rule_count'], 1)
        self.assertEqual(observed['listeners'], [{'protocol': 'tcp', 'address': '::', 'port': 22}])
        self.assertEqual(observed['nftables']['rules'][0]['matches'][0]['value'], '192.0.2.0/24')
        self.assertNotIn('"expr"', json.dumps(result))
        self.assertNotIn('pid=', json.dumps(result))

    def test_rocky_collects_active_zones(self):
        self.target.update(id='rocky', version_id='9.8')
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(self.commands, [fw.FIREWALLD_STATE, fw.FIREWALLD_ZONES, fw.FIREWALLD_DEFAULT,
                                         ZONE_PUBLIC, SERVICE_SSH, fw.NFT_RULESET, fw.LISTENERS_COMMAND])
        observed = result['details']['observations']
        self.assertEqual(observed['active_zones'], [
            {'zone': 'public', 'interface_count': 1, 'source_count': 1}])
        self.assertEqual(observed['zone:public']['sources'], ['192.0.2.0/24'])
        self.assertEqual(observed['service:ssh']['ports'], ['22/tcp'])
        self.assertEqual(len(observed['zone:public']['rich rules']), 1)
        self.assertEqual(result['status'], 'needs_review')

    def test_ufw_reads_allow_and_deny_ranges_and_removes_comments(self):
        self.outputs[fw.UFW_STATUS] += (
            '\nTo                         Action      From\n'
            '--                         ------      ----\n'
            '22/tcp (v6)                ALLOW IN    2001:db8::/64 # local-note\n'
            '22/tcp                     DENY IN     Anywhere\n'
            '8000:8002/tcp              ALLOW IN    192.0.2.0/24\n')
        result = fw.run_from_policy(command_runner=self.collect)
        rules = result['details']['observations']['ufw']['rules']
        self.assertEqual(rules[0]['from'], '2001:db8::/64')
        self.assertNotIn('local-note', json.dumps(result))
        comparison = result['details']['listener_comparison']
        self.assertEqual([ref['action'] for ref in comparison['listeners'][0]['matched_references']
                          if ref['source'] == 'ufw'], ['allow', 'deny'])
        self.assertEqual(comparison['configured_port_references_without_listener'][0]['last_port'], 8002)
        self.assertEqual(result['status'], 'needs_review')

    def test_port_references_match_protocol_and_range_without_access_verdict(self):
        self.target.update(id='rocky', version_id='9.8')
        self.outputs[fw.LISTENERS_COMMAND] += (
            'tcp LISTEN 0 128 0.0.0.0:8001 0.0.0.0:*\n'
            'udp UNCONN 0 0 0.0.0.0:22 0.0.0.0:*\n')
        result = fw.run_from_policy(command_runner=self.collect)
        comparison = result['details']['listener_comparison']
        by_port = {(row['listener']['protocol'], row['listener']['port']): row['matched_references']
                   for row in comparison['listeners']}
        self.assertEqual(by_port['tcp', 8001][0]['source'], 'firewalld_zone')
        self.assertIn('firewalld_service', [entry['source'] for entry in by_port['tcp', 22]])
        self.assertEqual(by_port['udp', 22], [])
        self.assertEqual(result['status'], 'needs_review')

    def test_default_zone_is_queried_when_no_active_zones_listed(self):
        self.target.update(id='rocky', version_id='9.8')
        self.outputs[fw.FIREWALLD_ZONES] = ''
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['details']['observations']['active_zones'], [])
        self.assertIn(ZONE_PUBLIC, self.commands)

    def test_firewalld_service_lookup_error_preserves_zone_and_other_observations(self):
        self.target.update(id='rocky', version_id='9.8')
        self.outputs[SERVICE_SSH] = subprocess.CalledProcessError(101, SERVICE_SSH)
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['stage'], 'service:ssh')
        self.assertIn('zone:public', result['details']['observations'])
        self.assertIn('listener_comparison', result['details'])

    def test_truncated_zone_does_not_count_as_empty_configuration(self):
        self.target.update(id='rocky', version_id='9.8')
        self.outputs[ZONE_PUBLIC] = 'public (active)\n  target: default\n'
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['stage'], 'zone:public')
        self.assertNotIn('zone:public', result['details']['observations'])

    def test_unsupported_nft_set_expression_is_recorded_as_unresolved(self):
        document = json.loads(RULESET)
        expression = document['nftables'][-1]['rule']['expr'][1]['match']
        expression['right'] = '@allowed_ports'
        rule = fw.summarize_nftables(json.dumps(document))['rules'][0]
        self.assertEqual(rule['unresolved_expression_count'], 1)
        self.assertEqual(len(rule['matches']), 1)

    def test_ufw_inactive_still_checks_nftables(self):
        self.outputs[fw.UFW_STATUS] = 'Status: inactive\n'
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(result['details']['observations']['nftables']['rule_count'], 1)

    def test_firewalld_not_running_does_not_query_zones(self):
        self.target.update(id='rocky', version_id='9.8')
        self.outputs[fw.FIREWALLD_STATE] = subprocess.CalledProcessError(252, fw.FIREWALLD_STATE)
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['details']['observations']['firewalld']['state'], 'not_running')
        self.assertEqual(result['status'], 'needs_review')
        self.assertNotIn(fw.FIREWALLD_ZONES, self.commands)

    def test_firewalld_failed_start_is_an_error(self):
        self.target.update(id='rocky', version_id='9.8')
        self.outputs[fw.FIREWALLD_STATE] = subprocess.CalledProcessError(251, fw.FIREWALLD_STATE)
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['exit_code'], 251)

    def test_absent_frontend_can_still_observe_nftables(self):
        self.outputs[fw.UFW_STATUS] = FileNotFoundError('ufw')
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(result['details']['observations']['ufw']['state'], 'tool_unavailable')

    def test_backend_permission_failure_preserves_other_evidence(self):
        self.outputs[fw.NFT_RULESET] = subprocess.CalledProcessError(
            1, fw.NFT_RULESET, stderr='Operation not permitted: sensitive rule expression')
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['details']['errors'][0]['reason'], 'permission_denied')
        self.assertIn('listeners', result['details']['observations'])
        self.assertNotIn('sensitive rule expression', json.dumps(result))

    def test_malformed_nftables_is_not_an_empty_ruleset(self):
        self.outputs[fw.NFT_RULESET] = '{"nftables":[{"rule":{}}]}'
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('nftables', result['details']['observations'])

    def test_explicit_empty_ruleset_remains_review(self):
        self.outputs[fw.NFT_RULESET] = '{"nftables":[]}'
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'needs_review')
        self.assertEqual(result['details']['observations']['nftables']['rule_count'], 0)

    def test_missing_os_preserves_backend_evidence_and_fails_collection(self):
        self.os_reader.side_effect = OSError('os-release unreadable')
        result = fw.run_from_policy(command_runner=self.collect)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(self.commands, [fw.NFT_RULESET, fw.LISTENERS_COMMAND])
        self.assertEqual(result['details']['errors'][0]['stage'], 'os')

    def test_cli_emits_diagnostic_error_with_exit_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / 'missing.json'
            with patch.object(fw.sys, 'argv', ['firewall_check', '--policy', str(missing)]), \
                    patch('builtins.print') as output:
                self.assertEqual(fw.main(), 0)
        result = json.loads(output.call_args[0][0])
        self.assertEqual(result['status'], 'error')
        self.assertEqual(set(result), {'check_id', 'status', 'severity', 'evidence', 'recommendation', 'details'})


if __name__ == '__main__':
    unittest.main()
