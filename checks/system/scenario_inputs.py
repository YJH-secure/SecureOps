"""Synthetic inputs reused from the reviewed five-status v1.1 demonstration."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
from unittest.mock import patch

from checks.system import file_check, firewall_check, log_check, service_check
from checks.system.common import make_result

FIELDS = ('check_id', 'status', 'severity', 'evidence', 'recommendation')
METRICS = {'pass': 'pass_count', 'vulnerable': 'vulnerable_count', 'error': 'error_count',
           'needs_review': 'needs_review_count', 'not_applicable': 'na_count'}


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False) + '\n',
                    encoding='utf-8')


def document(policy=None):
    return {'policy_version': 'MOCK-scenarios-v1', 'policies': [] if policy is None else [policy]}


def run_file(case, folder):
    inputs = case['inputs']
    policy = inputs['policy']
    data = inputs['observation']
    def collect(path):
        if path != data['path']:
            raise AssertionError('Unexpected fixture file path')
        return deepcopy(data)
    result = file_check.run(deepcopy(policy), collector=collect,
                            environment={'id': 'ubuntu', 'version_id': '24.04',
                                         'collection_origin': 'MOCK'})
    return result


def run_service(case, folder):
    inputs = case['inputs']
    policy = folder / 'mock-policy.json'
    write_json(policy, document(inputs['policy']))
    responses = {
        service_check.ACTIVE_COMMAND: inputs['active_units_stdout'],
        service_check.UNIT_FILES_COMMAND: inputs['unit_files_stdout'],
        service_check.LISTENERS_COMMAND: inputs['listeners_stdout'],
    }
    with patch.object(service_check, 'read_target_os', return_value=inputs['os']), \
            patch.object(service_check.socket, 'gethostname', return_value='scenario-host-mock'):
        return service_check.run_from_policy(
            policy, command_runner=lambda command: responses[command],
            **inputs['target'])


def run_firewall(case, folder):
    inputs = case['inputs']
    policy = folder / 'mock-policy.json'
    write_json(policy, document())
    responses = {firewall_check.UFW_STATUS: inputs['ufw_stdout'],
                 firewall_check.LISTENERS_COMMAND: inputs['listeners_stdout']}
    def collect(command):
        if command == firewall_check.NFT_RULESET:
            failure = inputs['nft_exception']
            if failure['kind'] != 'CalledProcessError':
                raise ValueError('Unsupported fixture error')
            raise subprocess.CalledProcessError(failure['exit_code'], command,
                                                stderr=failure['stderr'])
        return responses[command]
    with patch.object(firewall_check, 'read_target_os', return_value=inputs['os']):
        return firewall_check.run_from_policy(policy, command_runner=collect)


def run_log(case, folder):
    inputs = case['inputs']
    policy = folder / 'mock-policy.json'
    write_json(policy, document())
    etc = folder / 'mock-etc'
    etc.mkdir()
    responses = {log_check.unit_command(unit): inputs['unit_stdout'] for unit in log_check.UNITS}
    responses.update({log_check.JOURNAL_CONFIG: inputs['journald_stdout'],
                      log_check.JOURNAL_USAGE: inputs['usage_stdout']})
    def metadata(path):
        if path.as_posix() not in log_check.JOURNAL_PATHS + log_check.LOG_PATHS['ubuntu']:
            raise AssertionError('Unexpected fixture log path')
        return {'path': path.as_posix(), 'state': 'missing'}
    with patch.object(log_check, 'read_target_os', return_value=inputs['os']):
        return log_check.run_from_policy(policy, command_runner=lambda command: responses[command],
                                         config_root=etc, metadata_reader=metadata)


def run_exemption(case, folder):
    inputs = case['inputs']
    if inputs['approval_status'] != 'MOCK_ONLY_NOT_OPERATIONAL':
        raise ValueError('The exemption scenario must remain fixture-only')
    return make_result(inputs['check_id'], 'not_applicable', inputs['severity'],
                       inputs['evidence'], inputs['recommendation'],
                       {'fixture_only': True, 'exclusion_id': inputs['exclusion_id'],
                        'approval_status': inputs['approval_status'],
                        'condition': inputs['condition']})


RUNNERS = {'file': run_file, 'service': run_service, 'firewall': run_firewall,
           'log': run_log, 'exemption_fixture': run_exemption}

