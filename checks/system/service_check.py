"""Read-only SVC-01 service and listening socket diagnosis."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys

from .common import PolicyError, load_policy, make_result, recommendation_for_status
from .result_adapter import adapt_result, add_result_version_argument


CHECK_ID = 'SVC-01'
DEFAULT_POLICY = Path(__file__).resolve().parent / 'policies/service_policy.json'
SYSTEMCTL = ('systemctl', '--system', '--no-pager', '--no-legend', '--plain', '--full')
ACTIVE_COMMAND = SYSTEMCTL + ('list-units', '--type=service', '--state=active')
UNIT_FILES_COMMAND = SYSTEMCTL + ('list-unit-files', '*.service')
LISTENERS_COMMAND = ('ss', '-H', '-lntup')
SERVICE_NAME = re.compile(r'[A-Za-z0-9@_.:\\-]+\.service')
PROCESS_NAME = re.compile(r'\("([A-Za-z0-9_.@ +:/-]+)",pid=[0-9]+,fd=[0-9]+\)')


def parse_active_units(output):
    """Parse UNIT LOAD ACTIVE SUB, without exporting descriptions."""
    units = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 4)
        if len(fields) < 4 or not SERVICE_NAME.fullmatch(fields[0]) or fields[2] != 'active':
            raise ValueError('unexpected active service row')
        units.add(fields[0])
    return sorted(units)


def parse_unit_files(output):
    """Parse enablement inventory, separate from live service state."""
    files = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) not in (2, 3) or not SERVICE_NAME.fullmatch(fields[0]):
            raise ValueError('unexpected service unit file row')
        if fields[0] in files and files[fields[0]] != fields[1]:
            raise ValueError('conflicting service unit file states')
        files[fields[0]] = fields[1]
    return [{'unit': unit, 'state': files[unit]} for unit in sorted(files)]


def _endpoint(protocol, address, port):
    if protocol not in ('tcp', 'udp') or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid listener protocol or port')
    if not isinstance(address, str):
        raise ValueError('invalid listener address')
    host, separator, interface = address.partition('%')
    if separator and not re.fullmatch(r'[A-Za-z0-9_.:-]+', interface):
        raise ValueError('invalid listener interface')
    if host != '*':
        host = ipaddress.ip_address(host).compressed
    return protocol, host + separator + interface, port


def parse_listeners(output):
    """Parse bind endpoints and process-name hints when ss can see them."""
    listeners = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 6)
        if (len(fields) < 6 or (fields[0], fields[1]) not in
                (('tcp', 'LISTEN'), ('udp', 'UNCONN'))):
            raise ValueError('unexpected listening socket row')
        address, colon, port = fields[4].rpartition(':')
        if not colon or not re.fullmatch(r'[0-9]+', port):
            raise ValueError('expected a numeric local port')
        if address.startswith('[') and address.endswith(']'):
            address = address[1:-1]
        endpoint = _endpoint(fields[0], address, int(port))
        names = listeners.setdefault(endpoint, set())
        if len(fields) == 7 and fields[6].startswith('users:('):
            names.update(PROCESS_NAME.findall(fields[6]))
    return {endpoint: sorted(listeners[endpoint]) for endpoint in sorted(listeners)}


def _listener_item(endpoint):
    protocol, address, port = endpoint
    return {'protocol': protocol, 'address': address, 'port': port}


def read_target_os(path=Path('/etc/os-release')):
    values = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        key, _, value = line.partition('=')
        if key not in ('ID', 'VERSION_ID'):
            continue
        words = shlex.split(value)
        if key in values or len(words) != 1 or not re.fullmatch(r'[A-Za-z0-9_.-]+', words[0]):
            raise ValueError('invalid OS identification field: ' + key)
        values[key] = words[0]
    if set(values) != {'ID', 'VERSION_ID'}:
        raise ValueError('OS identification requires ID and VERSION_ID')
    return {'id': values['ID'], 'version_id': values['VERSION_ID']}


def _read_command(command):
    env = dict(os.environ, LC_ALL='C', SYSTEMD_COLORS='0')
    completed = subprocess.run(command, capture_output=True, encoding='utf-8',
                               env=env, timeout=10, check=True)
    if completed.stderr.strip():
        raise ValueError('command reported a diagnostic on stderr')
    return completed.stdout


def _profiles(document):
    if not document['policies']:
        return {}
    matches = [item for item in document['policies'] if item['check_id'] == CHECK_ID]
    if len(matches) != 1:
        raise PolicyError('expected one SVC-01 policy')
    policy = matches[0]
    if policy['severity'] != 'medium':
        raise PolicyError('SVC-01 severity must match the team baseline (medium)')
    criteria = policy['criteria']
    if 'applies_to' in policy or set(criteria) != {'profiles'} or not isinstance(criteria['profiles'], list):
        raise PolicyError('SVC-01 policy must use criteria.profiles')
    profiles = {}
    scope_fields = ('os_id', 'os_version', 'role', 'network_context')
    for profile in criteria['profiles']:
        if not isinstance(profile, dict) or set(profile) != set(scope_fields) | {
                'approval_status', 'unit_rules', 'listener_rules'}:
            raise PolicyError('invalid SVC-01 profile fields')
        key = tuple(profile[field] for field in scope_fields)
        if any(not isinstance(value, str) or not value.strip() for value in key) or key in profiles:
            raise PolicyError('invalid or duplicate SVC-01 profile scope')
        state = profile['approval_status']
        if state not in ('pending', 'candidate', 'approved'):
            raise PolicyError('unsupported SVC-01 approval status')
        units = profile['unit_rules']
        if not isinstance(units, dict) or any(not SERVICE_NAME.fullmatch(unit) or
                rule not in ('allowed', 'required', 'forbidden') for unit, rule in units.items()):
            raise PolicyError('unit_rules must map service names to allowed, required or forbidden')
        rules = profile['listener_rules']
        if not isinstance(rules, list):
            raise PolicyError('listener_rules must be an array')
        listeners = {}
        for rule in rules:
            if not isinstance(rule, dict) or set(rule) != {
                    'protocol', 'port', 'allowed_addresses', 'deny_unlisted_bindings'}:
                raise PolicyError('invalid listener rule fields')
            protocol, port = rule['protocol'], rule['port']
            addresses = rule['allowed_addresses']
            strict = rule['deny_unlisted_bindings']
            if not isinstance(addresses, list) or type(strict) is not bool:
                raise PolicyError('invalid listener address list or binding restriction')
            try:
                _endpoint(protocol, '*', port)
                allowed = {_endpoint(protocol, address, port)[1] for address in addresses}
            except ValueError as exc:
                raise PolicyError('invalid listener rule endpoint') from exc
            if (protocol, port) in listeners:
                raise PolicyError('duplicate listener rule')
            listeners[(protocol, port)] = (allowed, strict)
        profiles[key] = (state, units, listeners)
    return profiles


def _record_policy_findings(details, profile, listeners):
    _, units, rules = profile
    active = details['observations'].get('active_units')
    if active is not None:
        active = set(active)
        for unit, rule in sorted(units.items()):
            if (rule == 'forbidden' and unit in active) or (rule == 'required' and unit not in active):
                details['violations'].append({'unit': unit, 'rule': rule, 'active': unit in active})
    for endpoint in listeners:
        protocol, address, port = endpoint
        item = _listener_item(endpoint)
        rule = rules.get((protocol, port))
        if rule is None:
            item['reason'] = 'listener_policy_missing'
        else:
            allowed, strict = rule
            if address not in allowed:
                item['reason'] = 'binding_not_approved'
                if strict:
                    item.update(reason='binding_explicitly_forbidden', allowed_addresses=sorted(allowed))
                    details['violations'].append(item)
                    continue
            else:
                host = address.split('%', 1)[0]
                if host != '*' and ipaddress.ip_address(host).is_loopback:
                    continue
                item['reason'] = 'network_access_unverified'
        details['review'].append(item)


def run_from_policy(path=DEFAULT_POLICY, command_runner=None, *, target_id=None, role=None,
                    network_context=None):
    """Return one JSON v1.1 item for the local execution target."""
    try:
        document = load_policy(path)
        profiles = _profiles(document)
    except PolicyError as exc:
        return make_result(CHECK_ID, 'error', 'medium', 'SVC-01: 정책을 읽거나 검증할 수 없습니다.',
                           recommendation_for_status('error'),
                           {'errors': [{'stage': 'policy', 'reason': str(exc)}]})

    runner = _read_command if command_runner is None else command_runner
    target = {'target_id': target_id, 'role': role, 'network_context': network_context,
              'hostname': socket.gethostname(), 'os': None}
    details = {'policy_version': document['policy_version'], 'approval_status': 'pending',
               'target': target, 'observations': {}, 'violations': [], 'review': [], 'errors': []}
    try:
        target['os'] = read_target_os()
    except (OSError, ValueError) as exc:
        details['errors'].append({'stage': 'os', 'kind': type(exc).__name__})

    profile = None
    if not profiles:
        details['review'].append({'reason': 'policy_pending'})
    if target['os'] is None or not all(isinstance(value, str) and value.strip()
                                      for value in (target_id, role, network_context)):
        details['review'].append({'reason': 'target_context_missing'})
    elif profiles:
        key = (target['os']['id'], target['os']['version_id'], role, network_context)
        profile = profiles.get(key)
        if profile is None:
            details['review'].append({'reason': 'no_matching_profile'})
        else:
            details['approval_status'] = profile[0]
            if profile[0] != 'approved':
                details['review'].append({'reason': 'policy_pending'})

    listeners = {}
    for name, command, parser in (
            ('active_units', ACTIVE_COMMAND, parse_active_units),
            ('unit_files', UNIT_FILES_COMMAND, parse_unit_files),
            ('listeners', LISTENERS_COMMAND, parse_listeners)):
        try:
            output = runner(command)
            if not isinstance(output, str):
                raise ValueError('expected text output')
            values = parser(output)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            error = {'stage': name, 'command': list(command), 'kind': type(exc).__name__}
            if isinstance(exc, subprocess.CalledProcessError):
                error['exit_code'] = exc.returncode
            elif isinstance(exc, ValueError):
                error['reason'] = str(exc) if type(exc) is ValueError else 'invalid command text encoding'
            details['errors'].append(error)
            continue
        if name == 'listeners':
            listeners = values
            values = [dict(_listener_item(endpoint), process_names=names)
                      for endpoint, names in listeners.items()]
        details['observations'][name] = values

    if profile is not None and profile[0] == 'approved':
        _record_policy_findings(details, profile, listeners)

    count = len(details['violations'])
    if count:
        status = 'vulnerable'
        evidence = 'SVC-01: 승인된 유닛 또는 바인딩 정책 위반 {}건.'.format(count)
    elif details['errors']:
        status = 'error'
        evidence = 'SVC-01: 필수 조회 또는 파싱에 실패했습니다.'
    elif details['review']:
        status = 'needs_review'
        evidence = 'SVC-01: 서비스와 수신 소켓을 조회했습니다. 정책 또는 접근 범위 확인 {}건이 필요합니다.'.format(
            len(details['review']))
    else:
        status = 'pass'
        evidence = 'SVC-01: 점검 대상 유닛과 수신 소켓이 승인 기준을 충족합니다.'
    if details['errors']:
        evidence += ' 조회 오류 {}건.'.format(len(details['errors']))
    return make_result(CHECK_ID, status, 'medium', evidence, recommendation_for_status(status), details)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    parser.add_argument('--target-id')
    parser.add_argument('--role')
    parser.add_argument('--network-context')
    add_result_version_argument(parser)
    args = parser.parse_args()
    result = run_from_policy(args.policy, target_id=args.target_id, role=args.role,
                             network_context=args.network_context)
    # The exit code reports delivery of the JSON. Its status reports the diagnosis.
    print(json.dumps(adapt_result(result, args.result_version), ensure_ascii=False,
                     indent=2, allow_nan=False), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
