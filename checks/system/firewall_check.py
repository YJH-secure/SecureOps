"""FW-01 read-only host firewall inventory for policy review."""

import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

from .common import PolicyError, load_policy, make_result, recommendation_for_status
from .result_adapter import adapt_result, add_result_version_argument
from .service_check import LISTENERS_COMMAND, _read_command, parse_listeners, read_target_os


CHECK_ID = 'FW-01'
DEFAULT_POLICY = Path(__file__).resolve().parent / 'policies/firewall_policy.json'
UFW_STATUS = ('ufw', 'status', 'verbose')
FIREWALLD_STATE = ('firewall-cmd', '--state')
FIREWALLD_ZONES = ('firewall-cmd', '--get-active-zones')
FIREWALLD_DEFAULT = ('firewall-cmd', '--get-default-zone')
NFT_RULESET = ('nft', '-j', 'list', 'ruleset')
FIREWALLD_NAME = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*')
PORT_SPEC = re.compile(r'([0-9]{1,5})(?:[-:]([0-9]{1,5}))?/(tcp|udp)')


def parse_ufw_status(output):
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if not lines or lines[0] not in ('Status: active', 'Status: inactive'):
        raise ValueError('unrecognized UFW status')
    result = {'state': lines[0].split()[-1], 'rules': [], 'unparsed_rule_count': 0}
    in_rules = False
    for line in lines[1:]:
        if line.startswith('Default:'):
            result['default_policies'] = {
                direction: action for action, direction in
                re.findall(r'([a-z]+) \((incoming|outgoing|routed)\)', line)
            }
        elif re.fullmatch(r'To\s+Action\s+From', line):
            in_rules = True
        elif in_rules and not re.fullmatch(r'[-\s]+', line):
            row = re.fullmatch(r'(.+?)\s{2,}(ALLOW|DENY|REJECT|LIMIT)(?: (IN|OUT|FWD))?\s{2,}(.+)', line)
            if row:
                destination, action, direction, source = row.groups()
                result['rules'].append({'to': destination, 'action': action.lower(),
                                        'direction': (direction or 'IN').lower(),
                                        'from': source.partition('#')[0].strip()})
            else:
                result['unparsed_rule_count'] += 1
    return result


def parse_active_zones(output):
    zones = []
    for line in output.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace() and FIREWALLD_NAME.fullmatch(line.strip()):
            zones.append({'zone': line.strip(), 'interface_count': 0, 'source_count': 0})
            continue
        key, separator, values = line.strip().partition(':')
        if not zones or not separator or key not in ('interfaces', 'sources'):
            raise ValueError('unrecognized firewalld zone row')
        field = 'interface_count' if key == 'interfaces' else 'source_count'
        zones[-1][field] = len(values.split())
    return zones


def _default_zone(output):
    name = output.strip()
    if not FIREWALLD_NAME.fullmatch(name):
        raise ValueError('unrecognized firewalld default zone')
    return name


def _firewalld_fields(output, name, list_fields, multiline_fields=(), required_fields=()):
    lines = [line for line in output.splitlines() if line.strip()]
    if not lines or lines[0].split()[0] != name:
        raise ValueError('unexpected firewalld object header')
    fields = {key: [] for key in (*list_fields, *multiline_fields)}
    seen = set()
    multiline = None
    indentation = 0
    for line in lines[1:]:
        value = line.strip()
        depth = len(line) - len(line.lstrip())
        if multiline and depth > indentation:
            fields[multiline].append(value)
            continue
        multiline = None
        key, separator, values = value.partition(':')
        if not separator:
            continue
        if key in list_fields:
            fields[key] = values.split()
            seen.add(key)
        elif key in multiline_fields:
            multiline, indentation = key, depth
            if values.strip():
                fields[key].append(values.strip())
        elif key == 'target':
            fields[key] = values.strip()
    if any(field not in seen for field in required_fields):
        raise ValueError('incomplete firewalld object output')
    return fields


def _collect_firewalld_config(details, runner, zones):
    default = _observe(details, 'default_zone', lambda: _default_zone(runner(FIREWALLD_DEFAULT)))
    names = {zone['zone'] for zone in zones or []}
    if default is not None:
        names.add(default)
    service_names = set()
    for name in sorted(names):
        command = ('firewall-cmd', '--info-zone=' + name)
        fields = _observe(details, 'zone:' + name, lambda: _firewalld_fields(
            runner(command), name, ('interfaces', 'sources', 'services', 'ports', 'protocols'),
            ('rich rules', 'forward-ports'), required_fields=('services', 'ports')))
        if fields:
            service_names.update(fields['services'])
    for name in sorted(service_names):
        if not FIREWALLD_NAME.fullmatch(name):
            details['errors'].append({'stage': 'firewalld_services', 'kind': 'ValueError'})
            continue
        command = ('firewall-cmd', '--info-service=' + name)
        _observe(details, 'service:' + name, lambda: _firewalld_fields(
            runner(command), name, ('ports', 'protocols', 'source-ports', 'destination', 'includes'),
            required_fields=('ports',)))


def _required_strings(item, names):
    values = tuple(item.get(name) for name in names)
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError('missing nftables object identifier')
    return values


def _summarize_nft_rule(key, index, expressions):
    family, table, chain = key
    result = {'family': family, 'table': table, 'chain': chain, 'index': index,
              'matches': [], 'actions': [], 'unresolved_expression_count': 0}
    for expression in expressions:
        if not isinstance(expression, dict) or len(expression) != 1:
            raise ValueError('invalid nftables rule statement')
        kind, value = next(iter(expression.items()))
        if kind in ('accept', 'drop', 'reject', 'return', 'jump', 'goto'):
            result['actions'].append(kind)
        elif kind == 'match' and isinstance(value, dict):
            left = value.get('left')
            payload = left.get('payload') if isinstance(left, dict) else None
            right, operator = value.get('right'), value.get('op')
            if isinstance(right, dict) and isinstance(right.get('prefix'), dict):
                prefix = right['prefix']
                if isinstance(prefix.get('addr'), str) and type(prefix.get('len')) is int:
                    right = str(ipaddress.ip_network('{}/{}'.format(prefix['addr'], prefix['len']), strict=False))
            if (isinstance(payload, dict) and payload.get('protocol') in ('ip', 'ip6', 'tcp', 'udp')
                    and payload.get('field') in ('saddr', 'daddr', 'sport', 'dport')
                    and operator in ('==', '!=', 'in', 'not in')
                    and (type(right) is int or isinstance(right, str) and not right.startswith('@'))):
                result['matches'].append({'protocol': payload['protocol'], 'field': payload['field'],
                                          'operator': operator, 'value': right})
            else:
                result['unresolved_expression_count'] += 1
        elif kind != 'counter':
            result['unresolved_expression_count'] += 1
    return result


def summarize_nftables(output):
    """Capture selected runtime statements without resolving chains or verdicts."""
    document = json.loads(output)
    if not isinstance(document, dict) or not isinstance(document.get('nftables'), list):
        raise ValueError('expected nftables JSON object array')
    counts = Counter()
    rule_counts = Counter()
    base_chains = []
    rules = []
    for entry in document['nftables']:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise ValueError('invalid nftables object')
        kind, item = next(iter(entry.items()))
        if not isinstance(item, dict):
            raise ValueError('invalid nftables object attributes')
        if kind == 'table':
            _required_strings(item, ('family', 'name'))
        elif kind == 'chain':
            family, table, name = _required_strings(item, ('family', 'table', 'name'))
            if 'hook' in item:
                hook, chain_type, policy = _required_strings(item, ('hook', 'type', 'policy'))
                priority = item.get('prio')
                if type(priority) is not int or policy not in ('accept', 'drop'):
                    raise ValueError('invalid nftables base chain metadata')
                base_chains.append({'family': family, 'table': table, 'chain': name, 'hook': hook,
                                    'type': chain_type, 'policy': policy, 'priority': priority})
        elif kind == 'rule':
            key = _required_strings(item, ('family', 'table', 'chain'))
            if not isinstance(item.get('expr'), list):
                raise ValueError('nftables rule expression list missing')
            rule_counts[key] += 1
            rules.append(_summarize_nft_rule(key, rule_counts[key], item['expr']))
        counts[kind] += 1
    for chain in base_chains:
        key = chain['family'], chain['table'], chain['chain']
        chain['direct_rule_count'] = rule_counts[key]
    return {'table_count': counts['table'], 'chain_count': counts['chain'],
            'rule_count': counts['rule'], 'base_chains': base_chains, 'rules': rules}


def _firewalld_state(runner):
    try:
        output = runner(FIREWALLD_STATE).strip()
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 252:  # firewall-cmd NOT_RUNNING
            return {'state': 'not_running'}
        raise
    if output != 'running':
        raise ValueError('unrecognized firewalld state')
    return {'state': 'running'}


def _listeners(output):
    return [{'protocol': protocol, 'address': address, 'port': port}
            for protocol, address, port in parse_listeners(output)]


def _port_reference(token, **metadata):
    match = PORT_SPEC.fullmatch(token)
    if not match:
        return None
    first, last, protocol = match.groups()
    first, last = int(first), int(last or first)
    if not 1 <= first <= last <= 65535:
        return None
    return dict(protocol=protocol, first_port=first, last_port=last, **metadata)


def _port_references(observations):
    references = []
    ufw = observations.get('ufw', {})
    if ufw.get('state') == 'active':
        for index, rule in enumerate(ufw['rules'], 1):
            if rule['direction'] == 'in':
                references.append(_port_reference(rule['to'].split()[0], source='ufw',
                                                  action=rule['action'], rule_index=index))
    for stage, zone in observations.items():
        if not stage.startswith('zone:'):
            continue
        name = stage.partition(':')[2]
        for token in zone['ports']:
            references.append(_port_reference(token, source='firewalld_zone', zone=name))
        for service in zone['services']:
            service_fields = observations.get('service:' + service, {})
            for token in service_fields.get('ports', []):
                references.append(_port_reference(token, source='firewalld_service',
                                                  zone=name, service=service))
    for rule in observations.get('nftables', {}).get('rules', []):
        actions = [action for action in rule['actions'] if action in ('accept', 'drop', 'reject')]
        for match in rule['matches']:
            if (actions and match['field'] == 'dport' and match['operator'] == '=='
                    and type(match['value']) is int):
                token = '{}/{}'.format(match['value'], match['protocol'])
                references.append(_port_reference(token, source='nftables', actions=actions,
                                                  family=rule['family'], table=rule['table'],
                                                  chain=rule['chain'], rule_index=rule['index']))
    return [reference for reference in references if reference is not None]


def _compare_listeners(observations):
    references = _port_references(observations)
    listeners = observations['listeners']
    matches = []
    matched = set()
    for listener in listeners:
        indices = [index for index, ref in enumerate(references)
                   if listener['protocol'] == ref['protocol'] and ref['first_port'] <= listener['port'] <= ref['last_port']]
        matched.update(indices)
        matches.append({'listener': listener, 'matched_references': [references[index] for index in indices]})
    return {'basis': 'protocol_port_configuration_hints', 'listeners': matches,
            'configured_port_references_without_listener': [ref for index, ref in enumerate(references)
                                                            if index not in matched]}


def _observe(details, stage, collect, *, optional_tool=False):
    try:
        value = collect()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        if optional_tool and isinstance(exc, FileNotFoundError):
            details['observations'][stage] = {'state': 'tool_unavailable'}
            return None
        error = {'stage': stage, 'kind': type(exc).__name__}
        if isinstance(exc, subprocess.CalledProcessError):
            error['exit_code'] = exc.returncode
            if re.search(r'permission denied|operation not permitted|not authorized|need to be root',
                         exc.stderr or '', re.IGNORECASE):
                error['reason'] = 'permission_denied'
        details['errors'].append(error)
        return None
    details['observations'][stage] = value
    return value


def run_from_policy(path=DEFAULT_POLICY, command_runner=None):
    try:
        document = load_policy(path)
    except PolicyError as exc:
        return make_result(CHECK_ID, 'error', 'high', 'FW-01: 정책 파일을 읽거나 검증할 수 없습니다.',
                           recommendation_for_status('error'),
                           {'errors': [{'stage': 'policy', 'reason': str(exc)}]})

    runner = _read_command if command_runner is None else command_runner
    details = {'policy_version': document['policy_version'], 'observations': {}, 'errors': [],
               'review': ['policy_evaluation_pending' if document['policies'] else 'policy_pending']}
    target = _observe(details, 'os', read_target_os)
    if target and target['id'] == 'ubuntu':
        _observe(details, 'ufw', lambda: parse_ufw_status(runner(UFW_STATUS)), optional_tool=True)
    elif target and target['id'] == 'rocky':
        firewalld = _observe(details, 'firewalld', lambda: _firewalld_state(runner), optional_tool=True)
        if firewalld and firewalld['state'] == 'running':
            zones = _observe(details, 'active_zones', lambda: parse_active_zones(runner(FIREWALLD_ZONES)))
            _collect_firewalld_config(details, runner, zones)
    elif target:
        details['review'].append('frontend_not_selected_for_os')

    _observe(details, 'nftables', lambda: summarize_nftables(runner(NFT_RULESET)))
    _observe(details, 'listeners', lambda: _listeners(runner(LISTENERS_COMMAND)))
    if 'listeners' in details['observations']:
        details['listener_comparison'] = _compare_listeners(details['observations'])
    if details['errors']:
        status = 'error'
        evidence = 'FW-01: 조회 또는 파싱 오류 {}건을 기록했습니다.'.format(len(details['errors']))
    else:
        status = 'needs_review'
        evidence = 'FW-01: 방화벽 상태와 수신 소켓을 조회했습니다. 승인 기준과 접근 검증이 필요합니다.'
    return make_result(CHECK_ID, status, 'high', evidence, recommendation_for_status(status), details)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    add_result_version_argument(parser)
    args = parser.parse_args()
    result = run_from_policy(args.policy)
    print(json.dumps(adapt_result(result, args.result_version), ensure_ascii=False,
                     indent=2, allow_nan=False), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
