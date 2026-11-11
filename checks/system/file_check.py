"""FILE-01 read-only diagnosis with approval gates and bounded target inspection."""
import argparse
import json
import os
import platform
import re
import stat
import subprocess
import sys
from pathlib import Path
from .common import (PolicyError, load_policy, make_result, validate_policy,
                     recommendation_for_status, sanitize_details, sanitize_text)
from .policy_rules import validate_extensions, group_check, gate_candidate, valid_identity
from .link_check import inspect_link

TARGET = '/etc/passwd'
TARGETS = frozenset(('/etc/passwd', '/etc/shadow'))
DEFAULT_POLICY = Path(__file__).parent / 'policies' / 'file_policy.json'
PRIORITY = ('vulnerable', 'error', 'needs_review', 'not_applicable', 'pass')


def aggregate(statuses):
    if any(not isinstance(status, str) or status not in PRIORITY for status in statuses):
        raise ValueError('unknown status')
    if not statuses:
        return 'needs_review'
    for status in PRIORITY:
        if status in statuses:
            return status
    raise ValueError('unknown status')


def validate_file_policy(policy):
    validate_policy(policy)
    if policy['check_id'] != 'FILE-01':
        raise PolicyError('expected FILE-01')
    criteria = policy['criteria']
    if set(criteria) != {'files'} or not isinstance(criteria['files'], list) or not criteria['files']:
        raise PolicyError('criteria must contain a nonempty files array only')
    seen = set()
    for item in criteria['files']:
        required = {'path', 'expected_uid', 'allowed_permission_bits', 'reference_gid'}
        optional = {'approval_status', 'allowed_groups', 'acl_policy', 'link_policy'}
        if not isinstance(item, dict) or not required <= set(item) or set(item) - required - optional:
            raise PolicyError('invalid file criteria fields')
        if not isinstance(item['path'], str) or item['path'] not in TARGETS or item['path'] in seen:
            raise PolicyError('unsupported or duplicate file path')
        seen.add(item['path'])
        for key in ('expected_uid', 'reference_gid'):
            if item[key] is not None and (type(item[key]) is not int or item[key] < 0):
                raise PolicyError(key + ' must be a nonnegative integer or null (pending approval)')
        bits = item['allowed_permission_bits']
        if bits is not None and (not isinstance(bits, str) or not re.fullmatch(r'[0-7]{4}', bits)):
            raise PolicyError('allowed_permission_bits must be four octal digits or null')
        validate_extensions(item)
    return policy


def parse_acl(text):
    """Validate numeric getfacl structure, retaining annotations without trusting them."""
    if not isinstance(text, str):
        raise ValueError('ACL output must be text')
    entries, keys = [], set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('#', 1)[0].strip().split(':')
        default = parts[0] == 'default'
        if default:
            parts = parts[1:]
        if (len(parts) != 3 or parts[0] not in ('user', 'group', 'mask', 'other')
                or not re.fullmatch(r'[r-][w-][x-]', parts[2])
                or (parts[0] in ('mask', 'other') and parts[1])
                or (parts[1] and not parts[1].isdigit())):
            raise ValueError('invalid numeric ACL entry')
        key = (default, parts[0], parts[1])
        if key in keys:
            raise ValueError('duplicate ACL entry')
        keys.add(key)
        entries.append(line)
    for default in (False, True):
        subset = {key for key in keys if key[0] == default}
        if default and not subset:
            continue
        if not {(default, kind, '') for kind in ('user', 'group', 'other')} <= subset:
            raise ValueError('incomplete ACL base entries')
        if any(key[2] for key in subset) and (default, 'mask', '') not in subset:
            raise ValueError('named ACL entries require mask')
    return entries


def _names(uid, gid):
    import pwd
    import grp
    try:
        owner = pwd.getpwuid(uid).pw_name
    except KeyError:
        owner = None
    try:
        group = grp.getgrgid(gid).gr_name
    except KeyError:
        group = None
    return owner, group


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_ctime_ns)


def collect_file_info(path=TARGET):
    if path not in TARGETS:
        raise ValueError('unsupported system file')
    return _collect_file_info(path)


def _collect_file_info(path, inspect_links=True):
    info = os.lstat(path)
    kind = ('symlink' if stat.S_ISLNK(info.st_mode) else
            'regular' if stat.S_ISREG(info.st_mode) else 'other')
    observation = dict(path=path, uid=info.st_uid, gid=info.st_gid,
                       mode=format(stat.S_IMODE(info.st_mode), '04o'), file_type=kind)
    try:
        observation['owner'], observation['group'] = _names(info.st_uid, info.st_gid)
    except (OSError, ImportError) as exc:
        observation.update(owner=None, group=None, name_lookup_error=str(exc))
    if kind != 'regular':
        observation['acl'] = {'state': 'not_collected', 'reason': 'file type requires review'}
        if kind == 'symlink':
            try:
                observation['link_target'] = os.readlink(path)
            except OSError as exc:
                observation['link_read_error'] = str(exc)
            if inspect_links:
                observation['link_inspection'] = inspect_link(
                    path, info, lambda target: _collect_file_info(target, inspect_links=False))
        return observation
    try:
        completed = subprocess.run(['getfacl', '-n', '-p', '-P', '--', path],
                                   capture_output=True, text=True, timeout=5, check=True)
        observation['acl'] = {'state': 'collected', 'raw': completed.stdout,
                              'entries': parse_acl(completed.stdout)}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        observation['acl'] = {'state': 'error', 'detail': str(exc)}
    try:
        if _identity(info) != _identity(os.lstat(path)):
            observation['snapshot_error'] = 'file changed during observation; retry required'
    except OSError as exc:
        observation['snapshot_error'] = str(exc)
    return observation


def _check(name, status, actual, expected, reason):
    return dict(name=name, status=status, actual=actual, expected=expected, reason=reason)


def _acl_check(observation, criteria=None):
    acl = observation.get('acl', {})
    if not isinstance(acl, dict):
        return _check('acl', 'error', acl, 'ACL object', 'invalid ACL observation type')
    if acl.get('state') != 'collected':
        return _check('acl', 'error', acl, 'readable valid ACL', 'ACL collection failed')
    try:
        entries = parse_acl(acl['raw'])
    except (KeyError, TypeError, ValueError) as exc:
        return _check('acl', 'error', acl, 'valid ACL', str(exc))
    base = {}
    access = []
    extended = False
    for line in entries:
        parts = line.split('#', 1)[0].strip().split(':')
        if parts[0] != 'default':
            access.append(parts)
        if parts[0] == 'default' or parts[0] == 'mask' or parts[1]:
            extended = True
        else:
            base[parts[0]] = sum(bit for c, bit in zip(parts[2], (4, 2, 1)) if c != '-')
    def bits(perms):
        return sum(bit for c, bit in zip(perms, (4, 2, 1)) if c != '-')
    mask = next((bits(p[2]) for p in access if p[0] == 'mask'), 7)
    effective = []
    for kind, qualifier, perms in access:
        if kind == 'mask':
            continue
        value = bits(perms)
        if kind == 'group' or (kind == 'user' and qualifier):
            value &= mask
        effective.append(dict(kind=kind, qualifier=qualifier, declared_bits=bits(perms),
                              effective_bits=value))
    acl = dict(acl, effective_entries=effective)
    invalid_ids = {key: observation.get(key) for key in ('uid', 'gid')
                   if not valid_identity(observation.get(key))}
    if invalid_ids:
        return _check('acl', 'error', dict(acl, identity_errors=invalid_ids),
                      'valid numeric UID and GID',
                      'ACL principal authorization requires collected owner/group identities')
    if not isinstance(observation.get('mode'), str) or not re.fullmatch(r'[0-7]{4}', observation['mode']):
        return _check('acl', 'error', acl, 'four-digit octal mode', 'invalid collected mode')
    mode = int(observation['mode'], 8)
    if extended:
        # The group mode field represents the mask when an access mask exists.
        user_bits = next(bits(p[2]) for p in access if p[0] == 'user' and not p[1])
        other_bits = next(bits(p[2]) for p in access if p[0] == 'other')
        group_bits = next((bits(p[2]) for p in access if p[0] == 'mask'),
                          next(bits(p[2]) for p in access if p[0] == 'group' and not p[1]))
        if [user_bits, group_bits, other_bits] != [(mode >> s) & 7 for s in (6, 3, 0)]:
            return _check('acl', 'error', acl, 'ACL/mask consistent with mode', 'ACL and mode disagree')
        acl_policy = (criteria or {}).get('acl_policy')
        if acl_policy and acl_policy['approval_status'] == 'approved':
            violations = []
            for entry in effective:
                kind, qualifier, effective_bits = entry['kind'], entry['qualifier'], entry['effective_bits']
                if kind == 'user' and qualifier and int(qualifier) == observation['uid']:
                    # The owner entry takes priority; a named entry for the owner is unreachable.
                    entry['access_note'] = 'shadowed by owner entry'
                    continue
                if kind == 'other':
                    permitted = acl_policy['other_max_bits']
                else:
                    identity = int(qualifier) if qualifier else observation['uid' if kind == 'user' else 'gid']
                    permitted = next((p['max_bits'] for p in acl_policy['users' if kind == 'user' else 'groups']
                                      if p['id'] == identity), 0)
                if effective_bits & ~permitted:
                    violations.append(dict(entry=entry, permitted_bits=permitted,
                                           unexpected_bits=effective_bits & ~permitted))
            acl['violations'] = violations
            if violations:
                return _check('acl', 'vulnerable', acl, acl_policy,
                              'effective ACL access exceeds explicitly approved principal rights')
            if any(line.startswith('default:') for line in entries):
                return _check('acl', 'needs_review', acl, acl_policy,
                              'unexpected default ACL on regular file requires review')
            return _check('acl', 'pass', acl, acl_policy,
                          'effective entries fit explicitly approved principal rights')
        return _check('acl', 'needs_review', acl, 'authorized effective access',
                      'effective entry bits calculated; named principal authorization pending')
    if [base[k] for k in ('user', 'group', 'other')] != [
            (mode >> shift) & 7 for shift in (6, 3, 0)]:
        return _check('acl', 'error', acl, 'ACL consistent with mode',
                      'base ACL and mode disagree; retry collection')
    return _check('acl', 'pass', acl, 'base ACL consistent with mode',
                  'no extended ACL; access represented by mode bits')


def evaluate_file(criteria, observation, environment=None):
    checks = []
    if not isinstance(observation, dict) or observation.get('path') != criteria['path']:
        checks.append(_check('observation', 'error', observation, criteria['path'],
                             'observation must be an object with the requested path'))
    elif observation.get('snapshot_error'):
        checks.append(_check('snapshot', 'error', observation['snapshot_error'],
                             'stable metadata', 'unstable observation is not evaluated'))
    elif not isinstance(observation.get('file_type'), str) or observation['file_type'] not in ('regular', 'symlink', 'other'):
        checks.append(_check('file_type', 'error', observation.get('file_type'),
                             ['regular', 'symlink', 'other'], 'missing or invalid collected file type'))
    elif observation.get('file_type') != 'regular':
        inspection = observation.get('link_inspection')
        link_policy = criteria.get('link_policy')
        if observation.get('file_type') == 'symlink' and isinstance(inspection, dict):
            target = inspection.get('target_observation')
            if (inspection.get('state') == 'collected' and isinstance(target, dict)
                    and target.get('file_type') == 'regular'
                    and link_policy and link_policy['approval_status'] == 'approved'):
                if inspection.get('target_path') in link_policy['allowed_targets']:
                    target_criteria = dict(criteria, path=target['path'])
                    evaluated = evaluate_file(target_criteria, target, environment)
                    evaluated.update(path=criteria['path'], actual=observation, expected=dict(criteria),
                                     target_result=dict(path=target['path'], checks=evaluated['checks'][:]))
                    evaluated['checks'] = [_check('link_target', 'pass', inspection['target_path'],
                                                   link_policy, 'target path explicitly approved')] + evaluated['checks']
                    evaluated['status'] = aggregate([c['status'] for c in evaluated['checks']])
                    return evaluated
                checks.append(_check('link_target', 'vulnerable', inspection,
                                     link_policy, 'target outside explicitly approved target list'))
            else:
                status = 'error' if inspection.get('state') == 'error' else 'needs_review'
                checks.append(_check('link_target', status, inspection, link_policy,
                                     'target inspection does not grant policy approval'))
        checks.append(_check('file_type', 'needs_review', observation.get('file_type'),
                             'regular file', 'link target evaluation pending; no following'))
        if observation.get('link_read_error'):
            checks.append(_check('link_target', 'error', observation['link_read_error'],
                                 'readable link text', 'readlink failed'))
    else:
        uid = observation.get('uid')
        if type(uid) is not int or uid < 0:
            checks.append(_check('owner', 'error', uid, criteria['expected_uid'], 'invalid UID'))
        elif criteria['expected_uid'] is None:
            checks.append(_check('owner', 'needs_review', uid, None, 'approved UID pending'))
        else:
            checks.append(_check('owner', 'pass' if uid == criteria['expected_uid'] else 'vulnerable',
                                 uid, criteria['expected_uid'], 'compare numeric UID'))
        mode = observation.get('mode')
        allowed = criteria['allowed_permission_bits']
        if not isinstance(mode, str) or not re.fullmatch(r'[0-7]{4}', mode):
            checks.append(_check('permissions', 'error', mode, allowed, 'invalid mode'))
        elif allowed is None:
            checks.append(_check('permissions', 'needs_review', mode, None,
                                 'approved allowed permission bits pending'))
            checks.append(_acl_check(observation, criteria))
        else:
            forbidden = int(mode, 8) & (~int(allowed, 8) & 0o7777)
            checks.append(_check('permissions', 'vulnerable' if forbidden else 'pass',
                                 mode, {'allowed_permission_bits': allowed,
                                        'unexpected_bits': format(forbidden, '04o')},
                                 'actual & ~allowed within 07777; special bits included'))
            checks.append(_acl_check(observation, criteria))
        gid = observation.get('gid')
        if 'allowed_groups' in criteria:
            status, expected, reason = group_check(criteria, observation, environment or {})
            checks.append(_check('group', status, gid, expected, reason))
        elif type(gid) is not int or gid < 0:
            checks.append(_check('group', 'error', gid, criteria['reference_gid'], 'invalid GID'))
        elif criteria['reference_gid'] is None:
            checks.append(_check('group', 'needs_review', gid, None, 'approved group criterion pending'))
        else:
            checks.append(_check('group', 'pass' if gid == criteria['reference_gid'] else 'needs_review',
                                 gid, {'reference_gid': criteria['reference_gid'], 'enforced': False},
                                 'project strengthening reference only; mismatch is not a violation'))
    result = dict(path=criteria['path'], actual=observation, expected=dict(criteria), checks=checks)
    gate_candidate(result, criteria)
    result['status'] = aggregate([c['status'] for c in checks])
    return result


def environment_info():
    result = {'system': platform.system(), 'release': platform.release()}
    try:
        for line in Path('/etc/os-release').read_text(encoding='utf-8').splitlines():
            key, separator, value = line.partition('=')
            if separator and key in ('ID', 'VERSION_ID', 'PRETTY_NAME'):
                result[key.lower()] = value.strip().strip('"')
    except OSError as exc:
        result['os_release_error'] = str(exc)
    try:
        import grp
        result['named_groups'] = {'shadow': grp.getgrnam('shadow').gr_gid}
        result['group_lookup_state'] = 'collected'
    except KeyError as exc:
        result['named_groups'] = {}
        result['group_lookup_state'] = 'absent'
        result['group_lookup_note'] = str(exc)
    except (ImportError, OSError) as exc:
        result['named_groups'] = {}
        result['group_lookup_state'] = 'error'
        result['group_lookup_error'] = str(exc)
    return result


def run(policy, collector=None, environment=None):
    validate_file_policy(policy)
    if environment is None:
        environment = (environment_info() if collector is None else
                       {'id': None, 'version_id': None, 'reason': 'target environment not supplied by collector'})
    collector = collect_file_info if collector is None else collector
    files = []
    for criteria in policy['criteria']['files']:
        try:
            observation = collector(criteria['path'])
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            checks = [_check('metadata', 'error', str(exc), 'readable file metadata',
                             'file observation failed')]
            files.append(dict(path=criteria['path'], status='error', actual=None,
                              expected=dict(criteria), checks=checks))
        else:
            files.append(evaluate_file(criteria, observation, environment))
    return build_result(files, policy['severity'], environment)


def build_result(files, severity, environment):
    status = aggregate([f['status'] for f in files])
    states = [check['status'] for item in files for check in item.get('checks', [])]
    summary = '; '.join('{}={}'.format(item['path'], item['status']) for item in files)
    summary = 'FILE-01: ' + summary + '. 세부 오류 {}건, 검토 필요 {}건.'.format(
        states.count('error'), states.count('needs_review'))
    return make_result('FILE-01', status, severity, summary, recommendation_for_status(status), {
        'scope': 'per-file approval gates; bounded link inspection; explicit ACL and link approvals required',
        'environment': environment,
        'files': files})


def run_from_policy(path=DEFAULT_POLICY):
    document = load_policy(path)
    environment = environment_info()
    variants = document.get('os_policy_files', {})
    if not isinstance(variants, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                           for k, v in variants.items()):
        raise PolicyError('os_policy_files must map OS/version strings to sibling file names')
    selector = environment.get('id', '') + ':' + environment.get('version_id', '')
    if selector in variants:
        filename = variants[selector]
        if not isinstance(filename, str) or Path(filename).name != filename or '/' in filename or '\\' in filename:
            raise PolicyError('OS policy must be a sibling file name')
        document = load_policy(Path(path).parent / filename)
    target = document.get('target_os')
    if target is not None and target != {'id': environment.get('id'), 'version_id': environment.get('version_id')}:
        raise PolicyError('explicit OS policy does not match target OS/version')
    policies = [p for p in document['policies'] if p['check_id'] == 'FILE-01']
    if len(policies) != 1:
        raise PolicyError('exactly one FILE-01 policy is required')
    result = run(policies[0], environment=environment)
    result['details']['policy_version'] = document['policy_version']
    result['details']['policy_metadata'] = sanitize_details(document.get('policy_metadata', {}))
    return result


def main():
    parser = argparse.ArgumentParser(description='FILE-01 read-only diagnosis')
    parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    args = parser.parse_args()
    try:
        result = run_from_policy(args.policy)
    except PolicyError as exc:
        print('Policy error: ' + sanitize_text(str(exc)), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
