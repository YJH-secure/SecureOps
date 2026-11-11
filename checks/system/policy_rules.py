"""OS selection and approval gates, separate from observation/SSH transport."""
from .common import PolicyError

STATES = {'approved', 'candidate', 'pending'}


def valid_identity(value):
    # bool is an int subclass, but is not a collected Unix UID/GID.
    return type(value) is int and value >= 0


def validate_extensions(item):
    if not isinstance(item.get('approval_status', 'pending'), str) or item.get('approval_status', 'pending') not in STATES:
        raise PolicyError('invalid approval_status')
    groups = item.get('allowed_groups')
    if groups is not None:
        if not isinstance(groups, list):
            raise PolicyError('allowed_groups must be an array or null')
        for group in groups:
            if not isinstance(group, dict) or set(group) != {'kind', 'value'}:
                raise PolicyError('invalid group selector')
            if group['kind'] == 'gid':
                if type(group['value']) is not int or group['value'] < 0:
                    raise PolicyError('invalid numeric group ID')
            elif group['kind'] == 'name':
                if not isinstance(group['value'], str) or not group['value'].strip():
                    raise PolicyError('invalid group name')
            else:
                raise PolicyError('invalid group selector kind')
    acl = item.get('acl_policy')
    if acl is not None:
        if not isinstance(acl, dict) or set(acl) != {
                'approval_status', 'users', 'groups', 'other_max_bits'}:
            raise PolicyError('invalid ACL policy fields')
        if not isinstance(acl['approval_status'], str) or acl['approval_status'] not in STATES:
            raise PolicyError('invalid ACL approval')
        for key in ('users', 'groups'):
            entries = acl[key]
            if entries is None:
                if acl['approval_status'] == 'approved':
                    raise PolicyError('approved ACL policy requires explicit principal lists')
                continue
            if not isinstance(entries, list):
                raise PolicyError('ACL principal list must be an array')
            seen = set()
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {'id', 'max_bits'}:
                    raise PolicyError('invalid ACL principal')
                for field in ('id', 'max_bits'):
                    if type(entry[field]) is not int or entry[field] < 0:
                        raise PolicyError('invalid ACL numeric field')
                if entry['max_bits'] > 7 or entry['id'] in seen:
                    raise PolicyError('invalid or duplicate ACL principal')
                seen.add(entry['id'])
        bits = acl['other_max_bits']
        if bits is not None and (type(bits) is not int or not 0 <= bits <= 7):
            raise PolicyError('invalid ACL other bits')
        if acl['approval_status'] == 'approved' and bits is None:
            raise PolicyError('approved ACL requires other_max_bits')
    links = item.get('link_policy')
    if links is not None:
        if not isinstance(links, dict) or set(links) != {'approval_status', 'allowed_targets'}:
            raise PolicyError('invalid link policy')
        if not isinstance(links['approval_status'], str) or links['approval_status'] not in STATES:
            raise PolicyError('invalid link approval')
        targets = links['allowed_targets']
        if targets is None:
            if links['approval_status'] == 'approved':
                raise PolicyError('approved link policy requires explicit targets')
        elif not isinstance(targets, list) or any(
                not isinstance(t, str) or not t.startswith('/etc/') or '/..' in t for t in targets):
            raise PolicyError('link targets must be absolute paths inside /etc')


def group_check(criteria, observation, environment):
    """Resolve named groups from the TARGET environment only, never assume GID 42."""
    selectors = criteria.get('allowed_groups')
    actual = observation.get('gid')
    if not valid_identity(actual):
        return ('error', {'selectors': selectors, 'reference_gid': criteria.get('reference_gid')},
                'missing or invalid numeric GID')
    if selectors is None:
        reference = criteria.get('reference_gid')
        return ('needs_review', {'reference_gid': reference, 'enforced': False},
                'approved group criterion pending')
    gids, missing = [], []
    mapping = environment.get('named_groups', {})
    for selector in selectors:
        if selector['kind'] == 'gid':
            gids.append(selector['value'])
        else:
            value = mapping.get(selector['value']) if isinstance(mapping, dict) else None
            if type(value) is int and value >= 0:
                gids.append(value)
            else:
                missing.append(selector['value'])
    expected = {'selectors': selectors, 'resolved_gids': gids, 'unresolved_names': missing}
    if actual in gids:
        return 'pass', expected, 'numeric target GID matches policy'
    if missing:
        if environment.get('group_lookup_state') == 'error':
            expected['lookup_error'] = environment.get('group_lookup_error', 'group lookup failed')
            return 'error', expected, 'required target group lookup failed'
        return 'needs_review', expected, 'target group identity could not be resolved'
    return 'vulnerable', expected, 'numeric GID outside allowed groups'


def gate_candidate(file_result, criteria):
    state = criteria.get('approval_status', 'pending')
    file_result['policy_approval_status'] = state
    if state != 'approved':
        # Preserve the calculated comparison but never label a policy candidate approved.
        for check in file_result['checks']:
            if check['status'] in ('pass', 'vulnerable') and check['name'] in ('owner', 'permissions', 'group'):
                check['candidate_comparison'] = check['status']
                check['status'] = 'needs_review'
                check['reason'] += '; candidate policy is not finally approved'
        file_result['checks'].append(dict(name='policy_approval', status='needs_review',
                                         actual=state, expected='approved',
                                         reason='final approval and deployment validation pending'))
    return file_result
