"""Shared envelope validation; each checker validates its own criteria."""
import json
import re
from pathlib import Path

STATUSES = frozenset({'pass', 'vulnerable', 'error', 'not_applicable', 'needs_review'})
SEVERITIES = frozenset({'critical', 'high', 'medium', 'low'})


class PolicyError(ValueError):
    pass


def _text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(label + ' must be a nonempty string')


def validate_policy(policy):
    if not isinstance(policy, dict):
        raise PolicyError('policy must be an object')
    for key in ('check_id', 'description', 'severity', 'criteria'):
        if key not in policy:
            raise PolicyError('missing ' + key)
    for key in ('check_id', 'description', 'severity'):
        _text(policy[key], key)
    if policy['severity'] not in SEVERITIES:
        raise PolicyError('unsupported severity')
    if not isinstance(policy['criteria'], dict):
        raise PolicyError('criteria must be an object')
    # applies_to shape is not approved yet: preserve without interpretation.
    return policy


def validate_document(document):
    if not isinstance(document, dict):
        raise PolicyError('document must be an object')
    _text(document.get('policy_version'), 'policy_version')
    if not isinstance(document.get('policies'), list):
        raise PolicyError('policies must be an array')
    seen = set()
    for policy in document['policies']:
        validate_policy(policy)
        if policy['check_id'] in seen:
            raise PolicyError('duplicate check_id')
        seen.add(policy['check_id'])
    return document


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError('duplicate JSON key: ' + key)
        result[key] = value
    return result


def load_policy(path):
    try:
        document = json.loads(Path(path).read_text(encoding='utf-8'),
                              object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError) as exc:
        raise PolicyError('cannot load policy: ' + str(exc)) from exc
    return validate_document(document)


def sanitize_text(value):
    """Best-effort output minimization; not a complete sensitive-data detector."""
    value = re.sub(r'-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----',
                   '[REDACTED PRIVATE KEY]', value, flags=re.S)
    value = re.sub(r'(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+', 'Bearer [REDACTED]', value)
    value = re.sub(r'''(?i)(\b(?:password|token|secret|cookie|authorization|private_key)\b["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)''',
                   r'\1[REDACTED]', value)
    value = re.sub(r'/home/[^/\s]+', '/home/[USER]', value)
    value = re.sub(r'(?i)([A-Z]:[\\/]Users[\\/])[^\\/\s]+', r'\1[USER]', value)
    return value


def sanitize_details(value):
    # Names are unnecessary for numeric UID/GID decisions. Policy change history
    # remains in the source policy file, rather than the exported scan details.
    omit = {'owner', 'group', 'proposed_by', 'approved_by', 'implemented_by', 'tested_by'}
    secrets = {'password', 'passwd', 'private_key', 'token', 'secret', 'cookie',
               'authorization', 'access_token', 'refresh_token', 'api_key', 'credentials'}
    if isinstance(value, dict):
        return {key: ('[REDACTED]' if key.lower() in secrets else sanitize_details(item))
                for key, item in value.items() if key.lower() not in omit}
    if isinstance(value, list):
        return [sanitize_details(item) for item in value]
    return sanitize_text(value) if isinstance(value, str) else value


def recommendation_for_status(status):
    return {
        'pass': '승인된 설정을 유지하고 변경 후 다시 진단하세요.',
        'vulnerable': '위반 근거를 검토하고 관리자 승인·백업 후 별도 조치 절차를 진행하세요.',
        'error': '조회·권한·파싱 오류를 확인하고 수정 후 다시 진단하세요.',
        'needs_review': '정책 승인 상태·예외 및 상세 근거를 검토한 뒤 재판정하세요.',
        'not_applicable': '승인된 적용 제외 사유를 확인하고 기록을 유지하세요.'
    }[status]


def make_result(check_id, status, severity, evidence, recommendation, details=None):
    _text(check_id, 'check_id')
    if not isinstance(status, str) or status not in STATUSES:
        raise ValueError('unsupported status')
    if not isinstance(severity, str) or severity not in SEVERITIES:
        raise ValueError('unsupported severity')
    _text(evidence, 'evidence')
    _text(recommendation, 'recommendation')
    result = dict(check_id=check_id, status=status, severity=severity,
                  evidence=sanitize_text(evidence), recommendation=sanitize_text(recommendation))
    if details is not None:
        if not isinstance(details, dict):
            raise ValueError('details must be an object')
        normalized = json.loads(json.dumps(details, allow_nan=False))
        result['details'] = sanitize_details(normalized)
    json.dumps(result, allow_nan=False)
    return result
