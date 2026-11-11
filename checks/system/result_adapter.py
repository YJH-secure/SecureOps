"""Opt-in JSON v1.2 export for existing C diagnosis results."""

from copy import deepcopy

from .common import SEVERITIES, STATUSES, sanitize_text


REQUIRED_V11_FIELDS = frozenset({'check_id', 'status', 'severity', 'evidence', 'recommendation'})
OPTIONAL_FIELDS = frozenset({'category', 'title', 'checked_at', 'details'})
NO_ASSESSMENT_REASON = {
    'pass': '승인 기준을 충족해 CVSS 평가 대상이 아닙니다.',
    'error': '진단 오류가 발생해 취약 사례가 확인되지 않았습니다.',
    'needs_review': '정책 판정 또는 근거 확인이 남아 있어 CVSS 평가 대상이 아닙니다.',
    'not_applicable': '이 대상에는 해당 진단이 적용되지 않습니다.',
}


def add_result_version_argument(parser):
    parser.add_argument('--result-version', choices=('1.1', '1.2'), default='1.1',
                        help='JSON contract for this result item (default: 1.1)')


def adapt_result(result, version='1.1', *, policy_only_rationale=None):
    """Export a legacy result without changing its diagnosis or evidence.

    Set policy_only_rationale only for an explicitly reviewed policy-only violation.
    The adapter leaves scoring to D.
    """
    if version not in ('1.1', '1.2'):
        raise ValueError('unsupported result version')
    if version == '1.1':
        if policy_only_rationale is not None:
            raise ValueError('CVSS classification requires v1.2 output')
        return result

    if (not isinstance(result, dict) or not REQUIRED_V11_FIELDS <= result.keys()
            or not result.keys() <= REQUIRED_V11_FIELDS | OPTIONAL_FIELDS):
        raise ValueError('expected a v1.1 result item')
    status, severity = result['status'], result['severity']
    if (not isinstance(status, str) or status not in STATUSES
            or not isinstance(severity, str) or severity not in SEVERITIES):
        raise ValueError('invalid v1.1 result status or severity')

    if policy_only_rationale is not None:
        if status != 'vulnerable' or not isinstance(policy_only_rationale, str) or not policy_only_rationale.strip():
            raise ValueError('policy-only classification requires a vulnerable result and nonempty rationale')
        assessment_status = 'not_applicable'
        rationale = sanitize_text(policy_only_rationale.strip())
    elif status == 'vulnerable':
        assessment_status = 'pending'
        rationale = 'CVSS 적용 가능성과 공격 조건·영향 검토가 필요합니다.'
    else:
        assessment_status = 'not_applicable'
        rationale = NO_ASSESSMENT_REASON[status]

    exported = deepcopy(result)
    del exported['severity']
    exported['cvss'] = {'assessment_status': assessment_status, 'version': None,
                        'vector': None, 'base_score': None, 'rating': None,
                        'source': None, 'rationale': f'v1.1 {status}. {rationale}'}
    return exported
