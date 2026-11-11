"""Verify C JSON v1.2 MOCK scenarios against an explicitly selected D checkout."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch

from . import scenario_inputs as v11_inputs
from checks.system.result_adapter import adapt_result
from checks.system.validate_result import DEFAULT_SCHEMA, validate

ROOT = Path(__file__).resolve().parents[2]
SCENARIOS = Path(__file__).with_name('scenarios')
FIELDS = ('check_id', 'status', 'evidence', 'recommendation', 'cvss')
METRICS = v11_inputs.METRICS
CVSS_FIELDS = {'assessment_status', 'version', 'vector', 'base_score', 'rating', 'source', 'rationale'}
UNSCORED = ('version', 'vector', 'base_score', 'rating', 'source')
ASSESSMENTS = {'pass': 'not_applicable', 'vulnerable': 'pending', 'error': 'not_applicable',
               'needs_review': 'not_applicable', 'not_applicable': 'not_applicable'}
write_json = v11_inputs.write_json


def receive(result, schema_version='1.2', exit_code=0, execution_succeeded=True):
    from core.remote_result import parse_result_json
    return parse_result_json(json.dumps(result, ensure_ascii=False), exit_code=exit_code,
                             execution_succeeded=execution_succeeded, schema_version=schema_version)


def verify_d(result, case_id, folder, schema):
    from core.runner import run_target
    from core.storage import ReportStore
    item = receive(result)
    outcome = run_target(account_checks=[], system_checks=[lambda: item], mode='mock',
                         target_id='scenario-target-mock', os='ubuntu-24.04',
                         scan_id='scan-v12-' + case_id, scanned_at='2026-11-11T00:00:00Z',
                         schema_version='1.2', output_root=folder)
    saved = ReportStore(folder / 'mock').load('scenario-target-mock', outcome.report['scan_id'])
    if saved != outcome.report or saved['results'] != [result] or validate(saved, schema):
        raise AssertionError('D did not preserve a valid v1.2 report')
    for status, metric in METRICS.items():
        if outcome.summary['metrics'][metric] != int(status == result['status']):
            raise AssertionError('D diagnostic status count differs')
    expected = dict.fromkeys(('pending', 'not_applicable', 'scored'), 0)
    expected[result['cvss']['assessment_status']] = 1
    if outcome.summary['cvss_assessment_breakdown'] != expected:
        raise AssertionError('D CVSS assessment count differs')
    if any(outcome.summary['cvss_rating_breakdown'].values()):
        raise AssertionError('Unscored findings received a CVSS rating count')
    write_json(folder / (case_id + '-report.json'), saved)
    return {'passed': True, 'kind': 'local MOCK reference check',
            'full_result_preserved': True, 'metrics': outcome.summary['metrics'],
            'cvss_assessment_breakdown': outcome.summary['cvss_assessment_breakdown']}


def verify_case(case, folder, schema_v11, schema_v12):
    folder.mkdir()
    write_json(folder / 'scenario.json', case)
    write_json(folder / 'input.json', case['inputs'])
    write_json(folder / 'expected-v11.json', case['expected_v11'])
    write_json(folder / 'expected-v12.json', case['expected'])
    check = {'scenario_id': case['id'], 'execution_kind': case['execution_kind'],
             'expected_status': case['expected']['status'], 'passed': False,
             'official_integration_verified': False}
    try:
        with TemporaryDirectory() as temporary:
            with patch('subprocess.run', side_effect=AssertionError('Real commands are disabled')):
                legacy = v11_inputs.RUNNERS[case['runner']](case, Path(temporary))
        write_json(folder / 'actual-v11.json', legacy)
        if validate(legacy, schema_v11):
            raise AssertionError('Legacy result schema is invalid')
        if {field: legacy[field] for field in v11_inputs.FIELDS} != case['expected_v11']:
            raise AssertionError('Legacy result differs from v1.1 expectation')

        original = deepcopy(legacy)
        exported = adapt_result(legacy, '1.2')
        write_json(folder / 'actual-v12.json', exported)
        if legacy != original:
            raise AssertionError('The adapter mutated its v1.1 input')
        for field in ('check_id', 'status', 'evidence', 'recommendation', 'details'):
            if exported.get(field) != legacy.get(field):
                raise AssertionError('Legacy field changed: ' + field)
        if 'severity' in exported or 'cvss' in legacy:
            raise AssertionError('Version fields leaked')
        if validate(exported, schema_v12) or validate(case['expected'], schema_v12):
            raise AssertionError('Expected or actual v1.2 result has invalid schema')
        if {field: exported[field] for field in FIELDS} != case['expected']:
            raise AssertionError('Required v1.2 fields differ from declared expectation')
        cvss = exported['cvss']
        if set(cvss) != CVSS_FIELDS or cvss['assessment_status'] != ASSESSMENTS[legacy['status']]:
            raise AssertionError('CVSS fields or assessment status differ')
        if any(cvss[field] is not None for field in UNSCORED):
            raise AssertionError('Unscored result contains a score, vector, rating or source')
        if not isinstance(cvss['rationale'], str) or not cvss['rationale'].strip():
            raise AssertionError('Unscored rationale is empty')
        for condition in case['details_checks']:
            value = exported
            for part in condition['path']:
                value = value[part]
            if value != condition['equals']:
                raise AssertionError('Detailed evidence differs')
        # Legacy severity is not a CVSS input.
        alternate = deepcopy(legacy)
        alternate['severity'] = 'low' if legacy['severity'] != 'low' else 'critical'
        if adapt_result(alternate, '1.2') != exported:
            raise AssertionError('Legacy severity influenced CVSS output')
        check.update(v11_regression=True, v12_schema=True, evidence_details_preserved=True,
                     cvss_nulls=True, legacy_severity_not_converted=True,
                     actual_status=exported['status'], assessment_status=cvss['assessment_status'])
        check['d_reference_mock'] = verify_d(exported, case['id'], folder, schema_v12)
        check['passed'] = True
    except Exception as error:
        check.update(error_type=type(error).__name__, error=str(error))
    write_json(folder / 'test-result.json', check)
    return check


def rejected_inputs(items):
    invalid = []
    for status in ('pass', 'error', 'needs_review', 'not_applicable'):
        for assessment in ('pending', 'scored'):
            item = deepcopy(items[status])
            item['cvss']['assessment_status'] = assessment
            invalid.append((status + '-with-' + assessment, item))
    item = deepcopy(items['vulnerable'])
    item['cvss']['assessment_status'] = 'scored'
    invalid.append(('scored-with-null-metrics', item))
    for status in ('vulnerable', 'pass'):
        for field, value in (('version', '3.1'), ('vector', 'INVALID-MOCK-VECTOR'),
                             ('base_score', 7.5), ('rating', 'high')):
            item = deepcopy(items[status])
            item['cvss'][field] = value
            invalid.append((status + '-unscored-with-' + field, item))
    item = deepcopy(items['vulnerable'])
    item['severity'] = 'high'
    invalid.append(('legacy-severity-in-v12', item))
    item = deepcopy(items['vulnerable'])
    del item['cvss']
    invalid.append(('missing-cvss', item))
    item = deepcopy(items['vulnerable'])
    del item['cvss']['rationale']
    invalid.append(('missing-rationale', item))
    item = deepcopy(items['vulnerable'])
    item['cvss']['rationale'] = ''
    invalid.append(('empty-rationale', item))
    item = deepcopy(items['vulnerable'])
    item['cvss']['assessment_status'] = 'unknown'
    invalid.append(('unknown-assessment-status', item))
    return invalid


def verify_rejections(items, folder, schema):
    from core.remote_result import RemoteResultError, parse_result_json
    results = []
    for name, invalid in rejected_inputs(items):
        schema_rejected = bool(validate(invalid, schema))
        try:
            receive(invalid)
        except RemoteResultError:
            d_rejected = True
        else:
            d_rejected = False
        results.append({'case': name, 'input': invalid, 'expected': 'reject',
                        'schema_rejected': schema_rejected, 'd_rejected': d_rejected,
                        'passed': schema_rejected and d_rejected})
    raw = json.dumps(items['pass'], ensure_ascii=False)
    streams = (
        ('invalid-json', '{', 0, True, '1.2'),
        ('duplicate-key', '{"check_id":"FILE-01","check_id":"SVC-01"}', 0, True, '1.2'),
        ('nonstandard-number', '{"value":NaN}', 0, True, '1.2'),
        ('nonzero-exit', raw, 2, True, '1.2'),
        ('transport-failure', raw, 0, False, '1.2'),
        ('v12-sent-to-v11-receiver', raw, 0, True, '1.1'),
    )
    for name, text, code, succeeded, version in streams:
        try:
            parse_result_json(text, exit_code=code, execution_succeeded=succeeded,
                              schema_version=version)
        except RemoteResultError:
            rejected = True
        else:
            rejected = False
        results.append({'case': name, 'kind': 'MOCK input or delivery failure',
                        'expected': 'reject', 'd_rejected': rejected, 'passed': rejected})
    write_json(folder / 'rejection-tests.json', {'kind': 'invalid synthetic inputs',
                                               'cases': len(results),
                                               'passed': sum(row['passed'] for row in results),
                                               'results': results})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, help='New folder, must not exist')
    parser.add_argument('--d-root', type=Path, default=ROOT)
    parser.add_argument('--code-commit', help='Reference label only; verify source hashes separately')
    args = parser.parse_args()
    sys.path.insert(0, str(args.d_root.resolve()))
    cases = json.loads((SCENARIOS / 'v1.2.json').read_text(encoding='utf-8'))
    legacy_cases = json.loads((SCENARIOS / 'v1.1.json').read_text(encoding='utf-8'))
    if len(cases) != 5 or {case['expected']['status'] for case in cases} != set(METRICS):
        raise ValueError('Exactly five status scenarios are required')
    if any(new['inputs'] != old['inputs'] for new, old in zip(cases, legacy_cases)):
        raise ValueError('Original v1.1 fixture inputs changed')
    schema_v11 = json.loads(DEFAULT_SCHEMA.read_text(encoding='utf-8'))
    schema_v12 = json.loads(DEFAULT_SCHEMA.with_name('json-result-schema-v1.2.schema.json')
                           .read_text(encoding='utf-8'))
    validate({}, schema_v11)
    validate({}, schema_v12)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    folder = args.output_dir or ROOT / 'verification-runs' / 'json-v12' / stamp
    folder.mkdir(parents=True, mode=0o700)
    results = []
    for case in cases:
        result = verify_case(case, folder / case['id'], schema_v11, schema_v12)
        results.append(result)
        label = 'OK' if result['passed'] else 'FAIL'
        print(f'[{label}] {case["id"]}: {case["expected"]["status"]} / '
              f'{case["expected"]["cvss"]["assessment_status"]}')
    positive = sum(item['passed'] for item in results)
    negatives = []
    if positive == 5:
        items = {case['expected']['status']: json.loads(
            (folder / case['id'] / 'actual-v12.json').read_text(encoding='utf-8')) for case in cases}
        negatives = verify_rejections(items, folder, schema_v12)
    rejected = sum(item['passed'] for item in negatives)
    summary = {'kind': 'C JSON v1.2 MOCK scenarios, counterpart and live integration tracked separately',
               'executed_at': datetime.now(timezone.utc).isoformat(),
               'scenarios': 5, 'passed': positive, 'rejection_cases': len(negatives),
               'rejection_passed': rejected, 'results': results,
               'code_commit_reference': args.code_commit, 'commit_label_verified_by_runner': False,
               'ssh_executed': False,
               'operational_policy_approval': False, 'scored_scenarios': 0}
    write_json(folder / 'summary.json', summary)
    print(f'v1.2 scenarios passed: {positive}/5')
    print(f'Invalid inputs rejected: {rejected}/{len(negatives)}')
    print(f'Evidence folder: {folder.resolve()}')
    return 0 if positive == 5 and negatives and rejected == len(negatives) else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
