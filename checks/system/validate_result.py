"""Read-only developer validation against the pinned main schema (not D aggregation).

python3 -m pip install 'jsonschema[format]'
python3 -m checks.system.validate_result file01-result.json
"""
import argparse
import json
import sys
from pathlib import Path

DEFAULT_SCHEMA = Path(__file__).resolve().parents[2] / 'docs/architecture/json-result-schema-v1.1.schema.json'


def validate(data, schema):
    try:
        from jsonschema import Draft202012Validator, FormatChecker
    except ImportError as exc:
        raise RuntimeError("Install the optional developer dependency: python3 -m pip install 'jsonschema[format]'") from exc
    Draft202012Validator.check_schema(schema)
    checker = FormatChecker()
    # Do not silently skip date-time checks when optional format dependencies are missing.
    probe = Draft202012Validator({'format':'date-time'}, format_checker=checker)
    if not list(probe.iter_errors('2026-11-06T10:00:00')):
        raise RuntimeError("date-time checker unavailable; install 'jsonschema[format]'")
    report = isinstance(data,dict) and 'results' in data
    selected = schema if report else {'$ref':'#/$defs/checkResult','$defs':schema['$defs']}
    errors = ['{}: {}'.format('/'.join(map(str,e.absolute_path)) or '$',e.message)
              for e in Draft202012Validator(selected,format_checker=checker).iter_errors(data)]
    if not errors and report:
        ids = [item['check_id'] for item in data['results']]
        if len(ids) != len(set(ids)):
            errors.append('Duplicate check_id in one scan report')
    return errors


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('data',type=Path)
    parser.add_argument('--schema',type=Path,default=DEFAULT_SCHEMA)
    parser.add_argument('--fixture-report',action='store_true',
                        help='Validate each scenario result in the temporary-file test report; not a D scan report')
    args=parser.parse_args()
    try:
        schema=json.loads(args.schema.read_text(encoding='utf-8'))
        data=json.loads(args.data.read_text(encoding='utf-8'))
        if args.fixture_report:
            scenarios=data.get('scenarios') if isinstance(data,dict) else None
            if not isinstance(scenarios,list) or not scenarios or data.get('cases') != len(scenarios):
                raise ValueError('Invalid fixture report: expected nonempty scenarios and matching cases')
            errors=[]
            for index,item in enumerate(scenarios):
                errors.extend('scenario {}: {}'.format(index,error) for error in validate(item,schema))
        else:
            errors=validate(data,schema)
    except (OSError,ValueError,RuntimeError) as exc:
        print('Validation could not complete: '+str(exc),file=sys.stderr)
        return 2
    if errors:
        print('\n'.join(errors))
        return 1
    print('JSON v1.1 validation PASS' + (' (individual fixture scenario results)' if args.fixture_report else
                                      ' (schema; duplicate check_id for full scan reports)'))
    print('Actual D integration, scan-history uniqueness and full sensitive-data audit remain separate.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
