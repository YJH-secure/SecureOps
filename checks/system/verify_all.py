"""One-command LOCAL Linux verification. No SSH, Git writes or system-file changes.

python3 -m checks.system.verify_all
"""
import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from .common import sanitize_text
from .file_check import run_from_policy
from .validate_result import validate, DEFAULT_SCHEMA
from .verify_fixtures import execute as verify_temporary_files

ROOT=Path(__file__).resolve().parents[2]


def _write(path,data):
    path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def _preflight():
    if platform.system()!='Linux':
        raise RuntimeError('Run this command inside your Linux VM.')
    missing=[tool for tool in ('getfacl','setfacl') if shutil.which(tool) is None]
    if missing:
        raise RuntimeError('Missing '+', '.join(missing)+'. On Ubuntu: sudo apt install acl')
    schema=json.loads(DEFAULT_SCHEMA.read_text(encoding='utf-8'))
    sample=json.loads((ROOT/'tests/fixtures/sample-result-v1.1-MOCK.json').read_text(encoding='utf-8'))
    errors=validate(sample,schema)
    if errors:
        raise RuntimeError('Pinned MOCK schema preflight failed: '+'; '.join(errors))


def _run_unit_tests(folder):
    completed=subprocess.run([sys.executable,'-B','-m','unittest','discover',
                              '-s','checks/system/tests','-v'],cwd=str(ROOT),
                             capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=180)
    log=completed.stdout+'\n'+completed.stderr
    (folder/'unit-tests.txt').write_text(log,encoding='utf-8')
    if completed.returncode:
        raise RuntimeError('Unit tests failed. See unit-tests.txt; dependent stages were not run.')
    match=re.search(r'Ran (\d+) tests?',log)
    if not match or int(match.group(1))==0:
        raise RuntimeError('No unit tests were confirmed as executed; see unit-tests.txt.')
    print('Unit tests passed: '+match.group(1)+' (full log: unit-tests.txt)')
    return {'tests_run':int(match.group(1)),'exit_code':completed.returncode}


def _run_diagnosis(folder):
    result=run_from_policy()
    _write(folder/'file01-result.json',result)
    print('Actual local FILE-01 status: '+result['status']+' (not a verification pass/fail label)')
    return result


def _run_fixtures(folder):
    code=verify_temporary_files(folder/'file01-fixture-evidence.json')
    if code:
        raise RuntimeError('Temporary ACL/link scenarios did not all match; inspect their evidence JSON.')
    report=json.loads((folder/'file01-fixture-evidence.json').read_text(encoding='utf-8'))
    return {'exit_code':code,'cases':report['cases'],'matched':report['matched']}


def _validate_outputs(folder):
    schema=json.loads(DEFAULT_SCHEMA.read_text(encoding='utf-8'))
    actual=json.loads((folder/'file01-result.json').read_text(encoding='utf-8'))
    fixture=json.loads((folder/'file01-fixture-evidence.json').read_text(encoding='utf-8'))
    scenarios=fixture.get('scenarios')
    if not isinstance(scenarios,list) or not scenarios or fixture.get('cases')!=len(scenarios):
        raise RuntimeError('Invalid temporary-file verification report')
    for label,item in [('actual FILE-01',actual)]+[
            ('fixture '+str(i+1),item) for i,item in enumerate(scenarios)]:
        errors=validate(item,schema)
        if errors:
            raise RuntimeError(label+' schema failure: '+'; '.join(errors))
    print('Schema validated C result items: '+str(len(scenarios)+1))
    return {'validated_result_items':len(scenarios)+1,'schema_version':'1.1'}


def execute(output_dir=None):
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S_%fZ')
    folder=Path(output_dir).resolve() if output_dir else (Path.cwd()/'verification-runs'/stamp).resolve()
    folder.mkdir(parents=True,mode=0o700)  # Refuse an existing directory; never overwrite prior evidence.
    report={'kind':'FILE-01 LOCAL verification run (not a D scan report)',
            'started_at':datetime.now(timezone.utc).isoformat(),
            'notice':'Verification success does not mean the system is secure or policies approved.',
            'stages':{},'operational_status':None}

    def stage(name,action):
        print('\n== '+name+' ==',flush=True)
        try:
            value=action()
        except Exception as exc:
            message=sanitize_text(str(exc))
            report['stages'][name]={'status':'fail','error':message,'error_type':type(exc).__name__}
            (folder/(name+'-error.txt')).write_text(sanitize_text(traceback.format_exc()),encoding='utf-8')
            print('[FAIL] '+message,flush=True)
            return None
        report['stages'][name]={'status':'pass'}
        print('[OK] '+name,flush=True)
        return value

    def finish():
        required=('preflight','unit-tests','actual-diagnosis','temporary-acl-links','json-schema')
        for name in required:
            report['stages'].setdefault(name,{'status':'not_run'})
        ok=all(report['stages'][name]['status']=='pass' for name in required)
        report['verification_success']=ok
        report['finished_at']=datetime.now(timezone.utc).isoformat()
        _write(folder/'verification-summary.json',report)
        print('\nVerification '+('completed successfully' if ok else 'has failures or unfinished stages'))
        print('Actual FILE-01 status: '+str(report['operational_status']))
        print('Evidence folder: '+str(folder))
        print('No SSH/Git operations or passwd/shadow setting changes were performed.')
        return 0 if ok else 1

    stage('preflight',_preflight)
    if report['stages']['preflight']['status']!='pass':
        return finish()
    unit=stage('unit-tests',lambda:_run_unit_tests(folder))
    if unit is None:
        return finish()
    report['stages']['unit-tests'].update(unit)
    actual=stage('actual-diagnosis',lambda:_run_diagnosis(folder))
    if actual is not None:
        report['operational_status']=actual['status']
        files=actual['details']['files']
        if any(check['status']=='error' for item in files for check in item.get('checks',[])):
            report['stages']['actual-diagnosis']['status']='fail'
            report['stages']['actual-diagnosis']['error']='Acquisition/check errors remain in actual FILE-01 details.'
            print('[FAIL] Actual diagnosis contains errors; continuing independent fixture checks.')
    fixtures=stage('temporary-acl-links',lambda:_run_fixtures(folder))
    if fixtures is not None:
        report['stages']['temporary-acl-links'].update(fixtures)
    schema=stage('json-schema',lambda:_validate_outputs(folder))
    if schema is not None:
        report['stages']['json-schema'].update(schema)
    return finish()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',type=Path,help='New directory for private evidence; must not already exist')
    args=parser.parse_args()
    try:
        return execute(args.output_dir)
    except OSError as exc:
        print('Cannot create/write evidence folder: '+sanitize_text(str(exc)),file=sys.stderr)
        return 2


if __name__=='__main__':
    sys.exit(main())
