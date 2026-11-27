"""Explicit offline job; no install, source copying, network or forced skip."""
import datetime
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
value = os.environ.get('SECUREOPS_ABD_DEPS_ROOT')
if not value:
    raise SystemExit('SECUREOPS_ABD_DEPS_ROOT is required; this job never skips missing dependencies')
DEPS = Path(value).resolve()
manifest = json.loads((HERE/'dependencies.json').read_text())
for name, expected in manifest['files'].items():
    p = DEPS/name
    if not p.is_file() or hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest()!=expected['lf_sha256']:
        raise SystemExit('Missing or mismatched frozen dependency: '+name)
for name, expected in manifest['core_lf_sha256'].items():
    if hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n',b'\n')).hexdigest()!=expected:
        raise SystemExit('D base mismatch: '+name)
sys.path[:0] = [str(ROOT),str(HERE),str(DEPS/'checks/account')]
spec = importlib.util.spec_from_file_location('integration',DEPS/'integration/__init__.py',
                                            submodule_search_locations=[str(DEPS/'integration')])
package = importlib.util.module_from_spec(spec)
sys.modules['integration'] = package
spec.loader.exec_module(package)

class Recorded(unittest.TextTestResult):
    def __init__(self,*args,**kw):
        super().__init__(*args,**kw);self.rows=[]
    def addSuccess(self,test):
        super().addSuccess(test);self.rows.append({'id':test.id(),'result':'PASS'})
    def addFailure(self,test,err):
        super().addFailure(test,err);self.rows.append({'id':test.id(),'result':'FAIL'})
    def addError(self,test,err):
        super().addError(test,err);self.rows.append({'id':test.id(),'result':'ERROR'})
    def addSkip(self,test,reason):
        super().addSkip(test,reason);self.rows.append({'id':test.id(),'result':'SKIP','reason':reason})

started = datetime.datetime.now(datetime.timezone.utc).isoformat()
suite = unittest.defaultTestLoader.loadTestsFromName('test_abd_diagnosis')
result = unittest.TextTestRunner(verbosity=2,resultclass=Recorded).run(suite)
import test_abd_diagnosis
from orchestration import abd_diagnosis
from integration import a_ssh_transport,bd_collector_adapter
import collector_entry,core.main,core.storage
code = 0 if result.wasSuccessful() else 1
summary = {'kind':'new receipt-wrapper isolated MOCK, not the prior 21 tests',
 'started_utc':started,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'command':'python -B -X utf8 tests/offline_abd/run_tests.py',
 'python':sys.version,'jsonschema':importlib.metadata.version('jsonschema'),
 'tests_run':result.testsRun,'PASS':sum(r['result']=='PASS' for r in result.rows),
 'FAIL':len(result.failures),'ERROR':len(result.errors),'SKIP':len(result.skipped),
 'exit_code':code,'tests':result.rows,
 'imports':{m.__name__:m.__file__ for m in [abd_diagnosis,a_ssh_transport,bd_collector_adapter,collector_entry,core.main,core.storage]},
 'network_or_SSH_used':False,'metadata_writer_implemented':False}
outdir = os.environ.get('SECUREOPS_ABD_RESULTS_DIR')
if outdir:
    p=Path(outdir);p.mkdir(parents=True,exist_ok=True)
    for name,data in [('results.json',summary),('observations.json',test_abd_diagnosis.OBSERVATIONS)]:
        target=p/name
        if target.exists():raise SystemExit('Existing result file, refuse overwrite: '+name)
        target.write_text(json.dumps(data,ensure_ascii=True,indent=2),encoding='utf-8')
print(json.dumps({k:summary[k] for k in ['tests_run','PASS','FAIL','ERROR','SKIP','exit_code']}))
sys.exit(code)
