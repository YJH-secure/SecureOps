import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

root = Path.cwd()
evidence = root / 'reports/e-ssh01-phase1-20261113'
evidence.mkdir(parents=True, exist_ok=True)
label = sys.argv[1]
# Existing child-process CLI tests require UTF-8 JSON output on Windows pipes.
os.environ['PYTHONUTF8'] = '1'
os.environ['SECUREOPS_D_SOURCE'] = str(root)
suite = unittest.TestSuite()
for pattern in ('test_remediation*.py', 'test_execution_history*.py', 'test_cvss*.py'):
    suite.addTests(unittest.defaultTestLoader.discover('tests', pattern=pattern))
suite.addTests(unittest.defaultTestLoader.loadTestsFromNames([
    'checks.system.tests.test_firewall_check', 'checks.system.tests.test_log_check']))
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
log = stream.getvalue().replace(str(root), '<WORKTREE>')
(evidence / (label + '.log')).write_text(log, encoding='utf-8')
summary = dict(tests_run=result.testsRun, passed=result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
               failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
(evidence / (label + '.json')).write_text(json.dumps(summary, indent=2), encoding='utf-8')
print(json.dumps(summary))
if not result.wasSuccessful():
    print(log[-10000:])
sys.exit(not result.wasSuccessful())
