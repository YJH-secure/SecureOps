"""Explicit offline suite: fail closed when frozen external sources are absent.

No __init__.py: generic main discovery must not silently depend on local sources.
Run this file explicitly with the five SECUREOPS_DE_* variables in README.md.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def main():
    roots = {key: Path(os.environ['SECUREOPS_DE_' + key]).resolve()
             for key in ('E_ROOT', 'C_ROOT', 'BRIDGE_ROOT', 'CALLBACK_FILE', 'RESULTS_DIR')}
    manifest = json.loads(Path(__file__).with_name('sources.json').read_text(encoding='utf-8'))
    checked = []
    for entry in manifest['files']:
        base = roots[entry['root']]
        path = base / entry['path'] if base.is_dir() else base
        raw = path.read_bytes()
        lf = raw.replace(b'\r\n', b'\n')
        sha = hashlib.sha256(raw).hexdigest()
        if 'sha256' in entry and sha != entry['sha256']:
            raise ValueError('frozen SHA-256 mismatch: ' + entry['path'])
        blob = hashlib.sha1(b'blob ' + str(len(lf)).encode() + b'\0' + lf).hexdigest()
        if 'git_blob_lf' in entry and blob != entry['git_blob_lf']:
            raise ValueError('frozen E Git blob mismatch: ' + entry['path'])
        checked.append(dict(entry, actual_sha256=sha, actual_lf_blob=blob))
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(roots['E_ROOT']), str(roots['BRIDGE_ROOT']), str(ROOT)]
    import checks
    import checks.system
    checks.system.__path__.insert(0, str(roots['C_ROOT'] / 'checks' / 'system'))
    import core
    name = 'core.file01_mock_callback'
    spec = importlib.util.spec_from_file_location(name, roots['CALLBACK_FILE'])
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    setattr(core, 'file01_mock_callback', module)
    out = roots['RESULTS_DIR']
    out.mkdir(parents=True, exist_ok=True)
    os.environ['SECUREOPS_DE_OBSERVATIONS'] = str(out / 'observations')
    class Result(unittest.TextTestResult):
        records = []
        def addSuccess(self, test):
            super().addSuccess(test)
            self.records.append(dict(id=test.id(), result='PASS'))
        def addFailure(self, test, err):
            super().addFailure(test, err)
            self.records.append(dict(id=test.id(), result='FAIL'))
        def addError(self, test, err):
            super().addError(test, err)
            self.records.append(dict(id=test.id(), result='ERROR'))
        def addSkip(self, test, reason):
            super().addSkip(test, reason)
            self.records.append(dict(id=test.id(), result='SKIP'))
    suite = unittest.defaultTestLoader.discover(str(Path(__file__).parent), pattern='test_*.py')
    guards = [patch(name, side_effect=AssertionError('offline suite: live operation forbidden'), create=True)
              for name in ('subprocess.Popen', 'subprocess.run', 'socket.create_connection',
                           'socket.socket.connect', 'os.chmod', 'os.chown')]
    for guard in guards:
        guard.start()
    stream = io.StringIO()
    try:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    finally:
        for guard in reversed(guards):
            guard.stop()
    log = stream.getvalue()
    (out / 'unittest.log').write_text(log, encoding='utf-8')
    imports = {name: getattr(sys.modules.get(name), '__file__', None) for name in
               ('core.main', 'core.storage', 'core.file01_mock_callback', 'remediation.engine',
                'remediation.recheck', 'checks.system.file_check', 'file01_pilot.c_mock_bridge')}
    # Published evidence uses symbolic roots; private local paths stay outside Git.
    imports = {k: next((v.replace(str(base.parent if key == 'CALLBACK_FILE' else base), '<' + key + '>')
                       for key, base in roots.items() if v and str(base.parent if key == 'CALLBACK_FILE' else base) in v),
                      v.replace(str(ROOT), '<D_ROOT>') if v else None) for k, v in imports.items()}
    data = dict(python=platform.python_version(), platform=platform.system(),
                tested=result.testsRun, passed=result.testsRun-len(result.failures)-len(result.errors)-len(result.skipped),
                failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
                exit_code=0 if result.wasSuccessful() else 1, tests=Result.records,
                imports=imports, sources=checked, command='python -B tests/offline_de/run_tests.py')
    (out / 'results.json').write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(log)
    return data['exit_code']


if __name__ == '__main__':
    sys.exit(main())
