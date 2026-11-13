import json
import os
from pathlib import Path
import subprocess
import sys

root = Path.cwd()
rows = []
for mode in ('default', 'utf8'):
    env = dict(os.environ)
    env.pop('PYTHONIOENCODING', None)
    env.pop('PYTHONUTF8', None)
    if mode == 'utf8':
        env['PYTHONUTF8'] = '1'
    encoding = subprocess.check_output([sys.executable, '-c', 'import sys; print(sys.stdout.encoding)'], env=env).decode('ascii').strip()
    output = subprocess.check_output([sys.executable, '-B', '-m', 'remediation', '--mock', '--result-version', '1.2'], env=env)
    try:
        result = json.loads(output)
        rows.append(dict(mode=mode, stdout_encoding=encoding, utf8_json=True, outcome=result['outcome']))
    except UnicodeDecodeError as exc:
        decoded = json.loads(output.decode(encoding))
        rows.append(dict(mode=mode, stdout_encoding=encoding, utf8_json=False,
                         error=type(exc).__name__, outcome_when_decoded_with_stdout_encoding=decoded['outcome']))
path = root / 'reports/e-ssh01-phase1-20261113' / (sys.argv[1] + '-encoding.json')
path.write_text(json.dumps(rows, ensure_ascii=True, indent=2), encoding='utf-8')
print(json.dumps(rows))
