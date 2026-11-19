"""LOG-01 read-only logging configuration and metadata inventory."""

import argparse
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

from .common import PolicyError, load_policy, make_result, recommendation_for_status
from .result_adapter import adapt_result, add_result_version_argument
from .service_check import _read_command, read_target_os


CHECK_ID = 'LOG-01'
DEFAULT_POLICY = Path(__file__).resolve().parent / 'policies/log_policy.json'
UNIT_PROPERTIES = ('LoadState', 'ActiveState', 'UnitFileState')
UNITS = ('systemd-journald.service', 'rsyslog.service', 'logrotate.timer')
JOURNAL_CONFIG = ('systemd-analyze', '--no-pager', 'cat-config', 'systemd/journald.conf')
JOURNAL_USAGE = ('journalctl', '--no-pager', '--disk-usage')
JOURNAL_PATHS = ('/var/log/journal', '/run/log/journal')
LOG_PATHS = {
    'ubuntu': ('/var/log/auth.log', '/var/log/syslog'),
    'rocky': ('/var/log/secure', '/var/log/messages'),
}
JOURNAL_KEYS = frozenset({'Storage', 'SystemMaxUse', 'SystemKeepFree', 'SystemMaxFileSize',
                          'SystemMaxFiles', 'RuntimeMaxUse', 'RuntimeKeepFree', 'RuntimeMaxFileSize',
                          'RuntimeMaxFiles', 'MaxRetentionSec', 'MaxFileSec', 'ForwardToSyslog'})
ROTATE_FLAGS = frozenset({'hourly', 'daily', 'weekly', 'monthly', 'yearly', 'compress',
                          'nocompress', 'delaycompress', 'nodelaycompress'})
ROTATE_VALUES = frozenset({'rotate', 'maxage', 'size', 'minsize', 'maxsize', 'minutes',
                           'weekly', 'monthly', 'yearly'})
SCRIPT_DIRECTIVES = frozenset({'prerotate', 'postrotate', 'firstaction', 'lastaction', 'preremove'})


def unit_command(unit):
    return ('systemctl', '--system', '--no-pager', 'show') + tuple(
        '--property=' + key for key in UNIT_PROPERTIES) + (unit,)


def parse_unit_state(output):
    properties = {}
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        if key in UNIT_PROPERTIES and separator:
            if key in properties or value and not re.fullmatch(r'[a-z0-9_-]+', value):
                raise ValueError('invalid systemd unit property')
            properties[key] = value or None
    if not properties.get('LoadState') or not properties.get('ActiveState'):
        raise ValueError('systemd unit state is incomplete')
    return {key: properties.get(key) for key in UNIT_PROPERTIES}


def parse_journal_settings(output):
    settings = {}
    section = None
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif section == 'Journal':
            key, separator, value = line.partition('=')
            key = key.strip()
            if separator and key in JOURNAL_KEYS:
                value = value.strip()
                if value and not re.fullmatch(r'[A-Za-z0-9. ]+', value):
                    raise ValueError('unrecognized journald setting value')
                settings[key] = value or None
    return settings


def parse_journal_usage(output):
    match = re.fullmatch(r'Archived and active journals take up ([0-9]+(?:\.[0-9]+)?[A-Z]+) in the file system\.',
                         output.strip())
    if not match:
        raise ValueError('unrecognized journal disk usage')
    return match.group(1)


def path_metadata(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'path': str(path), 'state': 'missing'}
    if stat.S_ISREG(info.st_mode):
        kind = 'file'
    elif stat.S_ISDIR(info.st_mode):
        kind = 'directory'
    elif stat.S_ISLNK(info.st_mode):
        kind = 'symlink'
    else:
        kind = 'other'
    return {'path': str(path), 'state': 'present', 'type': kind,
            'mode': format(stat.S_IMODE(info.st_mode), '04o'), 'uid': info.st_uid, 'gid': info.st_gid}


def _config_files(primary, directory, suffix=None):
    candidates = [primary]
    try:
        candidates.extend(sorted(p for p in directory.iterdir() if not p.name.startswith('.')
                                 and (suffix is None or p.suffix == suffix)))
    except FileNotFoundError:
        pass
    for path in candidates:
        metadata = path_metadata(path)
        if metadata['state'] == 'present':
            yield path, metadata['type']


def _mentioned_paths(lines, expected_paths):
    return sorted(path for path in expected_paths if any(
        re.search(r'(?<![A-Za-z0-9_./-])' + re.escape(path) + r'(?![A-Za-z0-9_./-])', line)
        for line in lines))


def _rotation_directives(lines):
    directives = []
    in_script = False
    for line in lines:
        parts = line.partition('#')[0].split()
        if not parts:
            continue
        key = parts[0]
        if key == 'endscript':
            in_script = False
        elif not in_script:
            if key in SCRIPT_DIRECTIVES:
                in_script = True
            elif key in ROTATE_FLAGS and len(parts) == 1:
                directives.append({'name': key})
            elif key in ROTATE_VALUES and 2 <= len(parts) <= 3 and all(
                    re.fullmatch(r'-?[0-9]+[kKmMgG]?', value) for value in parts[1:]):
                directives.append({'name': key, 'value': ' '.join(parts[1:])})
    return directives


def _config_hints(details, root, paths, rotation=False):
    name = 'logrotate' if rotation else 'rsyslog'
    results = []
    files = _config_files(root / (name + '.conf'), root / (name + '.d'),
                          suffix=None if rotation else '.conf')
    for path, kind in files:
        item = {'config': path.relative_to(root).as_posix(), 'type': kind}
        if kind == 'file':
            try:
                lines = [line.strip() for line in path.read_text(encoding='utf-8').splitlines()
                         if line.strip() and not line.lstrip().startswith('#')]
            except (OSError, UnicodeError) as exc:
                details['errors'].append({'stage': name, 'config': item['config'], 'kind': type(exc).__name__})
            else:
                item['mentioned_log_paths'] = _mentioned_paths(lines, paths)
                if rotation:
                    item['observed_directives'] = _rotation_directives(lines)
        results.append(item)
    return results


def _observe(details, stage, read):
    try:
        value = read()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        error = {'stage': stage, 'kind': type(exc).__name__}
        if isinstance(exc, subprocess.CalledProcessError):
            error['exit_code'] = exc.returncode
        if (stage == 'journal_disk_usage' and type(exc) is ValueError
                and getattr(exc, 'collection_reason', None) == 'journal_visibility_limited'
                and type(getattr(exc, 'command_exit_code', None)) is int
                and exc.command_exit_code == 0
                and getattr(exc, 'visibility', None) == 'partial'):
            error.update(reason='journal_visibility_limited', command_exit_code=0,
                         visibility='partial')
        details['errors'].append(error)
        return None
    details['observations'][stage] = value
    return value


def run_from_policy(path=DEFAULT_POLICY, command_runner=None, *, config_root=Path('/etc'),
                    metadata_reader=None):
    try:
        document = load_policy(path)
    except PolicyError:
        return make_result(CHECK_ID, 'error', 'medium', 'LOG-01: 정책 파일을 읽거나 검증할 수 없습니다.',
                           recommendation_for_status('error'), {'errors': [{'stage': 'policy'}]})

    runner = _read_command if command_runner is None else command_runner
    metadata = path_metadata if metadata_reader is None else metadata_reader
    details = {'policy_version': document['policy_version'], 'observations': {}, 'errors': [],
               'review': ['policy_evaluation_pending' if document['policies'] else 'policy_pending']}
    os_info = _observe(details, 'os', read_target_os)
    paths = LOG_PATHS.get(os_info['id'], ()) if os_info else ()
    if os_info and not paths:
        details['review'].append('os_log_paths_unconfirmed')
    for unit in UNITS:
        _observe(details, 'unit:' + unit, lambda: parse_unit_state(runner(unit_command(unit))))
    _observe(details, 'journald_settings', lambda: parse_journal_settings(runner(JOURNAL_CONFIG)))
    _observe(details, 'journal_disk_usage', lambda: parse_journal_usage(runner(JOURNAL_USAGE)))
    for observed_path in JOURNAL_PATHS + paths:
        _observe(details, 'path:' + observed_path, lambda: metadata(Path(observed_path)))
    _observe(details, 'rsyslog_config_hints', lambda: _config_hints(details, config_root, paths))
    _observe(details, 'logrotate_config_hints', lambda: _config_hints(details, config_root, paths, rotation=True))

    if details['errors']:
        status = 'error'
        evidence = 'LOG-01: 필수 상태 또는 설정 조회 오류 {}건을 기록했습니다.'.format(len(details['errors']))
    else:
        status = 'needs_review'
        evidence = 'LOG-01: 로그 수집 상태와 보관 설정을 조회했습니다. 운영 기준과 이벤트 기록 검증이 필요합니다.'
    return make_result(CHECK_ID, status, 'medium', evidence, recommendation_for_status(status), details)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, default=DEFAULT_POLICY)
    add_result_version_argument(parser)
    args = parser.parse_args()
    result = run_from_policy(args.policy)
    print(json.dumps(adapt_result(result, args.result_version), ensure_ascii=False,
                     indent=2, allow_nan=False), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
