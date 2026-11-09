"""Real Linux temporary-file integration checks with MOCK approval policies.

Run: python3 -m checks.system.verify_fixtures
Never changes /etc, accounts, or operational policy JSON. No sudo required.
"""
import argparse
import copy
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .file_check import _collect_file_info, evaluate_file, environment_info, build_result
from .link_check import inspect_link


def execute(output):
    if platform.system() != 'Linux':
        raise RuntimeError('Run this real-file verification inside the Linux VM.')
    missing = [name for name in ('getfacl', 'setfacl') if shutil.which(name) is None]
    if missing:
        raise RuntimeError('Missing tools: ' + ', '.join(missing) + '. On Ubuntu install the acl package.')
    environment = environment_info()
    uid, gid = os.getuid(), os.getgid()
    named_uid = 60000 if uid != 60000 else 60001
    results = []
    output = Path(output).resolve()
    if output.exists():
        raise RuntimeError('Evidence file already exists; choose a new --output path to preserve it.')

    with tempfile.TemporaryDirectory(prefix='secureops-file01-') as scratch:
        base = Path(scratch)
        root = base / 'scope'
        root.mkdir(mode=0o700)
        def safe_file(name):
            path = root / name
            path.write_text('Synthetic fixture content only.\n', encoding='utf-8')
            path.chmod(0o600)
            return path

        def criteria(path):
            return dict(path=str(path), expected_uid=uid, reference_gid=gid,
                        allowed_permission_bits='0640', approval_status='approved',
                        acl_policy=dict(approval_status='approved', users=[dict(id=uid,max_bits=6)],
                                        groups=[dict(id=gid,max_bits=0)], other_max_bits=0),
                        link_policy=dict(approval_status='pending', allowed_targets=None))

        def collect(path):
            data = _collect_file_info(str(path), inspect_links=False)
            if data['file_type'] == 'symlink':
                data['link_inspection'] = inspect_link(
                    str(path), os.lstat(path),
                    lambda target: _collect_file_info(target, inspect_links=False),
                    inspection_root=str(root))
            return data

        def record(label, path, expected, policy=None, reason=None):
            policy = criteria(path) if policy is None else policy
            try:
                observation = collect(path)
                file_result = evaluate_file(policy, observation, environment)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                file_result = dict(path=str(path),status='error',actual=None,expected=policy,
                                   checks=[dict(name='observation',status='error',actual=str(exc),
                                                expected='readable fixture',reason='fixture collection failed')])
            result = build_result([file_result], 'high', environment)
            result['details'].update({
                'data_source': '(MOCK approval policy) real temporary-file integration check',
                'scenario': label, 'expected_status': expected, 'inspection_root': str(root)})
            matches = result['status'] == expected
            if reason is not None:
                inspection = (file_result.get('actual') or {}).get('link_inspection', {})
                matches = matches and inspection.get('reason') == reason
                result['details']['expected_inspection_reason'] = reason
            result['details']['matches_expectation'] = matches
            results.append(result)
            print('[{}] {}: expected={} actual={}'.format(
                'OK' if matches else 'FAIL', label, expected, result['status']))

        def set_acl(path, entry):
            # Only our freshly created files under TemporaryDirectory are passed here.
            subprocess.run(['setfacl','-m',entry,'--',str(path)], check=True,
                           capture_output=True,text=True,timeout=5)

        approved = safe_file('acl-approved')
        set_acl(approved, 'u:{}:r--,m::r--'.format(named_uid))
        policy = criteria(approved)
        policy['acl_policy']['users'].append(dict(id=named_uid,max_bits=4))
        record('ACL-approved-read', approved, 'pass', policy)

        denied = safe_file('acl-unapproved')
        set_acl(denied, 'u:{}:r--,m::r--'.format(named_uid))
        record('ACL-unapproved-read', denied, 'vulnerable')

        masked = safe_file('acl-masked-write')
        set_acl(masked, 'u:{}:-w-,m::r--'.format(named_uid))
        record('ACL-write-blocked-by-mask', masked, 'pass')

        policy = criteria(approved)
        policy['acl_policy'] = dict(approval_status='pending',users=None,groups=None,other_max_bits=None)
        record('ACL-approval-pending', approved, 'needs_review', policy)

        record('missing-file-error', root/'missing-file', 'error')

        target = safe_file('target')
        relative = root/'relative-link'
        relative.symlink_to('target')
        policy = criteria(relative)
        policy['link_policy'] = dict(approval_status='approved',allowed_targets=[str(target.resolve())])
        record('LINK-relative-approved', relative, 'pass', policy)

        absolute = root/'absolute-link'
        absolute.symlink_to(target)
        policy = criteria(absolute)
        policy['link_policy'] = dict(approval_status='approved',allowed_targets=[str(target.resolve())])
        record('LINK-absolute-approved', absolute, 'pass', policy)
        record('LINK-policy-pending', relative, 'needs_review')

        bad_target = safe_file('bad-target')
        bad_target.chmod(0o660)  # Temporary fixture only: forbidden group-write bit.
        bad_link = root/'bad-target-link'
        bad_link.symlink_to(bad_target)
        policy = criteria(bad_link)
        policy['link_policy'] = dict(approval_status='approved',allowed_targets=[str(bad_target.resolve())])
        record('LINK-target-permission-violation', bad_link, 'vulnerable', policy)

        broken = root/'broken-link'
        broken.symlink_to('missing-target')
        record('LINK-broken', broken, 'error', reason='target_lookup_failed')
        loop_a, loop_b = root/'loop-a', root/'loop-b'
        loop_a.symlink_to('loop-b')
        loop_b.symlink_to('loop-a')
        record('LINK-cycle', loop_a, 'error', reason='symlink_cycle')

        chain = [root/('hop-'+str(i)) for i in range(10)]
        for index, link in enumerate(chain):
            link.symlink_to(chain[index+1].name if index+1<len(chain) else 'target')
        record('LINK-depth-limit', chain[0], 'error', reason='symlink_hop_limit')

        outside = base/'outside-target'
        outside.write_text('Only a disposable fixture, never a system file.\n',encoding='utf-8')
        escape = root/'scope-escape'
        escape.symlink_to(outside)
        record('LINK-scope-escape', escape, 'needs_review', reason='target_outside_inspection_scope')

        # Capture evidence before TemporaryDirectory removes our fixtures.
        report = dict(kind='FILE-01 temporary-file integration verification',
                      checked_at=datetime.now(timezone.utc).isoformat(),
                      policy_notice='MOCK approval lists, not team operational approvals',
                      cases=len(results), matched=sum(r['details']['matches_expectation'] for r in results),
                      scenarios=results)

    output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('\nMatched {}/{} scenarios. Evidence: {}'.format(report['matched'],report['cases'],output))
    print('Temporary fixtures removed. System files and operational policies were not changed.')
    return 0 if report['matched']==report['cases'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='file01-fixture-evidence.json')
    args = parser.parse_args()
    try:
        return execute(args.output)
    except (OSError,RuntimeError,subprocess.SubprocessError) as exc:
        print('Verification could not complete: '+str(exc),file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
