"""SSH-01의 Dry-run 또는 명시적 Mock 조치를 가상 데이터로 시연한다."""

import argparse
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

from . import Approval, MockBackend, Remediator, build_plan


def main():
    """실행 옵션에 따라 계획 또는 모의 조치 결과를 출력한다."""
    parser = _make_parser()
    args = parser.parse_args()
    if args.report and args.mock:
        parser.error("--report supports Dry-run only")
    if (args.fail_at or args.deny or args.skip) and not args.mock:
        parser.error("--fail-at, --deny and --skip require --mock")

    # 외부 JSON은 변경 계획만 확인한다. 모의 변경은 내장 샘플로 실행한다.
    if args.report:
        try:
            result = _preview_report(args.report)
        except (OSError, ValueError, TypeError) as exc:
            parser.error(f"cannot plan from the report: {exc}")
    else:
        result = _run_demo(dry_run=not args.mock, fail_at=args.fail_at, deny=args.deny, skip=args.skip)

    print(json.dumps(result, ensure_ascii=False, indent=2))


def _make_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mock", action="store_true", help="simulate approved change in memory only")
    parser.add_argument("--report", type=Path, help="read a v1.1 JSON file in Dry-run")
    parser.add_argument("--fail-at", choices=("backup", "apply", "validate", "recheck", "verify_service"),
                        help="inject a failure during the built-in Mock demo")
    scenarios = parser.add_mutually_exclusive_group()
    scenarios.add_argument("--deny", action="store_true", help="simulate administrator denial")
    scenarios.add_argument("--skip", action="store_true", help="simulate a needs_review report")
    return parser


def _preview_report(path):
    """외부 보고서로 변경 계획을 미리 본다."""
    before = json.loads(path.read_text(encoding="utf-8-sig"))
    plan = build_plan(before, "SSH-01")
    engine = Remediator(allowed_targets={plan.target_id}, allowed_checks={"SSH-01"})
    return engine.run(before, plan)


def _run_demo(*, dry_run, fail_at, deny, skip):
    """가상 승인과 가상 서버를 준비해 예제 조치를 실행한다."""
    before = deepcopy(DEMO_REPORT)
    if skip:
        before["results"][0].update(status="needs_review", evidence="MOCK: policy review required")
    plan = build_plan(before, "SSH-01")
    # 시연용 가상 승인이다. 실제 관리자 승인 저장소를 대신하지 않는다.
    approval = Approval("demo-approval-MOCK", "demo-admin-MOCK", plan.target_id, plan.scan_id,
                        plan.plan_id, "2099-01-01T00:00:00Z", True)
    engine = Remediator(allowed_targets={plan.target_id}, allowed_checks={"SSH-01"},
                         verify_approval=lambda record: record == approval)
    failures = {fail_at} if fail_at else set()
    # 복구 후 서비스 확인을 재현하려면 먼저 조치에 실패해야 한다.
    if fail_at == "verify_service":
        failures.add("apply")
    backend = MockBackend(target_id=plan.target_id, os=plan.os, files={},
                           fail_at=failures,
                           access_verified=True, snapshot_verified=True, include_verified=True)
    # 준비한 진단 보고서, 계획, 가상 승인으로 조치 흐름을 실행한다.
    return engine.run(before, plan, backend=backend,
                      approval=replace(approval, approved=False) if deny else approval,
                      dry_run=dry_run)


DEMO_REPORT = {
    "schema_version": "1.1",
    "scan_id": "demo-before-MOCK",
    "target_id": "demo-MOCK",
    "os": "ubuntu-24.04",
    "scanned_at": "2026-11-09T01:00:00Z",
    "results": [
        {
            "check_id": "SSH-01",
            "status": "vulnerable",
            "severity": "high",
            "evidence": "MOCK: permitrootlogin yes",
            "recommendation": "MOCK: request administrator approval",
        },
    ],
}


if __name__ == "__main__":
    main()
