"""FILE-01 고정 합성 정책. 보고서의 trusted/approved 표시는 신뢰 근거가 아니다."""
from copy import deepcopy
import hashlib
import json

PATH = "/mock/secureops-file01/fixture.txt"
TARGET_MODE = "0644"


def initial_snapshot():
    """관리 코드에 고정된 승인 MOCK 기준. 실제 파일을 조회하지 않는다."""
    return dict(file_id="mock-file-001", path=PATH, uid=1001, gid=1001,
                mode="0666", content_sha256="a" * 64, file_type="regular",
                extended_acl=False, device=1, inode=101)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def actions():
    # 원본 mode/identity와 목표 mode가 기존 Plan.plan_id에 함께 포함된다.
    value = json.dumps({"initial_snapshot": initial_snapshot(), "target_mode": TARGET_MODE},
                       sort_keys=True, allow_nan=False)
    return (("file01_mode_mock", PATH, value),)


def validate_snapshot(actual, *, mode):
    expected = initial_snapshot()
    expected["mode"] = mode
    if not isinstance(actual, dict) or actual != expected:
        raise ValueError("FILE-01 snapshot/identity/mode mismatch")
    for key in ("uid", "gid", "device", "inode"):
        if type(actual[key]) is not int:
            raise ValueError("FILE-01 integer identity required")
    if actual["extended_acl"] is not False:
        raise ValueError("FILE-01 extended ACL is unsupported")


def permission(item, *, mode, status):
    """원본 C 세부 근거와 E 고정 정책을 대조. 종합 상태는 변경하지 않는다."""
    files = item.get("details", {}).get("files")
    if not isinstance(files, list) or len(files) != 1:
        raise ValueError("one FILE-01 evidence record required")
    row = files[0]
    if row.get("path") != PATH:
        raise ValueError("FILE-01 evidence path mismatch")
    actual = row.get("actual", {})
    for key, value in {"path": PATH, "uid": 1001, "gid": 1001,
                       "mode": mode, "file_type": "regular"}.items():
        if actual.get(key) != value:
            raise ValueError("FILE-01 original evidence mismatch")
    if type(actual["uid"]) is not int or type(actual["gid"]) is not int:
        raise ValueError("numeric C owner evidence required")
    checks = row.get("checks", [])
    selected = [c for c in checks if c.get("name") == "permissions"]
    if len(selected) != 1:
        raise ValueError("one permission subcheck required")
    check = selected[0]
    expected = {"allowed_permission_bits": TARGET_MODE,
                "unexpected_bits": "0022" if mode == "0666" else "0000"}
    if (check.get("status"), check.get("actual"), check.get("expected")) != (status, mode, expected):
        raise ValueError("approved permission evidence required")
    criteria = row.get("expected", {})
    if criteria.get("expected_uid") != 1001 or criteria.get("allowed_permission_bits") != TARGET_MODE:
        raise ValueError("C and E permission policy mismatch")
    return deepcopy(check)


def plan_reason(report, item):
    if report["schema_version"] != "1.2":
        return "file01_requires_v12"
    if item is None or item.get("status") not in {"vulnerable", "needs_review"}:
        return "check_not_vulnerable"
    try:
        permission(item, mode="0666", status="vulnerable")
    except (ValueError, TypeError, KeyError, AttributeError):
        return "file01_untrusted_evidence"
    return None


def validate_callback_context(request, state):
    """E 발신 전 및 신뢰된 MOCK 소비자에서 동일한 내용 바인딩을 재검증한다.

    해시·승인 기록은 서명이 아니다. 호출자가 신뢰된 E 경로인지 별도 보장해야 한다.
    """
    from .engine import build_plan, digest
    context = state["file01_context"]
    baseline = initial_snapshot()
    if (context["original_snapshot"] != baseline or context["expected_identity"] != baseline
            or context["snapshot_digest"] != fingerprint(baseline)
            or context["snapshot_digest"] != fingerprint(context["original_snapshot"])):
        raise ValueError("untrusted original snapshot/digest")
    if context["permission_subcheck_id"] != "permissions" or context["target_mode"] != TARGET_MODE:
        raise ValueError("unapproved permission subcheck/target mode")
    before = context["before_report"]
    plan = build_plan(before, "FILE-01")
    if plan.skip_reason or context["before_report_digest"] != digest(before):
        raise ValueError("before report evidence mismatch")
    for key, value in dict(target_id=plan.target_id, os=plan.os, check_id=plan.check_id,
                           before_scan_id=plan.scan_id, plan_id=plan.plan_id,
                           policy_version=plan.policy_version).items():
        if context[key] != value:
            raise ValueError("FILE-01 plan/report binding mismatch")
    if context["before_report_digest"] != plan.source_digest:
        raise ValueError("source digest mismatch")
    expected_request = dict(target_id=plan.target_id, os=plan.os, check_id=plan.check_id,
                            before_scan_id=plan.scan_id, schema_version="1.2")
    if request != expected_request:
        raise ValueError("FILE-01 request mismatch")
    proof = context["approval_evidence"]
    if (proof["approved"] is not True or proof["verification"] != "e_verify_approval_callback"
            or not proof["approved_by"] or not context["execution_id"]
            or proof["approval_id"] != context["approval_id"]):
        raise ValueError("verified approval evidence required")
    from .contract import timestamp
    if timestamp(proof["verified_at"]) >= timestamp(proof["expires_at"]):
        raise ValueError("approval expired at verification")
    for key, value in dict(target_id=plan.target_id, scan_id=plan.scan_id, plan_id=plan.plan_id).items():
        if proof[key] != value:
            raise ValueError("approval binding mismatch")
    for key, value in dict(approved_target_id=plan.target_id, approved_scan_id=plan.scan_id,
                           approved_plan_id=plan.plan_id, approved_check_id=plan.check_id).items():
        if context[key] != value:
            raise ValueError("approved context mismatch")
    modes = {"before": "0666", "after": "0644", "post_restore": "0666", "post_rollback": "0666"}
    if context["phase"] not in modes:
        raise ValueError("unknown FILE-01 phase")
    validate_snapshot(state["files"][PATH], mode=modes[context["phase"]])
    permission(before["results"][next(i for i, row in enumerate(before["results"])
              if row["check_id"] == "FILE-01")], mode="0666", status="vulnerable")


class File01MockHandler:
    """고정 파일 하나의 mode만 소유한다. UID/GID·내용·서비스는 변경하지 않는다."""
    @staticmethod
    def preflight(backend, plan):
        if plan.actions != actions() or not backend._file01_execution:
            raise ValueError("FILE-01 approved execution binding required")
        for key, value in {"approved_plan_id": plan.plan_id, "approved_target_id": plan.target_id,
                           "approved_scan_id": plan.scan_id, "approved_check_id": plan.check_id}.items():
            if backend._file01_execution.get(key) != value:
                raise ValueError("FILE-01 approval/plan context mismatch")
        validate_snapshot(backend.files.get(PATH), mode="0666")
        backend._file01_context = dict(
            original_snapshot=initial_snapshot(), expected_identity=initial_snapshot(),
            snapshot_digest=fingerprint(initial_snapshot()), target_mode=TARGET_MODE,
            target_id=plan.target_id, os=plan.os, check_id=plan.check_id,
            plan_id=plan.plan_id, before_scan_id=plan.scan_id,
            policy_version=plan.policy_version, **deepcopy(backend._file01_execution))

    @staticmethod
    def snapshot(backend):
        return deepcopy(backend.files[PATH])

    @staticmethod
    def apply(backend, plan):
        validate_snapshot(backend.files.get(PATH), mode="0666")
        backend.files[PATH]["mode"] = TARGET_MODE
        backend._step("apply")  # 일부 변경 이후 실패도 복구 대상으로 검증한다.

    @staticmethod
    def validate(backend, plan):
        validate_snapshot(backend.files.get(PATH), mode=TARGET_MODE)

    @staticmethod
    def restore(backend, snapshot):
        current = backend.files.get(PATH)
        if not isinstance(current, dict):
            raise ValueError("FILE-01 target disappeared")
        # identity가 달라졌으면 원래 metadata를 덮어써 숨기지 않는다.
        validate_snapshot(current, mode=current.get("mode"))
        validate_snapshot(snapshot, mode="0666")
        backend.files[PATH]["mode"] = snapshot["mode"]

    @staticmethod
    def verify_restore(backend, snapshot):
        validate_snapshot(backend.files.get(PATH), mode="0666")
        if backend.files[PATH] != snapshot:
            raise ValueError("FILE-01 restoration mismatch")

    @staticmethod
    def recheck(backend, plan, *, schema_version):
        raise ValueError("FILE-01 requires the existing MockRecheckAdapter")
