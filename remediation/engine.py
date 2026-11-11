"""변경 계획과 관리자 승인을 검증하고 메모리 내 조치·복구를 진행한다."""

from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

from .contract import timestamp, validate_report
from .mock import MockBackend, MockFailure

SUPPORTED_OS = {"ubuntu-24.04", "ubuntu-24.04.5"}


def digest(value):
    """JSON 호환 값 value를 입력받아 내용 비교용 SHA-256 해시 문자열을 반환한다."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     allow_nan=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Plan:
    """대상·원본 진단·정책·고정 작업을 묶은 수정 불가능한 조치 계획."""
    target_id: str
    os: str
    scan_id: str
    check_id: str
    source_digest: str
    policy_version: str
    # 작업 종류·고정 경로·적용 값만 보관한다. 권고 문구를 명령으로 실행하지 않는다.
    actions: tuple[tuple[str, str, str], ...]
    skip_reason: str | None = None

    @property
    def plan_id(self):
        """입력 인자 없이 계획 전체를 식별하는 해시 문자열을 반환한다."""
        fields = asdict(self)
        if self.skip_reason is None:
            del fields["skip_reason"]
        return digest(fields)


def build_plan(report, check_id):
    """진단 보고서를 확인해 가상 조치 계획 또는 제외 사유를 담은 계획을 만든다."""
    validate_report(report)
    if not isinstance(check_id, str) or not check_id.strip():
        raise ValueError("check_id required")

    item = next((item for item in report["results"] if item["check_id"] == check_id), None)
    # 진단 결과가 유효해도 대상·정책·판정에 따라 조치에서 제외할 수 있다.
    skip_reason = None
    if check_id != "SSH-01":
        skip_reason = "check_policy_not_allowed"
    elif report["os"] not in SUPPORTED_OS:
        skip_reason = "unsupported_os"
    elif item is None:
        skip_reason = "check_not_found"
    elif item["status"] != "vulnerable":
        skip_reason = "check_not_vulnerable"

    # SSH-01은 현재 Ubuntu 모의 조치에서만 허용한다.
    actions = () if skip_reason else (
        ("ssh_dropin", "/etc/ssh/sshd_config.d/01-secureops.conf", "PermitRootLogin no\n"),
    )
    return Plan(report["target_id"], report["os"], report["scan_id"], check_id, digest(report),
                "ssh-01-proposal-v1" if actions else "", actions, skip_reason)


@dataclass(frozen=True)
class Approval:
    """특정 서버·스캔·계획의 승인 기록. 신뢰된 저장소를 통한 검증도 필요하다."""
    approval_id: str
    approved_by: str
    target_id: str
    scan_id: str
    plan_id: str
    expires_at: str
    approved: bool = False


def compare_reports(before, after, check_id):
    """동일 항목의 조치 전후 결과와 개선 여부를 비교한다."""
    validate_report(before)
    validate_report(after)
    if before["schema_version"] != after["schema_version"]:
        raise ValueError("recheck schema version mismatch")
    if before["target_id"] != after["target_id"] or before["os"] != after["os"]:
        raise ValueError("recheck target/OS mismatch")
    if before["scan_id"] == after["scan_id"]:
        raise ValueError("recheck must have a new scan_id")
    if timestamp(after["scanned_at"]) < timestamp(before["scanned_at"]):
        raise ValueError("recheck precedes original scan")
    old = next((r for r in before["results"] if r["check_id"] == check_id), None)
    new = next((r for r in after["results"] if r["check_id"] == check_id), None)
    if old is None or new is None:
        raise ValueError("same check_id required for comparison")
    return {"target_id": before["target_id"], "check_id": check_id,
            "before_scan_id": before["scan_id"], "after_scan_id": after["scan_id"],
            "before": deepcopy(old), "after": deepcopy(new),
            "improved": old["status"] == "vulnerable" and new["status"] == "pass"}


class Remediator:
    """허용 목록과 신뢰된 승인 확인을 거쳐 Dry-run 또는 Mock 조치를 관리한다."""

    def __init__(self, *, allowed_targets, allowed_checks=(), verify_approval=None):
        """허용 대상/항목과 승인 검증 함수를 받아 실행 관리자를 초기화한다."""
        self.allowed_targets = frozenset(allowed_targets)
        self.allowed_checks = frozenset(allowed_checks)
        self.verify_approval = verify_approval
        self._used = set()

    def run(self, report, plan, *, backend=None, approval=None, dry_run=True, now=None):
        """계획을 검증하고 Dry-run 또는 승인된 Mock 조치를 수행한다."""
        # 외부 승인 함수가 원본을 바꾸더라도 실행 입력이 변하지 않도록 복사한다.
        report = deepcopy(report)
        expected = build_plan(report, plan.check_id)
        # 원본 진단이나 작업 내용이 검토한 계획과 달라졌으면 실행하지 않는다.
        if plan != expected:
            raise ValueError("modified or stale remediation plan")
        if type(dry_run) is not bool:
            raise ValueError("dry_run must be boolean")
        before_item = next((item for item in report["results"]
                            if item["check_id"] == plan.check_id), None)
        result = {"mode": "dry_run" if dry_run else "mock", "plan_id": plan.plan_id, "execution_id": str(uuid4()),
                  "target_id": plan.target_id, "check_id": plan.check_id,
                  "outcome": "planned", "backup": "not_attempted", "backup_id": None,
                  "rollback": "not_needed", "approval": None,
                  "before_status": before_item["status"] if before_item else None,
                  "before_scan_id": plan.scan_id,
                  "completed_steps": ["plan"],
                  "after_report": None, "comparison": None}
        # 제외 결과도 D가 저장할 수 있도록 사유와 함께 반환한다.
        if plan.skip_reason:
            result.update(outcome="skipped", stopped_stage="plan", failure_reason=plan.skip_reason)
            return result
        if plan.target_id not in self.allowed_targets or plan.check_id not in self.allowed_checks:
            result.update(outcome="skipped", stopped_stage="allowlist", failure_reason="target_or_check_not_allowed")
            return result
        if dry_run:
            # 여기서 종료하므로 승인 사용·백업·변경·재진단을 호출하지 않는다.
            result["plan"] = asdict(plan)
            return result
        # 실제 서버 구현을 잘못 전달해도 실행되지 않도록 Mock만 명시적으로 허용한다.
        if type(backend) is not MockBackend:
            raise PermissionError("live remediation is disabled; only MockBackend is supported")
        if backend.target_id != plan.target_id or backend.os != plan.os:
            raise ValueError("backend target/OS mismatch")
        now = datetime.now(timezone.utc) if now is None else now
        if now.utcoffset() is None:
            raise ValueError("timezone-aware clock required")
        # 승인 거부는 정상적인 중단이다. 승인 확인 자체가 실패하면 오류로 기록한다.
        rejection_reason = self._approval_rejection(approval, plan, now)
        if rejection_reason:
            if rejection_reason == "approval_verification_error":
                result.update(outcome="failed", failed_stage="approval", failure_reason=rejection_reason)
            else:
                result.update(outcome="rejected", stopped_stage="approval", failure_reason=rejection_reason)
            return result
        self._used.add(approval.approval_id)
        result["approval"] = {"approval_id": approval.approval_id,
                              "approved_by": approval.approved_by,
                              "scan_id": approval.scan_id}
        steps = result["completed_steps"]
        steps.append("approval")
        # 백업 이후 조치·설정 검증이 실패하면 백업으로 복구한다.
        snapshot = None
        stage = "preflight"
        try:
            backend.preflight(plan)
            steps.append("preflight")
            # 백업 완료 뒤에만 변경한다. 일부만 변경되더라도 원본으로 복구할 수 있어야 한다.
            stage = "backup"
            snapshot = backend.backup(plan)
            result.update(backup="success", backup_id=snapshot)
            steps.append("backup")
            stage = "apply"
            backend.apply(plan)
            steps.append("apply")
            stage = "validate"
            backend.validate(plan)
            steps.append("validate")
        except Exception as exc:
            reason = str(exc) if isinstance(exc, MockFailure) else f"{stage}_failed"
            result.update(outcome="failed", failed_stage=stage, failure_reason=reason)
            if stage == "backup":
                result["backup"] = "failed"
            if snapshot is not None:
                try:
                    recovery_step = "restore"
                    backend.restore(snapshot)
                    steps.append(recovery_step)
                    recovery_step = "verify_restore"
                    backend.verify_restore(snapshot)
                    steps.append(recovery_step)
                    # 설정을 복원한 뒤 가상 SSH 서비스 상태까지 확인한다.
                    recovery_step = "verify_service"
                    backend.verify_service()
                    steps.append(recovery_step)
                    result["rollback"] = "verified"
                except Exception as exc:
                    reason = str(exc) if isinstance(exc, MockFailure) else f"{recovery_step}_failed"
                    result.update(outcome="failed", rollback="failed",
                                  rollback_failed_stage=recovery_step, rollback_failure_reason=reason)
            return result

        # 설정 검증을 통과한 뒤에는 재진단 결과와 오류를 따로 기록한다.
        try:
            if report["schema_version"] == "1.2":
                from core.main import DiagnosisAggregator
                item = backend.recheck(plan, schema_version="1.2")
                steps.append("recheck")
                # D가 v1.2 보고서와 새 진단 ID·완료 시각을 생성한다.
                after = DiagnosisAggregator.from_results(
                    [item], [], target_id=plan.target_id, os=plan.os, schema_version="1.2",
                ).get_report()
            else:
                item = backend.recheck(plan)
                steps.append("recheck")
                after = {"schema_version": "1.1", "target_id": plan.target_id, "os": plan.os,
                         "scan_id": str(uuid4()), "scanned_at": datetime.now(timezone.utc).isoformat(),
                         "results": [item]}
            comparison = compare_reports(report, after, plan.check_id)
            steps.append("compare")
        except Exception:
            reason = ("invalid_recheck_result" if "recheck" in steps else
                      "recheck_execution_failed")
            result.update(outcome="failed", failed_stage="recheck",
                          failure_reason=reason)
            self._restore_after_recheck_failure(backend, snapshot, result)
            return result

        if item["status"] == "error":
            result.update(outcome="failed", failed_stage="recheck",
                          failure_reason="recheck_reported_error")
            self._restore_after_recheck_failure(backend, snapshot, result)
            return result

        # 재진단 보고서만 공통 진단 JSON 규격을 따른다. 조치·복구 상태는 바깥 결과에 남긴다.
        result.update(after_report=after, comparison=comparison)
        if comparison["improved"]:
            result["outcome"] = "success"
        else:
            result.update(outcome="failed", failed_stage="recheck",
                          failure_reason="recheck_not_improved")
            self._restore_after_recheck_failure(backend, snapshot, result)
        return result


    def _restore_after_recheck_failure(self, backend, snapshot, result):
        steps = result["completed_steps"]
        recovery_step = "restore"
        try:
            backend.restore(snapshot)
            steps.append("restore")
            recovery_step = "verify_restore"
            backend.verify_restore(snapshot)
            steps.append("verify_restore")
            recovery_step = "verify_service"
            backend.verify_service()
            steps.append("verify_service")
            result["rollback"] = "verified"
        except Exception as exc:
            reason = str(exc) if isinstance(exc, MockFailure) else f"{recovery_step}_failed"
            result.update(
                rollback="failed",
                rollback_failed_stage=recovery_step,
                rollback_failure_reason=reason,
            )

    def _approval_rejection(self, approval, plan, now):
        """승인을 사용할 수 없으면 사유 코드를 반환한다."""
        if not isinstance(approval, Approval):
            return "approval_required"
        if approval.approved is not True:
            return "approval_denied"
        if any(not isinstance(value, str) or not value.strip()
               for value in (approval.approval_id, approval.approved_by)):
            return "approval_identity_missing"
        # 다른 서버·스캔·계획의 승인을 재사용하지 못하도록 함께 검증한다.
        if (approval.target_id, approval.scan_id, approval.plan_id) != (plan.target_id, plan.scan_id, plan.plan_id):
            return "approval_binding_mismatch"
        try:
            expires_at = timestamp(approval.expires_at)
        except ValueError:
            return "approval_expiry_invalid"
        if expires_at <= now or approval.approval_id in self._used:
            return "approval_expired_or_used"
        # approved=True만 믿지 않고 신뢰된 승인 조회 결과까지 요구한다.
        try:
            verified = self.verify_approval is not None and self.verify_approval(approval) is True
        except Exception:
            return "approval_verification_error"
        if not verified:
            return "approval_not_verified"
        return None
