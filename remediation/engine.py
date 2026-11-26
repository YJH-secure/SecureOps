"""변경 계획과 관리자 승인을 검증하고 메모리 내 조치·복구를 진행한다."""

from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

from .contract import timestamp, validate_report
from .mock import MockBackend, MockFailure
from .policies import REMEDIATION_POLICIES
from .file01 import PATH as FILE01_PATH, permission as file01_permission, plan_reason as file01_reason

SUPPORTED_OS = set(REMEDIATION_POLICIES["SSH-01"].supported_os)


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
    policy = REMEDIATION_POLICIES.get(check_id)
    if policy is None:
        skip_reason = "check_policy_not_allowed"
    elif report["os"] not in policy.supported_os:
        skip_reason = "unsupported_os"
    elif item is None:
        skip_reason = "check_not_found"
    elif check_id == "FILE-01":
        skip_reason = file01_reason(report, item)
    elif item["status"] != "vulnerable":
        skip_reason = "check_not_vulnerable"

    # SSH-01은 현재 Ubuntu 모의 조치에서만 허용한다.
    actions = () if skip_reason else policy.actions
    return Plan(report["target_id"], report["os"], report["scan_id"], check_id, digest(report),
                policy.policy_version if actions else "", actions, skip_reason)


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

    def run(self, report, plan, *, backend=None, approval=None, dry_run=True, now=None,
            recheck_report=None, recheck_adapter=None, post_rollback_recheck=False):
        """기존 조치 절차와 별도로 E 실행 ID·진단 연결·최종 보안 상태를 기록한다."""
        started_at = datetime.now(timezone.utc).isoformat()
        if type(post_rollback_recheck) is not bool:
            raise ValueError("post_rollback_recheck must be boolean")
        if post_rollback_recheck and recheck_adapter is None:
            raise ValueError("post-rollback diagnosis requires the MOCK adapter")
        if recheck_adapter is not None:
            from .recheck import MockRecheckAdapter
            if type(recheck_adapter) is not MockRecheckAdapter or recheck_report is not None:
                raise ValueError("use one exact MockRecheckAdapter or the legacy callback")
            if report.get("schema_version") != "1.2":
                raise ValueError("MOCK adapter requires JSON v1.2")
        before = deepcopy(report)
        if (plan.check_id == "FILE-01" and not plan.skip_reason and not dry_run
                and recheck_adapter is None):
            raise ValueError("FILE-01 requires MockRecheckAdapter; no legacy callback")
        execution_id = str(uuid4())
        attempts = []

        def callback_for(phase):
            def callback(request, state):
                previous = deepcopy(attempts)
                attempt = {"execution_id": execution_id, "phase": phase,
                           "target_id": request["target_id"], "check_id": request["check_id"],
                           "scan_id": None, "scanned_at": None,
                           "save_status": "not_attempted", "load_status": "not_attempted",
                           "report_verified": False, "failure_stage": None, "failure_reason": None}
                attempts.append(attempt)
                return recheck_adapter.recheck(request, state, attempt,
                                               before_report=before, previous_attempts=previous)
            return callback

        selected = callback_for("after") if recheck_adapter is not None else recheck_report
        result = self._run(before, plan, backend=backend, approval=approval, dry_run=dry_run,
                           now=now, recheck_report=selected, execution_id=execution_id)
        if plan.check_id == "FILE-01":
            return self._finish_file01(before, plan, backend, result, callback_for,
                                       attempts, started_at)
        result.setdefault("after_scan_id", None)
        result.update(post_rollback_scan_id=None, post_rollback_report=None,
                      final_security_status=None, final_security_verified=False)
        if result["outcome"] == "success":
            result.update(final_security_status="pass", final_security_verified=True)
        if (post_rollback_recheck and result["rollback"] == "verified"):
            try:
                post = backend.request_recheck(plan, callback_for("post_rollback"))
                # 어댑터의 저장·조회 검증에 더해 기존 E 비교 규칙으로 다시 검사한다.
                checked = compare_reports(before, post, plan.check_id)["after"]
                result.update(post_rollback_report=post, final_security_status=checked["status"],
                              final_security_verified=checked["status"] in {"pass", "vulnerable"})
            except Exception as exc:
                result["post_rollback_recheck_error"] = type(exc).__name__
                # 복구 뒤 재진단 실패를 원래 조치의 성공으로 바꾸지 않는다.
        for attempt in attempts:
            field = "after_scan_id" if attempt["phase"] == "after" else "post_rollback_scan_id"
            result[field] = attempt["scan_id"]
        result["recheck_attempts"] = deepcopy(attempts)
        # 승인 검증·사용을 통과한 ID만 연결한다. 거부·제외·Dry-run은 null이다.
        result["schema_version"] = "1.0"  # E 실행 이력 자체의 승인된 버전
        result["diagnosis_schema_version"] = before["schema_version"]
        result["approval_id"] = result["approval"]["approval_id"] if result["approval"] else None
        result["started_at"] = started_at
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        return result

    def _run(self, report, plan, *, backend=None, approval=None, dry_run=True, now=None,
             recheck_report=None, execution_id):
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
        result = {"mode": "dry_run" if dry_run else "mock", "plan_id": plan.plan_id, "execution_id": execution_id,
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
        # 콜백은 신뢰된 테스트 코드에서만 전달한다. JSON 입력으로 선택하지 않는다.
        if recheck_report is not None:
            if report["schema_version"] != "1.2" or not callable(recheck_report):
                raise ValueError("recheck_report requires JSON v1.2 and a callable")
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
        if plan.check_id == "FILE-01":
            backend._file01_execution = {"execution_id": execution_id, "approval_id": approval.approval_id,
                "approved_plan_id": plan.plan_id, "approved_target_id": plan.target_id,
                "approved_scan_id": plan.scan_id, "approved_check_id": plan.check_id,
                "permission_subcheck_id": "permissions", "before_report": deepcopy(report),
                "before_report_digest": plan.source_digest,
                "approval_evidence": {"approved": True, "approval_id": approval.approval_id,
                    "approved_by": approval.approved_by, "target_id": approval.target_id,
                    "scan_id": approval.scan_id, "plan_id": approval.plan_id,
                    "expires_at": approval.expires_at, "verified_at": now.isoformat(),
                    "verification": "e_verify_approval_callback"}}
            backend._file01_phase = "after"
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
                if plan.check_id == "FILE-01":
                    result["_file01_rollback_before"] = deepcopy(backend.files.get(FILE01_PATH))
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
                if plan.check_id == "FILE-01":
                    result["_file01_rollback_after"] = deepcopy(backend.files.get(FILE01_PATH))
            return result

        # 설정 검증을 통과한 뒤에는 재진단 결과와 오류를 따로 기록한다.
        try:
            if recheck_report is not None:
                # 공통 실행 계층이 D에서 검증·저장·재조회한 전체 보고서를 받는다.
                after = backend.request_recheck(plan, recheck_report)
                steps.append("recheck")
            elif report["schema_version"] == "1.2":
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
            item = comparison["after"]
            result["after_scan_id"] = after["scan_id"]
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
        improved = comparison["improved"]
        if plan.check_id == "FILE-01":
            try:
                file01_permission(item, mode="0644", status="pass")
                backend.validate(plan)
                improved = item["status"] in {"pass", "needs_review"}
                result["permission_improved"] = improved
            except (ValueError, TypeError, KeyError, AttributeError, MockFailure):
                improved = False
        if improved:
            result["outcome"] = "success"
        else:
            result.update(outcome="failed", failed_stage="recheck",
                          failure_reason="recheck_not_improved")
            self._restore_after_recheck_failure(backend, snapshot, result)
        return result

    def _finish_file01(self, before, plan, backend, result, callback_for, attempts, started_at):
        """FILE 전용 종료: 개선 보고서와 복구 이후 최종 상태를 분리한다."""
        from .file01 import initial_snapshot, validate_snapshot
        result.update(normal_restore_result={"status": "not_attempted"},
                      failure_rollback_result={"status": "not_attempted"},
                      normal_restore_scan_id=None, normal_restore_report=None,
                      post_rollback_scan_id=None, post_rollback_report=None,
                      final_security_status=None, final_security_verified=False,
                      final_state_verified=False)
        apply_status = ("success" if "apply" in result["completed_steps"] else
                        "failed" if result.get("failed_stage") == "apply" else "not_attempted")
        result["action_result"] = {"apply_status": apply_status,
                                   "permission_improved": result.get("permission_improved", False)}
        rollback_before = result.pop("_file01_rollback_before", None)
        rollback_after = result.pop("_file01_rollback_after", None)
        phase = None
        if result["outcome"] == "success":
            phase = "normal_restore"
        elif result["rollback"] == "verified":
            phase = "post_rollback"
        if phase is not None:
            field = "normal_restore_result" if phase == "normal_restore" else "failure_rollback_result"
            stage = phase
            result[field] = {"status": "failed", "before_snapshot": (
                rollback_before if phase == "post_rollback" else deepcopy(backend.files.get(FILE01_PATH)))}
            try:
                if phase == "normal_restore":
                    backend._step("normal_restore")
                    backend.restore(result["backup_id"])
                    backend.verify_restore(result["backup_id"])
                    backend.verify_service()
                backend._file01_phase = "post_restore" if phase == "normal_restore" else phase
                stage = phase + "_recheck"
                backend._step(stage)
                report = backend.request_recheck(plan, callback_for(backend._file01_phase))
                checked = compare_reports(before, report, plan.check_id)["after"]
                file01_permission(checked, mode="0666", status="vulnerable")
                if checked["status"] not in {"vulnerable", "needs_review"}:
                    raise ValueError("restoration diagnosis contradicts vulnerable permissions")
                validate_snapshot(backend.files.get(FILE01_PATH), mode="0666")
                result[field].update(status="verified", after_snapshot=deepcopy(backend.files[FILE01_PATH]))
                report_field = "normal_restore_report" if phase == "normal_restore" else "post_rollback_report"
                result[report_field] = report
                result.update(final_security_status=checked["status"],
                              final_security_verified=checked["status"] in {"pass", "vulnerable"},
                              final_state_verified=True)
            except Exception as exc:
                result[field].update(failure_stage=stage, failure_reason=type(exc).__name__,
                                     after_snapshot=deepcopy(backend.files.get(FILE01_PATH)))
                if phase == "normal_restore":
                    result.update(outcome="failed", failed_stage=stage, failure_reason="normal_restore_unverified")
                else:
                    result.update(rollback="failed", rollback_failed_stage=stage,
                                  rollback_failure_reason="post_rollback_unverified")
        elif result["rollback"] == "failed":
            result["failure_rollback_result"] = {"status": "failed",
                "failure_stage": result.get("rollback_failed_stage"),
                "failure_reason": result.get("rollback_failure_reason"),
                "before_snapshot": rollback_before, "after_snapshot": rollback_after}
        for attempt in attempts:
            field = {"after": "after_scan_id", "post_restore": "normal_restore_scan_id",
                     "post_rollback": "post_rollback_scan_id"}[attempt["phase"]]
            result[field] = attempt["scan_id"]
        result.setdefault("after_scan_id", None)
        result["recheck_attempts"] = deepcopy(attempts)
        result.update(schema_version="1.0", diagnosis_schema_version=before["schema_version"],
                      approval_id=result["approval"]["approval_id"] if result["approval"] else None,
                      started_at=started_at, finished_at=datetime.now(timezone.utc).isoformat())
        return result


    def _restore_after_recheck_failure(self, backend, snapshot, result):
        steps = result["completed_steps"]
        if result["check_id"] == "FILE-01":
            result["_file01_rollback_before"] = deepcopy(backend.files.get(FILE01_PATH))
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
        if result["check_id"] == "FILE-01":
            result["_file01_rollback_after"] = deepcopy(backend.files.get(FILE01_PATH))

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
