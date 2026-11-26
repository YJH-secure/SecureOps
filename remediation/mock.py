"""메모리 안에서만 설정 변경을 흉내 낸다. 명령 실행·파일 쓰기·통신은 하지 않는다."""

from copy import deepcopy
from uuid import uuid4

from .handlers import SSH01MockHandler
from .policies import REMEDIATION_POLICIES


class MockFailure(RuntimeError):
    """실패 기록에 사용할 수 있는 고정된 모의 실패 코드."""


class MockBackend:
    """테스트용 서버 상태와 백업을 보관하며 실패 상황을 재현하는 가상 실행 계층."""
    def __init__(self, *, target_id, os, files, root_login="yes", recheck=None,
                 fail_at=(), access_verified=False, snapshot_verified=False,
                 include_verified=False, match_present=False):
        """가상 서버 상태와 사전 확인 결과를 입력받아 초기화한다."""
        self.target_id, self.os = target_id, os
        self.files = deepcopy(files)
        self.root_login = root_login
        self.service_running = True
        self.recheck_callback = recheck
        self.fail_at = set(fail_at)
        self.access_verified = access_verified
        self.snapshot_verified = snapshot_verified
        self.include_verified = include_verified
        self.match_present = match_present
        self.events = []
        self._backups = {}
        self._backup_contexts = {}
        self._backup_owner = str(uuid4())
        self._active_plan_id = None
        self._active_check_id = None
        self._file01_execution = None
        self._file01_context = None
        self._file01_bound_context = None
        self._file01_phase = "after"

    def _step(self, name):
        """단계 이름 name을 기록한다. 반환은 None이며 지정된 실패 단계면 예외를 낸다."""
        self.events.append(name)
        if name in self.fail_at:
            raise MockFailure(f"mock_{name}_failure")

    def preflight(self, plan):
        """입력 Plan의 접근 유지·복구 준비·파일 상태를 확인한다."""
        self._step("preflight")
        self._active_plan_id = plan.plan_id
        self._active_check_id = plan.check_id
        # 관리 접근과 VM 복구 경로를 확보하지 못한 상태에서는 변경을 시작하지 않는다.
        if not self.access_verified or not self.snapshot_verified:
            raise MockFailure("access_or_snapshot_unverified")
        REMEDIATION_POLICIES[plan.check_id].handler.preflight(self, plan)

    def backup(self, plan):
        """입력 Plan 실행 전 가상 파일 상태와 root 로그인 값을 복사해 보관한다."""
        self._step("backup")
        token = "mock-backup-" + str(uuid4())
        handler = REMEDIATION_POLICIES[plan.check_id].handler
        self._active_plan_id = plan.plan_id
        self._active_check_id = plan.check_id
        # SSH-01의 기존 snapshot 형태를 유지하고 token 문맥은 별도 보관한다.
        self._backups[token] = handler.snapshot(self)
        self._backup_contexts[token] = dict(owner=self._backup_owner, target_id=plan.target_id,
            os=plan.os, check_id=plan.check_id, plan_id=plan.plan_id, handler=handler,
            execution=deepcopy(self._file01_execution) if plan.check_id == "FILE-01" else None)
        if plan.check_id == "FILE-01":
            self._file01_context["backup_token"] = token
            self._file01_bound_context = deepcopy(self._file01_context)
        return token

    def apply(self, plan):
        """입력 Plan의 고정 작업을 메모리 상태에 적용한다. 반환값은 없다."""
        # 첫 변경 직후에도 실패를 주입해, 일부만 변경된 상태에서의 복구를 검증한다.
        self._step("before_apply")
        REMEDIATION_POLICIES[plan.check_id].handler.apply(self, plan)

    def validate(self, plan):
        """가상 drop-in과 유효 설정값을 확인한다."""
        self._step("validate")
        REMEDIATION_POLICIES[plan.check_id].handler.validate(self, plan)

    def recheck(self, plan, *, schema_version="1.1"):
        """동일 항목의 모의 진단 결과를 반환한다."""
        if schema_version not in {"1.1", "1.2"}:
            raise ValueError("unsupported recheck schema version")
        self._step("recheck")
        if self.recheck_callback is not None:
            return self.recheck_callback(self.target_id, plan.check_id,
                                         deepcopy(self.files), self.root_login)
        return REMEDIATION_POLICIES[plan.check_id].handler.recheck(self, plan, schema_version=schema_version)

    def request_recheck(self, plan, callback):
        """신뢰된 MOCK 콜백에 요청·가상 상태의 복사본을 전달하고 전체 보고서를 받는다.

        실제 백엔드나 승인 객체를 넘기지 않는다. 콜백은 Python 테스트 코드이며
        샌드박스가 아니므로 임의의 외부 코드나 원격 실행기를 전달하면 안 된다.
        """
        self._step("recheck")
        request = {"target_id": plan.target_id, "os": plan.os,
                   "check_id": plan.check_id, "before_scan_id": plan.scan_id,
                   "schema_version": "1.2"}
        state = {"files": deepcopy(self.files), "root_login": self.root_login}
        if plan.check_id == "FILE-01":
            self._bound_backup(self._file01_context["backup_token"])
            if self._file01_context != self._file01_bound_context:
                raise ValueError("FILE-01 trusted execution context changed")
            context = deepcopy(self._file01_context)
            if (context["plan_id"], context["target_id"], context["before_scan_id"]) != (
                    plan.plan_id, plan.target_id, plan.scan_id):
                raise ValueError("FILE-01 recheck context mismatch")
            context["phase"] = self._file01_phase
            state["file01_context"] = context
            from .file01 import validate_callback_context
            validate_callback_context(request, state)
        return deepcopy(callback(request, state))

    def _bound_backup(self, token):
        record = dict(self._backup_contexts[token], snapshot=self._backups[token])
        if (record["owner"] != self._backup_owner or record["target_id"] != self.target_id
                or record["os"] != self.os or record["plan_id"] != self._active_plan_id
                or record["check_id"] != self._active_check_id):
            raise ValueError("backup token target/plan binding mismatch")
        if record["check_id"] == "FILE-01":
            if record["execution"] != self._file01_execution:
                raise ValueError("backup token execution/approval mismatch")
            if self._file01_context is None or record["plan_id"] != self._file01_context["plan_id"]:
                raise ValueError("backup token check binding mismatch")
        return record

    def restore(self, token):
        """백업 식별자 token을 받아 파일 상태와 root 로그인 값을 복원한다."""
        self._step("restore")
        record = self._bound_backup(token)
        record["handler"].restore(self, record["snapshot"])

    def verify_restore(self, token):
        """백업 식별자 token의 원본과 현재 가상 상태가 일치하는지 검증한다."""
        self._step("verify_restore")
        record = self._bound_backup(token)
        record["handler"].verify_restore(self, record["snapshot"])

    def verify_service(self):
        """복구 후 가상 SSH 서비스 상태를 확인한다."""
        self._step("verify_service")
        SSH01MockHandler.verify_service(self)
