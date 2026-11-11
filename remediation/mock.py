"""메모리 안에서만 설정 변경을 흉내 낸다. 명령 실행·파일 쓰기·통신은 하지 않는다."""

from copy import deepcopy
from uuid import uuid4


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

    def _step(self, name):
        """단계 이름 name을 기록한다. 반환은 None이며 지정된 실패 단계면 예외를 낸다."""
        self.events.append(name)
        if name in self.fail_at:
            raise MockFailure(f"mock_{name}_failure")

    def preflight(self, plan):
        """입력 Plan의 접근 유지·복구 준비·파일 상태를 확인한다."""
        self._step("preflight")
        # 관리 접근과 VM 복구 경로를 확보하지 못한 상태에서는 변경을 시작하지 않는다.
        if not self.access_verified or not self.snapshot_verified:
            raise MockFailure("access_or_snapshot_unverified")
        if not self.include_verified or self.match_present:
            raise MockFailure("ssh_include_or_match_unverified")
        if not self.service_running:
            raise MockFailure("mock_service_initially_unhealthy")
        _, path, _ = plan.actions[0]
        record = self.files.get(path)
        if record is not None:
            if record.get("type") != "regular" or record.get("acl") != "none":
                raise MockFailure("ssh_file_type_or_acl_unverified")
            if any(type(record.get(key)) is not int for key in ("uid", "gid", "mode")):
                raise MockFailure("ssh_file_metadata_incomplete")

    def backup(self, plan):
        """입력 Plan 실행 전 가상 파일 상태와 root 로그인 값을 복사해 보관한다."""
        self._step("backup")
        token = "mock-backup-" + str(uuid4())
        self._backups[token] = deepcopy((self.files, self.root_login, self.service_running))
        return token

    def apply(self, plan):
        """입력 Plan의 고정 작업을 메모리 상태에 적용한다. 반환값은 없다."""
        # 첫 변경 직후에도 실패를 주입해, 일부만 변경된 상태에서의 복구를 검증한다.
        self._step("before_apply")
        _, path, value = plan.actions[0]
        self.files[path] = {"uid": 0, "gid": 0, "mode": 0o600,
                            "type": "regular", "acl": "none", "content": value}
        self.root_login = "no"
        self.service_running = False
        self._step("apply")
        self.service_running = True

    def validate(self, plan):
        """가상 drop-in과 유효 설정값을 확인한다."""
        self._step("validate")
        _, path, value = plan.actions[0]
        if self.files[path]["content"] != value or self.root_login != "no":
            raise MockFailure("mock_ssh_setting_invalid")
        if not self.service_running:
            raise MockFailure("mock_service_unhealthy_after_change")

    def recheck(self, plan, *, schema_version="1.1"):
        """동일 항목의 모의 진단 결과를 반환한다."""
        if schema_version not in {"1.1", "1.2"}:
            raise ValueError("unsupported recheck schema version")
        self._step("recheck")
        if self.recheck_callback is not None:
            return self.recheck_callback(self.target_id, plan.check_id,
                                         deepcopy(self.files), self.root_login)
        item = {"check_id": plan.check_id,
                "status": "pass" if self.root_login == "no" else "vulnerable",
                "evidence": "MOCK: effective PermitRootLogin value rechecked",
                "recommendation": "MOCK: review the change before any VM test"}
        if schema_version == "1.1":
            item["severity"] = "high"
        else:
            # 가상 설정의 판정만 제공한다. 점수나 Vector를 추측하지 않는다.
            item["cvss"] = {
                "assessment_status": "not_applicable" if item["status"] == "pass" else "pending",
                "version": None, "vector": None, "base_score": None, "rating": None, "source": None,
                "rationale": ("MOCK: no vulnerable finding after recheck" if item["status"] == "pass"
                              else "MOCK: CVSS applicability and evidence await review"),
            }
        return item

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
        return deepcopy(callback(request, state))

    def restore(self, token):
        """백업 식별자 token을 받아 파일 상태와 root 로그인 값을 복원한다."""
        self._step("restore")
        self.files, self.root_login, self.service_running = deepcopy(self._backups[token])

    def verify_restore(self, token):
        """백업 식별자 token의 원본과 현재 가상 상태가 일치하는지 검증한다."""
        self._step("verify_restore")
        if (self.files, self.root_login) != self._backups[token][:2]:
            raise MockFailure("backup_restoration_mismatch")

    def verify_service(self):
        """복구 후 가상 SSH 서비스 상태를 확인한다."""
        self._step("verify_service")
        if not self.service_running:
            raise MockFailure("mock_service_unhealthy_after_restore")
