"""SSH-01의 기존 가상 상태 변경·검증·복구 로직. 서버 I/O는 수행하지 않는다."""

from copy import deepcopy


class SSH01MockHandler:
    """PR #23의 SSH-01 동작을 상태 없는 핸들러로 제공한다."""

    @staticmethod
    def preflight(backend, plan):
        # MockFailure의 기존 import 경로와 타입을 유지한다.
        from .mock import MockFailure

        if not backend.include_verified or backend.match_present:
            raise MockFailure("ssh_include_or_match_unverified")
        if not backend.service_running:
            raise MockFailure("mock_service_initially_unhealthy")
        _, path, _ = plan.actions[0]
        record = backend.files.get(path)
        if record is not None:
            if record.get("type") != "regular" or record.get("acl") != "none":
                raise MockFailure("ssh_file_type_or_acl_unverified")
            if any(type(record.get(key)) is not int for key in ("uid", "gid", "mode")):
                raise MockFailure("ssh_file_metadata_incomplete")

    @staticmethod
    def snapshot(backend):
        return deepcopy((backend.files, backend.root_login, backend.service_running))

    @staticmethod
    def apply(backend, plan):
        _, path, value = plan.actions[0]
        backend.files[path] = {"uid": 0, "gid": 0, "mode": 0o600,
                               "type": "regular", "acl": "none", "content": value}
        backend.root_login = "no"
        backend.service_running = False
        backend._step("apply")
        backend.service_running = True

    @staticmethod
    def validate(backend, plan):
        from .mock import MockFailure

        _, path, value = plan.actions[0]
        if backend.files[path]["content"] != value or backend.root_login != "no":
            raise MockFailure("mock_ssh_setting_invalid")
        if not backend.service_running:
            raise MockFailure("mock_service_unhealthy_after_change")

    @staticmethod
    def recheck(backend, plan, *, schema_version):
        item = {"check_id": plan.check_id,
                "status": "pass" if backend.root_login == "no" else "vulnerable",
                "evidence": "MOCK: effective PermitRootLogin value rechecked",
                "recommendation": "MOCK: review the change before any VM test"}
        if schema_version == "1.1":
            item["severity"] = "high"
        else:
            item["cvss"] = {
                "assessment_status": "not_applicable" if item["status"] == "pass" else "pending",
                "version": None, "vector": None, "base_score": None, "rating": None, "source": None,
                "rationale": ("MOCK: no vulnerable finding after recheck" if item["status"] == "pass"
                              else "MOCK: CVSS applicability and evidence await review"),
            }
        return item

    @staticmethod
    def restore(backend, snapshot):
        backend.files, backend.root_login, backend.service_running = deepcopy(snapshot)

    @staticmethod
    def verify_restore(backend, snapshot):
        from .mock import MockFailure

        if (backend.files, backend.root_login) != snapshot[:2]:
            raise MockFailure("backup_restoration_mismatch")

    @staticmethod
    def verify_service(backend):
        from .mock import MockFailure

        if not backend.service_running:
            raise MockFailure("mock_service_unhealthy_after_restore")
