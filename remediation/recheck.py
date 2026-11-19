"""미확정 공통 실행 계약을 격리하는 E 전용 오프라인 MOCK 저장·조회 어댑터."""

from copy import deepcopy
from .contract import timestamp, validate_report


class MockRecheckAdapter:
    """diagnose(request, state)가 만든 D v1.2 보고서를 저장·재조회한다.

    diagnose는 신뢰된 로컬 MOCK 코드다. 임의 코드를 격리하거나 SSH를 실행하는
    기능은 제공하지 않는다. 테스트에서는 임시 ReportStore만 사용한다.
    """
    def __init__(self, diagnose, store):
        from core.storage import ReportStore
        if not callable(diagnose) or type(store) is not ReportStore:
            raise TypeError("MOCK diagnosis callback and D ReportStore required")
        self.diagnose = diagnose
        self.store = store

    def recheck(self, request, state, attempt, *, before_report, previous_attempts=()):
        """E 소유 attempt에 단계별 결과를 남기며 원본 예외는 호출자에게 전달한다."""
        stage = "diagnose"
        try:
            candidate = deepcopy(self.diagnose(deepcopy(request), deepcopy(state)))
            stage = "validate"
            validate_report(candidate)
            if candidate["schema_version"] != "1.2":
                raise ValueError("MOCK adapter requires JSON v1.2")
            if any(candidate[key] != before_report[key] for key in ("target_id", "os", "schema_version")):
                raise ValueError("recheck target/OS/schema mismatch")
            if not any(item["check_id"] == request["check_id"] for item in candidate["results"]):
                raise ValueError("requested check_id missing")
            used_ids = {before_report["scan_id"]} | {a["scan_id"] for a in previous_attempts if a["scan_id"]}
            if candidate["scan_id"] in used_ids:
                raise ValueError("recheck must have a fresh scan_id")
            latest = max([timestamp(before_report["scanned_at"])] +
                         [timestamp(a["scanned_at"]) for a in previous_attempts if a.get("scanned_at")])
            if timestamp(candidate["scanned_at"]) < latest:
                raise ValueError("recheck time precedes earlier diagnosis")
            # 저장 반환값은 경로다. ID는 검증된 보고서에서 저장 시도 전에 확보한다.
            attempt.update(scan_id=candidate["scan_id"], scanned_at=candidate["scanned_at"])
            stage = "save"
            attempt["save_status"] = "attempted"
            self.store.save(candidate)
            attempt["save_status"] = "success"
            stage = "load"
            attempt["load_status"] = "attempted"
            loaded = self.store.load(request["target_id"], attempt["scan_id"])
            attempt["load_status"] = "success"
            stage = "validate_loaded"
            validate_report(loaded)
            if loaded != candidate:
                raise ValueError("saved and loaded reports differ")
            attempt["report_verified"] = True
            return deepcopy(loaded)
        except Exception as exc:
            if stage == "save":
                attempt["save_status"] = "failed"
            elif stage == "load":
                attempt["load_status"] = "failed"
            # 예외 원문에는 개인 경로가 포함될 수 있어 단계와 오류 종류만 기록한다.
            attempt.update(failure_stage=stage, failure_reason=type(exc).__name__)
            raise
