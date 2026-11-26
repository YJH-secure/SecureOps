"""D callback 부재 시 사용하는 테스트 전용 보고서 생성기. 저장소 호출 없음."""
from copy import deepcopy

from c_mock_bridge import diagnose
from core.main import DiagnosisAggregator
from remediation.file01 import validate_callback_context


def diagnose_file01_mock(request, state):
    """합의한 D 함수와 같은 시그니처. 실제 D 구현이라고 표시하지 않는다."""
    validate_callback_context(request, state)
    context = state["file01_context"]
    if any(context[k] != request[k] for k in ("target_id", "os", "check_id", "before_scan_id")):
        raise ValueError("callback context mismatch")
    baseline = context["original_snapshot"]
    if context["expected_identity"] != baseline:
        raise ValueError("callback identity baseline mismatch")
    snapshot = deepcopy(state["files"][baseline["path"]])
    wrapper = diagnose(snapshot, version="1.2", expected_identity=baseline)
    return DiagnosisAggregator.from_results(
        [], [wrapper["c_result"]], target_id=request["target_id"], os=request["os"],
        schema_version="1.2",
    ).get_report()
