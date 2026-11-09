"""단일 서버 MOCK 실행 계층. 실제 진단·SSH 함수는 포함하지 않는다."""

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.main import DiagnosisAggregator
from core.storage import ReportStore


@dataclass(frozen=True)
class CheckFailure:
    area: str
    index: int
    cause: Exception


class RunFailed(RuntimeError):
    """실행·반환값 실패. 부분 결과는 참고용이며 공통 보고서가 아니다.

    cause에는 원래 예외를 보존하므로 로그로 출력하기 전 민감정보 검토가 필요하다.
    기본 메시지에는 콜백 예외 원문이나 진단 근거를 포함하지 않는다.
    """

    def __init__(self, failures, partial_results):
        self.failures = tuple(failures)
        self.partial_results = deepcopy(partial_results)
        locations = ", ".join(f"{failure.area}[{failure.index}]" for failure in failures)
        super().__init__(f"진단 호출 또는 반환값 검증 실패: {locations}. 보고서를 저장하지 않았습니다.")


@dataclass(frozen=True)
class RunResult:
    mode: str
    path: Path
    report: dict
    summary: dict


def run_target(*, account_checks: list[Callable], system_checks: list[Callable],
               target_id: str, os: str, output_root, mode: str,
               scan_id=None, scanned_at=None) -> RunResult:
    """호출 → 개별 검증 → 통합 검증 → 저장. 이번 단계는 mode='mock'만 지원.

    각 호출 객체는 인자 없이 호출 가능하고 개별 v1.1 결과 dict를 반환한다.
    실제 함수의 인자는 향후 확인 후 호출자가 closure/partial로 묶는다.
    서로 다른 출처를 자동 판별할 수 없으므로 실제 VM 함수를 주입하지 않는다.
    실행 출처·저장 경로는 공통 JSON 바깥에서 관리한다.
    """
    if mode != "mock":
        raise ValueError("현재 MOCK 모드만 지원합니다. 실제 VM 인터페이스는 연결되지 않았습니다.")
    for name, checks in (("account_checks", account_checks), ("system_checks", system_checks)):
        if not isinstance(checks, list) or any(not callable(check) for check in checks):
            raise TypeError(f"{name}: 호출 가능한 객체의 list가 필요합니다.")
    # 메타데이터 오류는 진단을 실행하기 전에 거부한다. 누락값 생성은 from_results에 맡긴다.
    DiagnosisAggregator._validate_fields({"target_id": target_id, "os": os},
                                        {"target_id": str, "os": str}, {}, "target")
    if scan_id is not None:
        DiagnosisAggregator._validate_fields({"scan_id": scan_id}, {"scan_id": str}, {}, "run")
    if scanned_at is not None:
        DiagnosisAggregator._validate_fields({"scanned_at": scanned_at}, {"scanned_at": str}, {}, "run")
        DiagnosisAggregator._validate_timestamp(scanned_at, "scanned_at")

    collected = {"account": [], "system": []}
    failures = []
    for area, checks in (("account", account_checks), ("system", system_checks)):
        for index, check in enumerate(checks):
            try:
                item = check()
                # 콜백 원본을 즉시 복사하고 기존 검증기를 그대로 사용한다.
                validated = DiagnosisAggregator.from_results(
                    [item], [], target_id=target_id, os=os,
                    scan_id="mock-validation", scanned_at="2000-01-01T00:00:00Z",
                ).get_report()["results"][0]
                collected[area].append(validated)
            except Exception as error:
                failures.append(CheckFailure(area, index, error))
    if failures:
        raise RunFailed(failures, collected)

    aggregator = DiagnosisAggregator.from_results(
        collected["account"], collected["system"], target_id=target_id, os=os,
        scan_id=scan_id, scanned_at=scanned_at,
    )
    report = aggregator.get_report()
    # 저장소 생성 전 최종 검증·민감정보 검사를 수행한다.
    ReportStore._validate(report)
    store = ReportStore(Path(output_root) / "mock")
    path = store.save(report)  # 저장 실패 예외는 숨기지 않고 호출자에게 전달한다.
    return RunResult("mock", path, report, aggregator.aggregate_results())
