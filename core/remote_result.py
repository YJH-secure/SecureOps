"""원격 출력 형태를 가정하지 않는 개별 JSON 수신 파서.

이 함수의 인자는 D 내부 경계이며 공통 SSH API가 아니다. 향후 전송 어댑터가
실행 성공 여부와 종료 코드를 명시적으로 매핑해야 한다. SSH·명령 실행·저장 및
실환경 출처 판별은 하지 않는다. 반환값은 기존 from_results()에 전달할 항목이다.
"""

import json

from core.main import DiagnosisAggregator


class RemoteResultError(ValueError):
    """실행 실패·파싱·형식 오류. 원격 출력 원문은 메시지에 포함하지 않는다."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RemoteResultError("응답 JSON에 중복 키가 있습니다.")
        result[key] = value
    return result


def _reject_constant(value):
    raise RemoteResultError("응답 JSON에 비표준 숫자가 있습니다.")


def parse_result_json(stdout: str, *, exit_code: int,
                      execution_succeeded: bool, max_bytes: int = 1024 * 1024) -> dict:
    """성공적으로 종료된 응답의 개별 v1.1 결과 객체를 검증해 반환한다.

    stdout은 디코딩된 JSON 문서 하나여야 한다. 배열·보고서 envelope·로그를
    추측해 추출하지 않는다. timeout/연결 실패/종료 코드 미확인은 거부한다.
    max_bytes는 D의 자원 보호 한도이며 원격 전송에서도 별도 출력 제한이 필요하다.
    실행 성공은 진단 status=pass를 뜻하지 않는다. error/needs_review도 보존한다.
    """
    if type(execution_succeeded) is not bool:
        raise TypeError("execution_succeeded는 명시적인 bool이어야 합니다.")
    if not execution_succeeded:
        raise RemoteResultError("원격 실행 실패 응답은 진단 결과로 수신하지 않습니다.")
    if type(exit_code) is not int:
        raise TypeError("확인된 정수 exit_code가 필요합니다.")
    if exit_code != 0:
        raise RemoteResultError("원격 프로그램이 비정상 종료했습니다.")
    if not isinstance(stdout, str):
        raise TypeError("stdout은 디코딩된 JSON 문자열이어야 합니다.")
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes는 양의 정수여야 합니다.")
    try:
        if len(stdout) > max_bytes or len(stdout.encode("utf-8")) > max_bytes:
            raise RemoteResultError("응답 크기가 허용 한도를 초과했습니다.")
        item = json.loads(stdout, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except RemoteResultError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise RemoteResultError("응답을 올바른 JSON 문서로 읽을 수 없습니다.") from None
    if not isinstance(item, dict):
        raise RemoteResultError("개별 진단 결과는 JSON 객체 하나여야 합니다.")
    try:
        # 아래 메타데이터는 개별 항목 검증용이며 반환·저장되는 실제 스캔 정보가 아니다.
        validated = DiagnosisAggregator.from_results(
            [item], [], target_id="validation-only", os="validation-only",
            scan_id="validation-only", scanned_at="2000-01-01T00:00:00Z",
        ).get_report()["results"][0]
        json.dumps(validated, allow_nan=False)
    except (KeyError, TypeError, ValueError, RecursionError):
        raise RemoteResultError("개별 진단 결과가 JSON v1.1 규격에 맞지 않습니다.") from None
    return validated
