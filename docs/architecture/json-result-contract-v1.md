# SecureOps 공통 JSON 결과 규격 v1.0 (5개 상태값 반영 · 팀 검토본)

- 작성 담당: 양지혁 (아키텍처 / 인터페이스 설계)
- 관련 Issue: #2 ARCH-01
- 작업 브랜치: `feature/architecture-yjh`
- 상태: **팀장 결정사항 `needs_review` 반영 · 필드/연동 방식은 팀 검토 중**
- 수정일: 2026-11-05
- 변경: `needs_review` 신규 상태값 추가, 집계·이행률·조치 차단 규칙 명시

## 1. 왜 필요한가?

최종욱 담당 계정/SSH 진단과 김서후 담당 시스템 진단이 서로 다른 값을 반환하면 조효민 담당 통합 분석에서 결과를 일관되게 처리하기 어렵다. 모든 진단 코드는 동일한 **진단 항목 구조**를 반환하고, 통합 모듈은 서버별 결과를 한 번에 담는 **JSON 보고 객체**를 만든다.

- Python (`.py`): 실제 진단/분석/조치 프로그램
- JSON (`.json`): 프로그램이 만든 진단 결과의 표현 및 전달 형식
- JSON 결과를 매번 GitHub에 올릴 필요는 없다. 테스트용 가상 예시만 공유한다.

## 2. 권장 JSON 구조 (서버 1대의 진단 결과)

```json
{
  "schema_version": "1.0",
  "target_id": "ubuntu-a",
  "scanned_at": "2026-11-05T09:00:00+09:00",
  "results": [
    {
      "check_id": "SSH-01",
      "status": "vulnerable",
      "severity": "high",
      "evidence": "Effective SSH setting: PermitRootLogin yes"
    },
    {
      "check_id": "FILE-01",
      "status": "pass",
      "severity": "medium",
      "evidence": "Example file permission check passed"
    },
    {
      "check_id": "SVC-01",
      "status": "needs_review",
      "severity": "medium",
      "evidence": "Example only: running service requires business-purpose verification"
    }
  ]
}
```

**주의:** 위 값은 규격을 설명하기 위한 **가상 테스트 데이터**이며 실제 서버를 점검한 결과가 아니다. `SSH-01` 등의 실제 정의와 심각도는 취약점 점검 기준표에 맞춰 확정한다.

### 최상위 필드

| 필드 | 자료형 | 필수 | 의미 |
| --- | --- | --- | --- |
| `schema_version` | string | 예 | 결과 규격 버전, 현재 `"1.0"` |
| `target_id` | string | 예 | 서버 식별자 (예: `ubuntu-a`). 로그인 정보 대신 별도 식별자 사용 |
| `scanned_at` | string | 예 | 진단 시각, ISO 8601 + 타임존 (예: `+09:00`) |
| `results` | array | 예 | 한 서버에 대해 수행한 개별 점검 결과 목록 |

### `results` 배열 내부의 항목별 필드

| 필드 | 자료형 | 필수 | 의미 |
| --- | --- | --- | --- |
| `check_id` | string | 예 | 공통 취약점 점검 기준표의 점검 ID |
| `status` | string | 예 | `pass`, `vulnerable`, `error`, `not_applicable`, `needs_review` 중 하나 |
| `severity` | string | 예 | `critical`, `high`, `medium`, `low` 중 하나 (항목별 기본 위험도 정책) |
| `evidence` | string | 예 | 판단 근거 또는 오류 원인. 비밀번호, 토큰, 개인키 등 비밀값 제외 |

## 3. 상태값 정의 — 서로 혼동하지 않기

- `pass`: 설정을 검사했고 기준을 만족함
- `vulnerable`: 설정을 검사했고 기준을 만족하지 못함
- `error`: SSH 연결/권한/파싱 등의 이유로 검사에 실패함. **취약으로 단정하지 않음**
- `not_applicable`: 대상 환경에 해당 점검 항목이 적용되지 않음
- `needs_review`: 설정값은 수집했으나 서비스의 업무 필요성처럼 **사람의 추가 판단이 있어야** 최종 양호/취약 판정을 내릴 수 있음. 이 상태를 `error`나 `pass`로 임의 변환하지 않음

**중요:** `error`는 검사 실패, `needs_review`는 검사 정보를 얻었으나 수동 판단이 필요한 상태다. 점검 기준상 명백히 취약한 경우에는 `needs_review`로 우회하지 않고 `vulnerable`을 사용한다.

`severity`는 점검 항목에 부여된 기본 중요도이며, `status`와 다른 개념이다. `pass`라고 해서 `severity`가 없어지거나 `low`로 바뀌지 않는다. 서버별 종합 위험도 계산 방법은 추후 별도 정책으로 정의한다.

## 4. 팀원별 인터페이스 약속 (제안)

1. **최종욱 / `checks/account/`**: SSH·계정 항목별 Python 함수가 점검 결과 **딕셔너리 1개**를 반환한다.
2. **김서후 / `checks/system/`**: 파일·서비스·방화벽·로그 항목별 Python 함수가 동일한 형태의 **딕셔너리 1개**를 반환한다.
3. **조효민 / `core/`**: 위 딕셔너리들을 모아 `results` 배열을 만들고, `schema_version`, `target_id`, `scanned_at`을 추가하여 JSON으로 저장하거나 전달한다. 필수 키와 허용값도 검증한다.
4. **박태준 / `remediation/`**: `needs_review` 상태에는 자동 조치를 적용하지 않고, `vulnerable` 결과를 참고하되 **승인 여부 및 허용된 조치 항목을 별도로 검증**한 뒤 조치한다. 조치 후 같은 진단을 재실행하여 결과를 비교한다.
5. **양지혁 / `docs/`**: 점검 ID·상태값·위험도 정책과 모듈 간 계약을 검토하고 변경을 관리한다.
6. **김민우 / `infrastructure/`**: 진단 대상 서버와 중앙 관리 서버의 접속/권한 환경을 준비한다.

**추가 합의 (2026-11-05):** 최종욱·김서후는 필요한 경우 `needs_review`를 생성하며, 조효민은 이를 별도 건수로 집계한다. 관리자 검토 절차·최종 판정 이력 기능은 2차 구현 항목으로 남긴다.

**현재는 실행 방식이 확정 전이다.** 초기에는 로컬 가상 결과로 출력 형식을 검증하고, 이후 중앙 서버가 SSH로 원격 설정을 수집하도록 연동한다. 진단 모듈에 각자 SSH 접속 코드를 중복으로 만들지 여부는 인터페이스 설계 시 확정한다.

## 5. Python 결과 작성 예시

아래 코드는 **원격 진단 코드가 아니라 JSON 출력 형식을 보여주는 학습용 예제**다.

```python
import json
from datetime import datetime, timezone

ssh_check_result = {
    "check_id": "SSH-01",
    "status": "vulnerable",
    "severity": "high",
    "evidence": "Example only: PermitRootLogin yes",
}

report = {
    "schema_version": "1.0",
    "target_id": "ubuntu-a",
    "scanned_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
    "results": [ssh_check_result],
}

print(json.dumps(report, ensure_ascii=False, indent=2))
```

## 6. 결과 집계 및 이행률 (공통 처리 기준)

- 전체 건수: `results` 배열의 전체 항목 수
- 판정 완료 건수: `pass + vulnerable`
- 양호 이행률: `pass / (pass + vulnerable) * 100` (판정 완료 항목 기준)
- `error`, `not_applicable`, `needs_review`는 이행률의 분자·분모에서 **제외**, 단 각 상태를 독립된 건수로 표시
- `pass + vulnerable = 0`이면 이행률을 **`N/A (계산 불가)`**로 표시. 0% 또는 100%로 간주하지 않음
- 판정 완료 건수 및 전체 건수를 이행률과 같이 표시하여 오류·미확정 항목이 많을 때 오해를 줄임
- 위험도 점수는 양호 이행률과 별도로 정의하며, 현재 수식은 위험도 점수 계산이 아님
- 미정의 상태값(예: `unknown`)이 들어오면 조용히 무시하거나 `pass` 처리하지 않고 **데이터 검증 오류**로 기록
- 각 결과 객체에는 `check_id`, `status`, `severity`, `evidence`가 필요. 누락·자료형 오류도 검증 실패로 처리

### 테스트 예시

| 상태 | 개수 | 이행률 포함 여부 |
| --- | ---: | --- |
| `pass` | 2 | 분자·분모 포함 |
| `vulnerable` | 3 | 분모 포함 |
| `error` | 1 | 제외, 별도 집계 |
| `not_applicable` | 1 | 제외, 별도 집계 |
| `needs_review` | 1 | 제외, 별도 집계 |

총 8건 / 판정 완료 5건 / 양호 이행률 **40.0%**. 이 표는 가상 테스트 예시이다.

## 7. 보안 및 협업 수칙

- 진단 로직은 **기본 읽기 전용**으로 개발하며, 관리자 승인 없이 보안 설정을 변경하지 않는다.
- JSON의 `evidence`에 인증 정보·민감한 사용자 정보·개인키 원문을 넣지 않는다.
- 실제 결과/운영 서버 정보는 공개 저장소나 PR에 무분별하게 올리지 않는다. GitHub에는 가상/비식별화 테스트 예시를 권장한다.
- 진단 실패 시 `pass`나 `vulnerable`로 추정하지 않고 `error`를 기록한다.
- `needs_review` 항목은 관리자 검토 후 최종 판정이 기록되기 전에는 자동 보안 조치를 수행하지 않는다.
- 팀원별 코드는 각자 `feature/` 브랜치와 담당 폴더에서 작업하고 PR로 검토한다.
- 스키마 변경은 임의로 하지 않고 팀 합의와 문서 버전 갱신 후 적용한다.

## 8. 확정해야 할 사항

- [x] 다섯 번째 상태값 `needs_review` 추가 (팀장 결정, 2026-11-05)
- [ ] 공통 필드 및 이름에 대한 팀원 합의
- [ ] `SSH-01`, `FILE-01` 등 점검 ID와 위험도 표준표 대조
- [ ] 중앙 관리 서버의 SSH 수집 모듈 담당 및 실행 방식
- [ ] JSON 저장 경로 및 파일명 규칙
- [ ] 진단 오류 상세 표현 (예: 오류 코드 추가)
- [ ] 서버별 위험도 계산 방식과 조치 승인 기록 형식
- [ ] Ubuntu 첫 통합 테스트 후 Rocky Linux 확장 호환성 확인

---
이 문서는 팀의 상태값 결정 내용을 반영한 **v1.0 검토본**이며 실제 구현/검증 완료를 의미하지 않는다.
