# SecureOps 공통 JSON 결과 규격 v1.0 (검토 초안)

- 작성 담당: 양지혁 (아키텍처 / 인터페이스 설계)
- 관련 Issue: #2 ARCH-01
- 작업 브랜치: `feature/architecture-yjh`
- 상태: **팀 검토 전 초안 — 아직 최종 확정 아님**

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
| `status` | string | 예 | `pass`, `vulnerable`, `error`, `not_applicable` 중 하나 |
| `severity` | string | 예 | `critical`, `high`, `medium`, `low` 중 하나 (항목별 기본 위험도 정책) |
| `evidence` | string | 예 | 판단 근거 또는 오류 원인. 비밀번호, 토큰, 개인키 등 비밀값 제외 |

## 3. 상태값 정의 — 서로 혼동하지 않기

- `pass`: 설정을 검사했고 기준을 만족함
- `vulnerable`: 설정을 검사했고 기준을 만족하지 못함
- `error`: SSH 연결/권한/파싱 등의 이유로 검사에 실패함. **취약으로 단정하지 않음**
- `not_applicable`: 대상 환경에 해당 점검 항목이 적용되지 않음

`severity`는 점검 항목에 부여된 기본 중요도이며, `status`와 다른 개념이다. `pass`라고 해서 `severity`가 없어지거나 `low`로 바뀌지 않는다. 서버별 종합 위험도 계산 방법은 추후 별도 정책으로 정의한다.

## 4. 팀원별 인터페이스 약속 (제안)

1. **최종욱 / `checks/account/`**: SSH·계정 항목별 Python 함수가 점검 결과 **딕셔너리 1개**를 반환한다.
2. **김서후 / `checks/system/`**: 파일·서비스·방화벽·로그 항목별 Python 함수가 동일한 형태의 **딕셔너리 1개**를 반환한다.
3. **조효민 / `core/`**: 위 딕셔너리들을 모아 `results` 배열을 만들고, `schema_version`, `target_id`, `scanned_at`을 추가하여 JSON으로 저장하거나 전달한다. 필수 키와 허용값도 검증한다.
4. **박태준 / `remediation/`**: `vulnerable` 결과를 참고하되 **승인 여부 및 허용된 조치 항목을 별도로 검증**한 뒤 조치한다. 조치 후 같은 진단을 재실행하여 결과를 비교한다.
5. **양지혁 / `docs/`**: 점검 ID·상태값·위험도 정책과 모듈 간 계약을 검토하고 변경을 관리한다.
6. **김민우 / `infrastructure/`**: 진단 대상 서버와 중앙 관리 서버의 접속/권한 환경을 준비한다.

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

## 6. 보안 및 협업 수칙

- 진단 로직은 **기본 읽기 전용**으로 개발하며, 관리자 승인 없이 보안 설정을 변경하지 않는다.
- JSON의 `evidence`에 인증 정보·민감한 사용자 정보·개인키 원문을 넣지 않는다.
- 실제 결과/운영 서버 정보는 공개 저장소나 PR에 무분별하게 올리지 않는다. GitHub에는 가상/비식별화 테스트 예시를 권장한다.
- 진단 실패 시 `pass`나 `vulnerable`로 추정하지 않고 `error`를 기록한다.
- 팀원별 코드는 각자 `feature/` 브랜치와 담당 폴더에서 작업하고 PR로 검토한다.
- 스키마 변경은 임의로 하지 않고 팀 합의와 문서 버전 갱신 후 적용한다.

## 7. 확정해야 할 사항

- [ ] 공통 필드 및 이름에 대한 팀원 합의
- [ ] `SSH-01`, `FILE-01` 등 점검 ID와 위험도 표준표 대조
- [ ] 중앙 관리 서버의 SSH 수집 모듈 담당 및 실행 방식
- [ ] JSON 저장 경로 및 파일명 규칙
- [ ] 진단 오류 상세 표현 (예: 오류 코드 추가)
- [ ] 서버별 위험도 계산 방식과 조치 승인 기록 형식
- [ ] Ubuntu 첫 통합 테스트 후 Rocky Linux 확장 호환성 확인

---
이 문서는 팀 개발 시작을 위한 **v1.0 검토 초안**이며 실제 구현/검증 완료를 의미하지 않는다.
