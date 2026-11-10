# D Core CVSS v3.1 Base / JSON v1.2 구현 및 검증 보고서

작성일: 2026-11-10 KST. 커밋·Push·PR 생성·Merge 전 작업 트리의 구현 결과다.
실행별 시각·환경·명령·결과·입력 해시는 [실행 메타데이터](environment-and-results.json)에 기록한다.

## 1. 기준선과 변경 범위

- 시작 브랜치: `feature/core-jhm`, 시작 작업 트리 깨끗함.
- 기준 D HEAD / PR #8 HEAD: `994d20c1d7a914ba8a77ab9e89ea7080c16e171e`.
- 작업 브랜치: `feature/cvss-core-jhm`. 기존 D 브랜치에서 생성했다.
- [PR #8](https://github.com/YJH-secure/SecureOps/pull/8)의 기존 기능을 유지했다.
- [PR #18](https://github.com/YJH-secure/SecureOps/pull/18)의 채택 결정 및 HEAD
  `0647f7e0de104c2a7196d34ccd6143f22731a0c3`을 확인했다.
- 요구된 정책·계약·Schema·MOCK 4개 파일은 위 커밋의 바이트를 그대로 반영했다.
  각 SHA-256 및 원본 일치 여부는 메타데이터에 기록했다.
- 기존 테스트·fixture·`core/legacy.py`·B/C 소스는 수정하지 않았다.
  Windows checkout의 CRLF/LF 차이는 Git diff 기준으로 판별한다.
- v1.1 검증 함수는 `_validate_report_v11`로 이름만 분리했다.
  함수 이름을 제외한 AST가 기존 `_validate_report`와 동일함을 확인했다.

이 보고서의 구현은 아직 커밋되어 있지 않다. HEAD만으로 새 구현을 재현할 수 없으며,
메타데이터의 파일 해시로 테스트한 작업 트리를 식별한다.
기존 `docs/evidence/`의 11월 9일 보고서와 로그는 덮어쓰지 않았다.

## 2. 계약 차이와 구현

| 영역 | v1.1 유지 | 신규 v1.2 |
|---|---|---|
| 결과 판정 | 5개 status | 동일 5개 status |
| 평가 필드 | severity 필수 | severity 금지, cvss 7개 필드 필수 |
| 검증 | 기존 검증 함수 보존 | 별도 `core/cvss_validation.py` |
| 집계 | severity_breakdown | cvss_rating_breakdown, cvss_assessment_breakdown |
| 이행률 | pass / (pass + vulnerable) | 동일, 분모 0이면 N/A |
| 저장·이력 | 기존 JSON 원본 버전 유지 | v1.2 원본 저장·조회, 혼합 버전 이력 가능 |
| 전후 연결 | 동일 버전의 check_id 연결 | 다른 버전의 직접 비교는 명시적 ValueError |

### 공식 계산기

`core/cvss.py`는 FIRST v3.1 Base의 공식 가중치 및 Scope별 산식을 구현한다.
8개 Base 메트릭만 받고 SecureOps 순서 `AV/AC/PR/UI/S/C/I/A`를 강제한다.
누락·중복·알 수 없는 값·버전·비정규 순서·Temporal/Environmental 확장은 거부한다.
Scope에 따라 PR 가중치를 선택하고, FIRST Appendix A의 정수 스케일 방식으로 Roundup한다.
기존 severity와 정책 우선순위는 계산에 사용하지 않는다.

### 검증과 D 계층 연결

- `scored`는 vulnerable에서만 허용한다. version=3.1, 공식 점수·등급 일치,
  비어 있지 않은 source/rationale을 검증한다.
- vulnerable의 pending/not_applicable 및 나머지 진단 상태의 not_applicable을 허용한다.
  미채점의 version/vector/base_score/rating은 모두 null이어야 한다.
- 숫자 점수는 0~10의 유한 값이며 0.1 단위다. bool·문자열·NaN·Infinity는 거부한다.
  JSON 숫자의 9와 9.0, 9.80과 9.8은 같은 숫자 값으로 취급한다. 문자열 표기 자릿수 대신
  수치 정밀도를 검증하며, 9.81 또는 9.80000000001은 거부한다.
- 중복 check_id, 실제 달력 날짜·시간대, 필수 필드·타입·추가 필드,
  JSON 중복 키, 비JSON Python 값·순환 참조·비정상 중첩을 검증한다.
- FILE-01 details를 수정하지 않으며 기존 깊은 복사·저장 보존 경로를 유지한다.
- `from_results`, `run_target`, `parse_result_json`에 `schema_version="1.2"`를 명시해야 한다.
  기본값은 기존 1.1이며 개별 항목을 추측해 버전을 선택하거나 자동 이전하지 않는다.
- v1.2 보고서는 최상위 schema_version으로 검증기를 선택한다.
- v1.2 집계에서 등급별 건수는 vulnerable AND scored에 한정한다.
  평가 상태별 건수는 전체 결과를 scored/pending/not_applicable로 구분한다.
- 점수가 없는 결과를 0.0으로 바꾸지 않는다. scored 0.0/none은 독립적으로 보존·집계한다.
- 점수 평균·합계나 전체 서버 위험도 지표는 추가하지 않았다.
- CLI는 파일 경로를 명시한 기존 직접 실행 방식과 `python -m core.main`을 모두 지원한다.
- v1.1→v1.2 자동 변환기는 추가하지 않았다. 기존 레거시 정규화는 v1.1 대상 그대로다.

런타임 검증은 표준 라이브러리로 구현하여 jsonschema 설치를 요구하지 않는다.
Schema 수용 테스트는 `jsonschema`의 Draft 2020-12 검증기를 사용한다.
테스트 의존성은 `requirements-test.txt`에 기록했다.

### 팀장 추가 승인 반영 — 명시적 평가 생성 경계

`core/cvss_assessment.py`의 `assess_cvss()`를 추가했다. B/C의 status/evidence/details를
바꾸지 않고 별도의 cvss 객체를 생성하는 D 내부 도우미다. B/C나 SSH의 확정 공통 API가 아니다.

- 호출자가 `cvss_applicable`로 적용 가능 여부를 명시한다. D는 정책 위반의 문구나 check_id로 판단하지 않는다.
- 취약 판정이면서 CVSS 적용 가능하지만 Vector·출처·8개 메트릭 근거 중 하나라도 없으면 pending이다.
- `evidence_sufficient`의 기본값은 False이다. 텍스트가 있다는 사실만으로 근거 검토가 끝났다고 보지 않는다.
  호출자의 명시적인 검토 완료 표시가 없으면 완전한 Vector와 근거를 넣어도 pending이다.
- 비대상 정책 위반 및 취약 판정이 아닌 결과에는 not_applicable을 생성한다.
- 두 미채점 상태는 version/vector/base_score/rating을 모두 null로 유지하고 rationale에 사유를 기록한다.
- 명시적인 적용 가능·검토 완료, 유효 Vector, source, 메트릭별 근거가 모두 있을 때만 공식 산식으로 계산한다.
  근거는 rationale에 메트릭 이름과 함께 보존한다. 입력 객체는 변경하지 않는다.
- 잘못된 Vector나 모순된 분류 입력은 오류다. 잘못된 Vector를 정상화하거나 조용히 미평가로 바꾸지 않는다.
- 근거의 사실성·충분성을 자연어에서 자동 판정하거나 승인을 대신하는 기능은 없다.

독립 계산기 → Vector 검증 → 별도 v1.2 검증 → 기존 D 저장/집계 연결의 모듈 분리를 유지했다.
PR #8 병합 후 main 기준으로 정리할 수 있으나, 이번 작업에서는 merge/rebase하지 않았다.

## 3. FIRST 공식 기대 점수

기대 점수는 실행 중 자체 계산기로 만들지 않고 FIRST 사례 문서의 상수로 고정했다.
Vector는 해당 사례의 메트릭 표를 SecureOps 정규 순서로 직렬화한 것이다.
아래 CVE는 계산기 검증 사례이며 SecureOps 서버에서 탐지된 취약점이 아니다.

| 출처 | Vector | 기대 점수 |
|---|---|---:|
| FIRST Examples §3, CVE-2013-0375 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N` | 6.4 |
| FIRST Examples §4, CVE-2014-3566 | `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N` | 3.1 |
| FIRST Examples §5, CVE-2012-1516 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` | 9.9 |
| FIRST Examples §6, CVE-2009-0783 | `CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L` | 4.2 |
| FIRST Examples §7, CVE-2012-0384 | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 7.2 |
| PR #18 계산용 MOCK | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **9.8 / critical** |

위 6개 기대값 대조가 모두 통과했다. 추가로 Scope U/C와 PR N/L/H 조합,
Roundup 경계, C/I/A=None의 0.0점 및 등급 경계를 검증했다.
2592개 Base 조합을 순회해 범위·0.1 단위·무영향=0 불변식을 확인했다.
2592개 전체를 별도의 공식 기대값 데이터와 대조했다고 주장하지 않는다.

공식 출처:

- [FIRST v3.1 Specification §7.1/§7.4/Appendix A](https://www.first.org/cvss/v3-1/specification-document)
- [FIRST v3.1 Examples §3~§7](https://www.first.org/cvss/v3-1/examples)

## 4. 최종 재실행 결과 — 고정 회귀 기준선

Windows 11 / AMD64 / CPython 3.14.2 / unittest 표준 라이브러리에서 실행했다.
jsonschema 4.25.1이 설치되어 Schema 테스트 4개도 실제 실행했다.
해당 설치에는 jsonschema의 선택적 date-time format checker가 없다.
따라서 Schema의 달력 날짜 검증까지 실행했다고 주장하지 않으며,
날짜·시간대의 의미 검사는 D 런타임 음성 테스트에서 별도로 수행해 통과했다.

| 실행 | 통과 | 건너뜀 | 실패 / 오류 | 로그 |
|---|---:|---:|---:|---|
| CVSS 계산기 | 11 | 0 | 0 / 0 | [01](logs/01-cvss-official.log) |
| v1.2 런타임·Schema·파이프라인 | 28 | 0 | 0 / 0 | [02](logs/02-json-v12.log) |
| 명시적 근거 검토·미평가 생성 | 13 | 0 | 0 / 0 | [09](logs/09-explicit-assessment.log) |
| 기존 v1.1 core 계층 | 70 | 0 | 0 / 0 | [03](logs/03-v11-core-regression.log) |
| 기존 v1.1 원격 파서 | 14 | 0 | 0 / 0 | [04](logs/04-v11-remote-regression.log) |
| D 작업 트리 전체 | **136** | **3** | 0 / 0 | [05](logs/05-full-worktree.log) |
| 기존 B/C 실제 판정 함수 오프라인 | 3 | 0 | 0 / 0 | [06](logs/06-actual-bc-v11-offline.log) |
| 고정 B/C 소스 제공 전체 | **139** | **0** | 0 / 0 | [07](logs/07-full-with-bc.log) |
| v1.2 MOCK CLI | 종료 코드 0 | 해당 없음 | 해당 없음 | [08](logs/08-v12-cli-mock.log) |

전체 139개는 기존 87개와 신규 52개이다. 행별 테스트는 중복되므로 합산하지 않는다.
subTest와 2592개 조합 순회는 독립 unittest 메서드 수에 추가하지 않는다.
기본 작업 트리에서 건너뛴 3개는 B/C 실제 소스 파일 부재 때문이다.
`jsonschema`가 없는 환경에서는 Schema 테스트 4개도 의존성 사유로 건너뛰도록 되어 있다.

기존 87개 회귀 기준을 재현할 때 사용한 실제 B/C 소스:

- B: `cfbd37b4dbd102ec894a2150d47f751ad5c74afa`의 `checks/account/ssh_check.py`.
- C: `6bb330feccfc6541bc145db9b6e18f24b4bce394`의 `file_check.py`, `common.py`,
  `policy_rules.py`, `link_check.py`.
- 이 커밋은 이전 87개 검증에 사용한 버전이다. 현재 B 브랜치 최신과 동일하다는 뜻이 아니다.
- Git 객체를 임시 경로에 읽어 환경변수 `SECUREOPS_B_SOURCE_ROOT`/
  `SECUREOPS_C_SOURCE_ROOT`로 제공했다. 실제 수집·명령·네트워크는 차단했다.

## 5. 현재 B 브랜치와의 호환 실패 — 미해결

고정 회귀 기준선 실행 전에 현재 로컬 B/C 추적 소스로도 시도했다.

- B 현재 참조: `3eda5a56ed3e9fd56d162676507c526ea0d1a1c1`.
- C 현재 참조: `782f568593c24626aa2cc87c398221bedd75e4aa`.
- B의 현재 함수는 `root_output=None` 인자가 추가되었고
  `criteria.vulnerable_values`를 필수 입력으로 읽는다.
- 기존 오프라인 테스트의 합성 정책에는 이 필드가 없으므로 B 콜백이 실패했다.
  B는 prohibit-password 등의 판정도 기존 needs_review에서 vulnerable로 변경했다.
- 기존 오프라인 테스트 3개 메서드가 모두 오류로 끝났다. unittest는 subTest를 포함해
  `errors=6`을 출력한다. 이는 서로 다른 테스트 메서드 6개를 뜻하지 않는다.
- 해당 소스를 제공한 전체 테스트 실행도 실패했다. 통과 결과로 대체하거나 숨기지 않았다.

증거:

- [현재 B/C 시도의 환경·커밋·명령·결과](attempts/current-bc-20261110/environment-and-results.json)
- [기존 오프라인 테스트의 실제 실패 로그](attempts/current-bc-20261110/06-actual-bc-v11-offline.log)
- [현재 B/C 제공 전체 실행의 실패 로그](attempts/current-bc-20261110/07-full-with-bc.log)

기존 테스트나 B 정책을 이번 CVSS 작업에서 임의 변경하지 않았다.
현재 B 인터페이스에 맞는 합성 정책·관측 데이터 및 기대 상태를 B 담당과 맞춘 뒤,
최신 소스를 대상으로 별도 통합 수용 테스트를 추가해야 한다.
따라서 **현재 B 브랜치와의 통합이 완료되었다고 보고하지 않는다.**

## 6. MOCK 파이프라인과 실제 연동 구분

v1.2 파이프라인 테스트는 합성 B/C 콜백 → JSON 수신 → run_target → 검증·집계 →
저장·재조회 흐름을 검증했다. FILE-01의 중첩 details 및 입력·저장 원본 보존을 포함한다.
기존 B/C 실제 판정 함수 테스트는 위 고정 소스의 **v1.1 결과**에 대한 회귀 검증이다.
B/C 실제 함수가 v1.2 결과를 제공했다고 주장하지 않는다.

PR #18 MOCK의 출력은 전체 4개, pass 1개, vulnerable 3개, 이행률 25.0%이다.
CVSS 상태는 scored 1개 / pending 1개 / not_applicable 2개,
채점된 취약 항목의 critical은 1개다. 이는 합성 데이터의 결과다.

실제 SSH 연결·VM 수집·진단·재진단·공통 SSH API 연동·Ubuntu/Rocky 실서버 및
Python 3.12 실행은 모두 **미실행**이다. E 모듈의 실제 호출·승인·조치도 검증하지 않았다.
같은 버전의 저장 결과 전후 연결만 D 테스트에서 확인했다.

## 7. B/C에 필요한 추가 데이터와 검토 사항

- CVSS 적용 가능성 및 구체적 취약 시나리오와 영향 근거.
- 채점 대상이면 AV/AC/PR/UI/S/C/I/A 각각의 관측·분석 근거와 정규 Vector.
- source/rationale에 기록할 평가 출처·분석 및 승인 기록. 단순 설정 위반을 CVE로 추정하지 않음.
- 근거가 없으면 vulnerable은 pending 또는 not_applicable, 그 외 status는 not_applicable로
  null 점수를 명시하는 v1.2 결과 어댑터가 필요하다. D는 B/C에 없는 메트릭을 채우지 않았다.
- 현재 B의 새로운 vulnerable_values 정책 및 root 조건 관측 인터페이스와 기대 판정의 정합성.
- E 호출자는 v1.2의 새 집계 키를 명시적으로 처리해야 한다. severity_breakdown과 혼용하지 않음.
- 버전 간 전후 비교는 현재 거부한다. 별도 승인된 명시적 이전 정책이 생기면 확장 가능하다.
- 숫자의 한 자리 정밀도는 수치 기준이다. JSON 토큰 표기 자체의 고정 자리수가 필요하면
  계약에 직렬화 규칙을 추가로 명시해야 한다.
- Schema title/description에는 DRAFT/Proposed라는 잔여 문구가 있으나 PR 채택 결정은 확정이다.
  실행 가능한 필드 제약과 본문 상태 조합에서 충돌은 발견하지 못했다. 원문은 수정하지 않았다.
- 기존 인자 없는 CLI 기본 경로의 v1.1 샘플 부재는 기존부터 있던 제한이다.
  이번 CLI 수용 테스트는 존재하는 v1.2 fixture 경로를 명시했다.

## 8. 재현 명령 및 산출물

```powershell
python -B -X utf8 -m unittest discover -s tests -p 'test_cvss.py' -v
python -B -X utf8 -m unittest discover -s tests -p 'test_cvss_v12.py' -v
python -B -X utf8 -m unittest discover -s tests -p 'test_cvss_assessment.py' -v
python -B -X utf8 -m unittest discover -s tests -p 'test_core*.py' -v
python -B -X utf8 -m unittest discover -s tests -p 'test_remote_result.py' -v
python -B -X utf8 -m unittest discover -s tests -v
python -B -X utf8 core/main.py tests/fixtures/sample-result-v1.2-MOCK.json
python -B -X utf8 docs/evidence/cvss-v1.2/run-cvss-evidence.py
```

마지막 명령은 로컬 고정 B/C 커밋을 제공하는 실행까지 포함하고 현재 위치의 최종 로그를 갱신한다.
기존 실패 시도 자료는 별도로 유지한다. 네트워크 fetch·checkout·Merge는 하지 않는다.
로그의 로컬 저장소·임시 디렉터리·Python 설치 경로는 치환했다.
인증정보·환경변수 덤프·실제 서버 데이터·실제 IP는 저장하지 않았다.

변경 파일:

- 수정: `core/main.py`, `core/runner.py`, `core/storage.py`, `core/remote_result.py`.
- 신규 구현: `core/cvss.py`, `core/cvss_validation.py`, `core/cvss_assessment.py`.
- 신규 테스트: `tests/test_cvss.py`, `tests/test_cvss_v12.py`, `tests/test_cvss_assessment.py`, `requirements-test.txt`.
- PR #18 원문 반영: 정책 문서·계약 문서·Schema·MOCK fixture 각 1개.
- 신규 증거: 이 보고서, 재실행 스크립트, 환경 JSON, 최종 로그 9개,
  현재 B 호환 실패의 환경 JSON 및 로그 2개.

Commit/Push/PR 생성 전에는 위 현재 B 호환 문제, B/C v1.2 실제 어댑터, E 연계,
실제 VM 검증 미완료 범위를 검토해야 한다. 사용자의 승인 없이 커밋·Push·PR 생성·Merge·rebase하지 않는다.
