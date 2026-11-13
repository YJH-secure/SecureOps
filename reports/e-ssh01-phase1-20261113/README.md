# SSH-01 정책·핸들러 분리 1차 구현 검증

2026-11-13 · 로컬 구현 및 MOCK 테스트

## 기준과 작업 환경

- 기준 SHA는 PR #23 제출 HEAD `b0ef73a1613ebc40fdd596edcbaf0413d32309b8`이다.
- 신규 브랜치는 `feature/remediation-ssh01-registry-phase1`이다. HEAD는 기준 SHA와 같다.
- 별도 Git worktree는 기존 저장소 아래 `.venv/worktrees/ssh01-phase1`에 생성했다. 상위 저장소의 기존 ignore 규칙이 적용되는 위치를 선택했다.
- 생성 직후 Git 상태가 깨끗했고, 기준선 소스를 확인한 후 구현했다. 이전 미완성 코드의 복사·병합은 수행하지 않았다.
- 기존 작업 디렉터리의 상태는 시작·종료 시 동일하다. 설계 문서와 기존 .bak 2개는 시작 시 SHA-256과 같다.
- Windows / CPython 3.12.10 / jsonschema[format] 4.26.0. 독립 임베디드 Python 환경을 새 worktree의 .venv에 준비했다. PR #23의 과거 실행 환경은 CPython 3.12.14였다.

## 변경 파일과 핵심 diff

| 파일 | 변경 내용 |
| --- | --- |
| remediation/policies.py 신규 | 변경 불가능한 정책 레코드와 읽기 전용 레지스트리. SSH-01의 기존 OS, actions, 정책 버전 및 핸들러 연결 |
| remediation/handlers.py 신규 | 기준선 MockBackend의 SSH-01 사전 검증, 상태 복사, 조치, 설정 검증, 기존 유효값 재진단, 복원·서비스 검증 로직 이전 |
| remediation/engine.py | build_plan의 check_id 고정 분기를 레지스트리 조회로 교체. 동일 제외 우선순위와 Plan 구성 유지 |
| remediation/mock.py | 기존 단계·백업 토큰·공개 API·콜백을 유지하고 정책별 동작을 핸들러로 위임 |
| tests/test_remediation_policy_handler.py 신규 | 정책 고정성, 실제 위임, 공개 시그니처, 기준 SHA와 계획·MOCK 동작 비교, 실패·복원 및 미지원 항목 검증 12개 |
| reports/e-ssh01-phase1-20261113/ | 수정 전후 실행 로그·집계, 인코딩 재현, 계획 해시 비교 자료 및 재현 스크립트 |

추적 파일의 코드 diff는 engine.py와 mock.py에서 총 18줄 추가, 51줄 삭제다. 신규 파일은 이 수치에 포함되지 않는다. Remediator.run 및 Plan/Approval 정의의 변경은 없다. 기존 테스트 소스와 B/C/D, 공통 JSON 계약, CLI, 실행 이력 저장소의 추적 파일 diff는 없다.

정책 레지스트리에 등록된 항목은 SSH-01 1개다. 정책 내용은 기존 ssh-01-proposal-v1과 같다. plan을 받는 백엔드 메서드는 레지스트리의 handler를 선택한다. plan 인자가 없는 복원·복구 검증 메서드는 이번 범위의 SSH01MockHandler로 위임하며, 기존 전체 files/root_login/service_running 백업 형태를 유지한다.

MockFailure의 공개 import 경로와 예외 타입을 유지하기 위해 핸들러의 오류 경로에서 기존 remediation.mock.MockFailure를 지연 import한다. 신규 실행 상태·다중 항목 API·추가 취약점 조치 로직은 포함하지 않는다.

## 실제 실행 결과

| 실행 | 통과 | 실패 | 오류 | SKIP |
| --- | ---: | ---: | ---: | ---: |
| 수정 전 기준선의 기존 회귀 | 204 | 0 | 0 | 0 |
| 수정 후 기존 회귀 및 신규 단위 테스트 | 216 | 0 | 0 | 0 |
| 지정 SHA의 D 소스 추출 실행기 | 24 | 0 | 0 | 0 |
| 기본 cp949 환경의 v1.2 회귀 재현 | 17 | 0 | 1 | 0 |

216개는 기존 204개와 신규 12개의 합이다. 지정 SHA D 실행기의 24개는 기존 회귀 중 22+2개를 별도 프로세스로 다시 검증한 것이며 중복 합산하지 않는다. 기본 인코딩 재현 18개도 위 회귀와 중복이다. 이 범위는 PR #23의 E/D/C 연동 회귀 묶음이며 저장소 전체 테스트를 실행한 수치로 표시하지 않는다.

검증 항목은 승인 누락·거부·만료·ID 재사용, 계획 무결성, 사전 조건, 백업 실패, 조치·검증·재진단 실패와 롤백, 복구 실패, dry-run 부작용, 정확한 MockBackend 타입 제한, 기존 CLI, JSON v1.1/v1.2, CVSS scored/pending/not_applicable 및 null/0, D ReportStore 저장·재조회, E 실행 이력 저장·조회·버전 필드를 포함한다.

기준선 204개는 이번 작업에서 실제 재실행한 결과다. PR #23의 과거 204개 기록도 기존 파일에 보존된다.

## 실행 명령과 재현

모든 명령은 신규 worktree 루트에서 실행한다. 테스트 실행 전에 `jsonschema[format]==4.26.0`을 설치했다.

실제로 실행한 묶음 검증 명령은 다음과 같다. 당시 스크립트는 로컬 .venv에 두었으며 동일 내용의 재현 스크립트를 이 디렉터리에 포함했다.

```powershell
./.venv/python.exe -B .venv/verify.py baseline
./.venv/python.exe -B .venv/verify.py final
./.venv/python.exe -B .venv/check_encoding.py baseline
./.venv/python.exe -B .venv/check_encoding.py final
$env:PYTHONUTF8 = '1'
./.venv/python.exe -B tests/run_de_mock.py --d-ref b0ef73a1613ebc40fdd596edcbaf0413d32309b8
```

현재 구현의 묶음 검증은 아래 명령으로 재현할 수 있다. verify.py는 자식 CLI 프로세스에 PYTHONUTF8=1을 전달하고 SECUREOPS_D_SOURCE를 현재 worktree로 지정한다. unittest 패턴 test_remediation*.py, test_execution_history*.py, test_cvss*.py와 C firewall/log 테스트를 합친다. 개별 모듈 수는 test-modules.json에 기록했다.

```powershell
./.venv/python.exe -B reports/e-ssh01-phase1-20261113/verify.py rerun
./.venv/python.exe -B reports/e-ssh01-phase1-20261113/check_encoding.py rerun
```

신규 단위 테스트는 아래 명령으로도 실행한다.

```powershell
$env:PYTHONUTF8 = '1'
./.venv/python.exe -B -m unittest discover -s tests -p test_remediation_policy_handler.py -v
```

수정 전 로그는 baseline.log, 수정 후 로그는 final.log, 집계는 각각 baseline.json과 final.json이다. 별도 D 실행기 로그는 pinned-d-integration.log다. 로그에 포함된 작업 디렉터리는 `<WORKTREE>`로 치환했다.

## 계획 및 API 동일성

신규 테스트는 git show로 고정 기준 SHA의 원본 engine.py 및 mock.py를 직접 읽어 비교한다. 계획 비교는 원본 build_plan의 반환값과 신규 build_plan의 반환값을 대조한다. 과거 미완성 작업 디렉터리를 import하지 않는다.

28가지 입력 모두에서 actions, policy_version, source_digest, plan_id가 일치했다. Plan의 나머지 필드와 skip_reason도 일치한다. 입력 보고서의 불변성도 확인했다.

- v1.1/v1.2 각각 Ubuntu 24.04/24.04.5와 5종 진단 상태 20가지
- 각 버전의 OS 미지원·요청 항목 부재·정책 미등록 6가지
- v1.2 SSH-01 CVSS not_applicable/null 및 합성 평가 항목 0점 입력 2가지

v1.2 원본 fixture에는 scored 9.8, pending/null 및 not_applicable/null이 함께 포함돼 있다. 원본 전체 보고서 해시를 비교하므로 다른 항목의 CVSS도 계획 바인딩에 포함된다. 각 입력과 원본/신규 계획 및 해시의 실제 값은 plan-identity.json에 기록했다.

build_plan, Plan, Approval, Remediator 생성자 및 run, MockBackend 생성자와 기존 공개 메서드의 시그니처가 기준선과 일치함을 검사했다. 사전 검증 실패 코드, 백업 스냅샷, 파일·root_login·서비스 복원, 단계 이벤트와 v1.1/v1.2 재진단 객체도 원본 동작과 대조했다.

## UTF-8 오류와 남아 있는 문제

수정 전후 기본 환경에서 stdout.encoding은 cp949였다. CLI는 ensure_ascii=False인 JSON에 한글 문자열을 포함한다. Windows 파이프로 받은 cp949 바이트를 기존 테스트가 json.loads(bytes)에 전달하면 UTF-8 해석 중 UnicodeDecodeError가 발생한다. 같은 바이트를 cp949로 디코딩하면 유효한 success JSON으로 읽힌다.

PYTHONUTF8=1로 실행하면 자식 CLI 출력이 UTF-8이 되고 기존 테스트가 정상 통과한다. 수정 전후 인코딩 결과는 baseline-encoding.json과 final-encoding.json에 보존했다. 기본 환경에서 기존 test_remediation_v12.py를 실행한 18개 중 1개 오류의 원문은 default-encoding-v12.log에 기록했다.

이 환경 문제는 이번 리팩터링 후에도 기본 cp949 실행에서 재현된다. 현재 216개 통과는 UTF-8 실행 환경을 명시한 결과다. CLI 자체의 출력 인코딩 변경은 이번 네 파일 리팩터링 범위에서 수행하지 않았다. 계획 해시·조치 결과·저장 데이터의 기능 회귀는 검증 범위에서 발견되지 않았다.

1차 로컬 검증 완료 시점에는 코드·테스트·증거를 미커밋 상태로 보관했다. 기존 미완성 브랜치와 설계 문서는 보존했다.

## 승인 후 Draft PR 제출 검증

팀장 승인에 따라 신규 브랜치의 커밋·푸시 및 Draft PR 제출을 진행한다. 제출 전 `PYTHONUTF8=1` 환경에서 아래 명령으로 회귀를 재실행했다.

```powershell
$env:PYTHONUTF8 = '1'
./.venv/python.exe -B reports/e-ssh01-phase1-20261113/verify.py pre-push
```

결과는 216개 통과, 실패 0, 오류 0, SKIP 0이다. pre-push.log 및 pre-push.json에 이번 실행 기록을 보존했다. 기본 cp949 환경의 기존 재현 이슈는 앞 절의 기록을 따른다.

프로젝트 ADR-001은 기능 브랜치 PR 및 테스트 증거를 통한 검토를 명시한다. 원격 조회 시 PR #23은 열린 상태이며 head 브랜치 feature/remediation-cvss-v12의 SHA는 b0ef73a1613ebc40fdd596edcbaf0413d32309b8이다. 신규 PR의 base는 이 선행 브랜치로 선택한다. main 기준에는 선행 PR의 15개 커밋이 추가로 포함되므로, 이번 변경 범위는 선행 브랜치와의 diff로 검토한다.

이번 제출 파일은 SSH-01 정책·핸들러 분리 코드 4개, 신규 테스트 1개 및 이 검증 디렉터리의 텍스트 자료다. 기존 미완성 코드·설계 문서·백업·ZIP·Python 런타임은 제출 범위에서 제외한다. 기존 PR #23 및 main의 병합은 팀장 통합 절차에 따른 후속 작업이다.

공개 로그 사본은 Windows 중복 CR 및 줄 끝 공백을 정규화했다. 테스트 판정과 오류 내용은 실행 기록을 따른다.
