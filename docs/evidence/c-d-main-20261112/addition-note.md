# PR20 추가 증거 — 공식 main C→D 독립 재검증

이 디렉터리는 기존에 실제 실행한 공식 main 재검증의 제출 사본이다. 이번 증거 정리·제출 단계에서
테스트를 새로 실행하지 않았다. 기존 PR20의 ZIP 검증 24개 파일과 설명·링크는 보존했다.

## 시점과 소스 구분

| 구분 | 입력 및 검증 기준 |
|---|---|
| 기존 PR20 ZIP 검증 | 제공 SecureOps_C_v12_VM.zip / D f7e4f16 기준의 과거 오프라인 기록 |
| PR27 병합 전 검증 | C d218166 / D 6bf80bb 기준의 별도 과거 기록 |
| **이번에 추가하는 기존 실행 증거** | **공식 C/D main 62d1bf72ef52c7455bc0c2dd624206eb8350f925** |

제출 전 fetch한 origin/main도 같은 62d1bf7이다. PR20 브랜치에 main 코드를 merge/cherry-pick하지 않았다.
PR20의 추가 전 HEAD는 0ed1c5efd3fb4b6d0cc97e5df3bf0d0da6c56faa다.

실제 D 독립 실행 시각: 2026-11-12 09:59:39–10:00:02 KST.
Windows 11 / Python 3.14.2 / jsonschema[format] 4.26.0.
[원래 재검증 보고서](report.md), [공유 요약](team-summary.md),
[환경·명령·기준 SHA·결과](environment-and-results.json), [의존성](dependencies.txt).

## 실제 기존 실행 결과

| 범위 | 통과 | 실패 | 오류 | Skip | 로그 |
|---|---:|---:|---:|---:|---|
| C 원본 회귀 | 163 | 0 | 0 | 0 | [01](logs/01-c-unit.log) |
| v1.2 상태 5종 | 5/5 | 0 | 0 | 0 | [03](logs/03-c-scenarios.log) |
| 잘못된 입력 거부 | 28/28 | 0 | 0 | 0 | [거부 JSON](official-scenarios/rejection-tests.json) |
| 원본 main 기본 D 전체 | 171개 메서드 OK | 0 | 0 | 1* | [04](logs/04-d-default.log) |
| 같은 main D 경로 지정 전체 | 173 | 0 | 0 | 0 | [05](logs/05-d-source-specified.log) |
| 기존 PR20 통합 | 9 | 0 | 0 | 0 | [06](logs/06-pr20-nine.log) |
| D 독립 통합 | 8 | 0 | 0 | 0 | [07](logs/07-d-independent-eight.log) |

*기본 원시 출력은 Ran 171 / OK(skipped=1)이다. E setUpClass가 SECUREOPS_D_SOURCE 미지정으로 Skip되며,
클래스 Skip은 testsRun과 별도 이벤트이므로 171에서 1을 빼 통과 메서드 수를 계산하지 않았다.
같은 main D를 지정한 실행에서는 E 연동 2개를 포함해 Skip 없이 통과했다.
범위가 겹치므로 위 숫자를 서로 다른 테스트 총합으로 더하지 않는다.

기본·경로 지정 실행에서 test_bc_offline_integration의 3개 메서드가 모두 OK다.
PR29에서 수정한 과거 fixture 오류 이벤트 6개는 재발하지 않았다. fixture나 기대값을 이번에 다시 수정하지 않았다.

## 실제 네 모듈 통합 보고서

[four-module-results.json](four-module-results.json)은 실제 FILE/SVC/FW/LOG 함수와 v1.2 어댑터의 합성 입력
결과를 D parse_result_json → run_target → 저장 → load로 처리한 기존 실행 증거다.
테스트 메서드 수에 이 별도 왕복을 추가하지 않았다.

| check_id | status | CVSS 상태 | 점수·등급 |
|---|---|---|---|
| FILE-01 | pass | not_applicable | null/null |
| SVC-01 | vulnerable | pending | null/null |
| FW-01 | error | not_applicable | null/null |
| LOG-01 | needs_review | not_applicable | null/null |

고유 ID 4개, 이행률 50.0%, pending 1/not_applicable 3/scored 0이다.
미평가 version/vector/base_score/rating/source의 null을 보존하고 CVSS 등급 건수는 모두 0이다.
status/evidence/recommendation/details와 저장·재조회 일치를 확인했다.
v1.1 기본 호환, JSON/CVSS 오류·중복 키/check_id 거부, scan_id 충돌 시 이전 원본 보존도 통과했다.
not_applicable의 5번째 상태는 별도 계약 fixture이며 네 모듈 보고서에 FILE-01을 중복 추가하지 않았다.

저장 증거는 PR20 재사용 2개 + 독립 13개 + 네 모듈 1개 = 16개, C 시나리오 저장 보고서는 별도 5개다.
[독립 결과](independent-results.json), [PR20 결과](pr20-results.json), [검증 명세](verification.json).

## 서후님 결과와 교차 확인

서후님 제공 SecureOps_C_MainRecheck_20261112.zip의 SHA-256은
f4292660d9b6aeba908079f3c0883f0d7a6aa2f8618c231bfd66dd06e1192247이다. ZIP은 제출하지 않았다.
서후님 Python 3.12.14 기록과 D의 Python 3.14.2 독립 기록을 구분했다.
87개 소스 Git blob SHA가 공식 main과 일치했고 163/5/28/171/173 건수도 일치했다.
[C 측 기록 요약](c-author-evidence-summary.json), [출력 비교](c-d-result-comparison.json).

네 모듈 status/evidence/recommendation/CVSS는 일치한다. 일부 details는 합성 policy_version/호스트/OS
메타데이터 및 FW의 CalledProcessError와 PermissionError 주입 차이이며 한 실행 안의 C 원본과 D 저장 결과는 일치했다.
C 측 CLI8건을 D가 별도로 다시 실행했다고 표시하지 않았다.

## 제출본·원본 보존과 재현

원래 실행 자료 경로는 docs/evidence/c-d-main-recheck-20261112/이며 제출 경로만 이 디렉터리로 구분했다.
원래 JSON 안의 실행 당시 경로·시각·원본 해시 표기는 역사적 기록으로 남겼다.
개인/민감 경로 대신 표시자를 사용하고 UTF-8/LF·후행 공백 정리를 적용했다.
재현 스크립트 사본의 로컬 checkout 절대경로는 <PR20_CHECKOUT>/<D_INDEPENDENT_CHECKOUT>으로 바꿨다.
숫자·기대값·상태·실행 시각은 변경하지 않았다.
[원본/제출본 변환과 SHA-256](source-transfer-manifest.json),
[기존 PR20 파일 보존](existing-pr20-preservation.json), [제출 파일 해시](submitted-file-hashes.json).

기존 독립 테스트 소스는 reproduction-sources/의 증거 스냅샷이다. tests/에는 추가하지 않았다.
재현 시 고정 main의 별도 checkout에 필요한 경로로 복원하고 소스 표시자를 설정해야 한다.
기존 결과 폴더에서 재실행하거나 현재 PR20의 과거 기반을 최신 main checkout으로 오인하지 않는다.
원래 보고서의 'Commit·Push 미수행' 문구는 실행 당시 상태이며 이번 증거 제출 여부와 구분한다.

실제 SSH/VM·운영 조치·서버 설정 변경은 미검증이다. 공통 실행 계층·권한 인수와 운영 정책 보류는 후속 사항이다.
PR20은 Draft로 유지한다. Ready 전환·Merge·새 PR 생성은 수행하지 않는다.
