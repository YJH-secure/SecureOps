# 최신 main 공식 C → D 독립 오프라인 재검증

## 기준·출처 구분

- C/D 실제 checkout 및 fetch한 origin/main: `62d1bf72ef52c7455bc0c2dd624206eb8350f925`.
- PR29 fixture 수정 `80e73efd8b4d7300d5df2fb912019656eb5e50fe`와 PR27 병합이 포함됐다.
- 별도 Worktree 브랜치: `feature/c-d-main-recheck-jhm`.
- 첨부 `SecureOps_C_MainRecheck_20261112.zip` SHA-256:
  `f4292660d9b6aeba908079f3c0883f0d7a6aa2f8618c231bfd66dd06e1192247`.
- ZIP은 서후님의 기존 실행 증거다. 별도 비공개 입력 디렉터리에 경로·크기·링크·CRC/해시 검사 후 해제했다.
  72개 항목 중 파일별 해시를 [ZIP 명세](input-zip-manifest.json)에 기록했다.
  ZIP의 보조 스크립트나 역사적 실측 예제를 실행·재사용하지 않았다.
- 서후님 VERIFIED_SOURCE의 87개 Git blob SHA가 실제 공식 main과 모두 일치했다.
  [C 측 증거 요약](c-author-evidence-summary.json)은 원본 개인 경로를 옮기지 않은 요약이다.

시점별 구분:

| 기록 | 소스·D 기준 | 이번 결과와의 관계 |
|---|---|---|
| 최초 ZIP / PR20 | 별도 제공 ZIP, D f7e4f16 | 과거 기록 보존. 공식 main 실행으로 바꾸지 않음 |
| PR27 병합 전 독립 검증 | C d218166 / D 6bf80bb | 독립 8·PR20 9·고정 소스 전체 190 통과 및 당시 기본 fixture 오류는 과거 기록 |
| 서후님 최신 ZIP 재검증 | main 62d1bf7, Python 3.12.14 | C 측 자체 실행. 이번 D 실행과 별도 |
| **이번 D 독립 재검증** | **C/D main 62d1bf7, Python 3.14.2** | 정상 Git Worktree에서 새 Python 프로세스로 실행 |

## 실제 새 실행 결과

2026-11-12 09:59:39–10:00:02 KST.
Windows 11 / CPython 3.14.2 / 별도 검증 가상환경 / jsonschema[format] 4.26.0.
Git blob과 tracked 파일의 내용(체크아웃 CRLF/LF 차이 제외)을 검증했고 실행 전후 tracked 해시가 일치했다.

| 범위 | 통과 | 실패 | 오류 | Skip | 로그 |
|---|---:|---:|---:|---:|---|
| 공식 main C 원본 회귀 | 163 | 0 | 0 | 0 | [01](logs/01-c-unit.log) |
| C 작성 v1.2 상태 시나리오 | 5/5 | 0 | 0 | 0 | [03](logs/03-c-scenarios.log) |
| JSON/CVSS/전달 조건 거부 | 28/28 | 0 | 0 | 0 | [거부 JSON](official-scenarios/rejection-tests.json) |
| 원본 main 기본 D 전체 | 171개 메서드 OK | 0 | 0 | 1* | [04](logs/04-d-default.log) |
| 원본 main D 경로 지정 전체 | 173 | 0 | 0 | 0 | [05](logs/05-d-source-specified.log) |
| PR20 원본 테스트 | 9 | 0 | 0 | 0 | [06](logs/06-pr20-nine.log) |
| 기존 D 독립 테스트 | 8 | 0 | 0 | 0 | [07](logs/07-d-independent-eight.log) |

*기본 출력은 Ran 171 / OK(skipped=1)이다. Skip은 SECUREOPS_D_SOURCE 미지정으로 생기는 기존 E setUpClass 1개다.
클래스 Skip은 testsRun과 다른 이벤트이므로 171에서 1을 빼 통과 메서드 수로 계산하지 않았다.
같은 main D 경로를 지정하면 기존 E 연동 2개까지 실행해 173개 모두 통과한다.

기본·D 경로 지정 실행은 별도 검증 테스트 파일을 복사하기 **전에 원본 main tests/**에서 실행했다.
그 후 PR20 9개와 독립 8개 파일을 이전 Worktree에서 바이트 동일하게 복사해 각각 실행했다.
기존 테스트·입력·Skip 조건을 수정하지 않았다. 소스 환경변수의 legacy ZIP/PR27 명칭과 관계없이
이번 실제 입력은 같은 공식 main checkout이다.
기존 D CVSS 52개·v1.1 84개·FIRST 공식 사례도 전체 회귀에 포함된다.
대상 범위가 겹치므로 표의 숫자를 서로 다른 테스트의 총합으로 계산하지 않는다.

## 상태·거부·원본 보존

공식 main의 실제 FILE/SVC/FW/LOG 진단·수집 함수와 result_adapter를 사용했다.
명령·OS·호스트·파일 메타데이터는 합성 입력 경계에서 제공했으며 실제 판정·직렬화 결과를 대체하지 않았다.
not_applicable 시나리오는 계약 fixture이고 실제 FILE 자동 제외 판정 구현 증거가 아니다.

- v1.1 기본 출력과 severity 보존, D 기본 수신·저장·재조회 경로가 통과했다.
- v1.2 status 5종 수신, vulnerable/pending 및 그 외/not_applicable을 확인했다.
  version/vector/base_score/rating/source는 null이고 임의 scored나 점수를 생성하지 않았다.
- evidence/recommendation/details와 error/needs_review의 원본을 보존했다.
- 잘못된 JSON, 중복 JSON 키, 혼합/다중 JSON, 부적절한 CVSS 조합을 거부했다.
- 같은 보고서의 중복 check_id를 거부했고 같은 scan_id 재저장 시 기존 바이트를 보존했다.
- 유효한 status=error JSON은 진단 오류로 수신하고, 비정상 종료·실행 성공 플래그 실패는 별도 거부했다.
- FILE 중첩 details의 복사 독립성과 D 저장·재조회·집계 일치를 확인했다.

PR20 결과는 [pr20-results.json](pr20-results.json), 독립 결과는 [independent-results.json](independent-results.json)에 있다.
실제 저장 보고서는 pr20-reports 2개, independent-reports 13개이며 각각 다시 조회했다.

## 네 모듈을 한 보고서로 통합

독립 8개 실행 후 별도 MOCK 왕복을 추가 수행했다. unittest 메서드 수에 더하지 않는다.
실제 C 함수의 결과를 v1.2로 직렬화한 뒤 parse_result_json(schema_version=1.2) →
run_target(mode=mock, schema_version=1.2) → 저장 → load를 수행했다.

| check_id | 실제 status | CVSS | 점수/등급 |
|---|---|---|---|
| FILE-01 | pass | not_applicable | null/null |
| SVC-01 | vulnerable | pending | null/null |
| FW-01 | error | not_applicable | null/null |
| LOG-01 | needs_review | not_applicable | null/null |

고유 ID 4개, pass/vulnerable/error/needs_review 각 1개, 이행률 50.0%,
CVSS scored=0/pending=1/not_applicable=3이다. 모든 등급별 scored 취약 건수는 0이다.
다섯 번째 not_applicable fixture를 FILE-01과 중복해 같은 보고서에 넣지 않았다.
[결과·집계·원본](four-module-results.json), [실제 저장 보고서](four-module-store/mock).

PR20의 기존 네 모듈 입력은 FILE vulnerable / SVC·FW needs_review / LOG error를 만드는 다른 합성 사례다.
이를 이번 네 모듈 상태나 서후님 입력과 같다고 바꾸지 않았다.

## PR29 오류 재발 확인

기본·D 경로 지정 전체 실행 모두 test_bc_offline_integration의 세 메서드가 OK였다.
과거 세 메서드/네 subtest에서 발생했던 오류 이벤트 6개는 재발하지 않았다.
현재 main에 병합된 vulnerable_values/test_connection과 prohibit-password=vulnerable 기대값을 그대로 사용했다.
fixture 추가 수정·강제 Skip·과거 B/C 커밋 주입으로 통과시킨 결과가 아니다.

## 서후님 결과와 비교

C 163, 상태 5, 거부 28, D 기본 171/클래스 Skip 1, D 경로 지정 173이 모두 일치한다.
네 모듈 status/evidence/recommendation/cvss도 각각 일치했다([세부 비교](c-d-result-comparison.json)).

세부 details 일부는 다음 합성 입력 차이로 다르다.

- SVC: 합성 policy_version·hostname 및 OS collection_origin 메타데이터.
- FW: C 측 CalledProcessError와 D 독립 입력 PermissionError의 종류·종료 코드·reason 및 합성 메타데이터.
- LOG: 합성 policy_version 및 OS collection_origin.
- FILE details는 동일하다.

이는 서로 다른 MOCK 입력 경계의 세부 근거 차이다. 한 실행 안에서 C가 반환한 원본과 D 저장 결과는
모두 일치했다. 차이를 숨기거나 양쪽 details를 억지로 같은 값으로 바꾸지 않았다.

환경·재현 방식 차이도 구분한다. 서후님은 Python 3.12.14와 Git blob 검증 스냅샷/fixture-only Git 참조를 사용했고,
이번 D 실행은 Python 3.14.2와 실제 고정 main Worktree의 Git 참조를 사용했다.
첨부 ZIP의 CLI 8건은 C 측 MOCK 주입 결과다. 이번에 별도의 동일 8건 CLI 프로그램을 실행했다고 추가 집계하지 않는다.
C 원본 회귀에는 실제 로컬 CLI 오류 출력·비정상 인자 종료 및 어댑터 CLI 검사도 포함된다.

## 재현·증거와 후속 공유

[환경·정확한 명령·시간·소스 해시](environment-and-results.json), [의존성](dependencies.txt).

```powershell
python -B -X utf8 -m unittest discover -s checks/system/tests -v
python -B -X utf8 -m checks.system.verify_json_scenarios --help
python -B -X utf8 -m checks.system.verify_json_scenarios --code-commit 62d1bf72ef52c7455bc0c2dd624206eb8350f925 --d-root <MAIN_CHECKOUT> --output-dir <NEW_OUTPUT>
python -B -X utf8 -m unittest discover -s tests -v
# 아래 실행만 기존 E 연동 클래스를 활성화한다.
$env:SECUREOPS_D_SOURCE = '<MAIN_CHECKOUT>'
python -B -X utf8 -m unittest discover -s tests -v
```

run-recheck.py는 기존 결과 파일이 있으면 중단한다. 원본 main 전체 검증이 끝난 뒤에만 재사용 테스트를 복사하므로
같은 Worktree에서 재현 시 새 작업 경로를 사용해야 한다. ZIP을 코드 소스로 사용하지 않는다.

PR20에 추가할 신규 증거 후보:

1. 이번 보고서·환경/명령·의존성·소스/테스트 해시.
2. ZIP 해시·안전 검사 명세와 C 측 결과 요약·87개 공식 Git blob 대조.
3. C 163개, 시나리오 5/28, 원본 main 171/173개, PR20 9개·독립 8개 새 로그.
4. 실제 C 결과·독립 저장 보고서와 네 모듈 한 보고서 왕복·집계·원본 보존 증거.
5. 서후님 비교 결과와 PR29 fixture 재발 없음 확인.

기존 ZIP·병합 전 증거를 교체하지 않고 이번 main 실행을 별도 절/디렉터리로 추가하는 방식이 적합하다.
아직 PR20·PR25·GitHub 본문을 수정하지 않았다.

남은 사항은 실제 SSH/VM·신규 중앙 실행 계층 인수, 운영 정책 보류, OS별 수집 권한 및 실환경 접근성이다.
MOCK not_applicable fixture를 운영 제외 승인으로, FW/LOG의 수집·보류를 운영 pass/vulnerable 판정 완료로 표현하지 않는다.
운영 코드·정책·공통 SSH·기존 테스트를 변경하지 않았고 Commit·Push·PR 변경·Merge·서버 설정 변경은 하지 않았다.
