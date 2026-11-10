# 최신 main 기준 CVSS Worktree 재검증

실행일: 2026-11-10 KST. 이 보고서는 기존 feature/cvss-core-jhm의 과거 실행 기록과 구분한다.
실행별 시각·명령·환경·결과는 [환경 기록](environment-and-results.json)에 있다.

## 보존과 기준선

- 원본 브랜치: feature/cvss-core-jhm, HEAD 994d20c1d7a914ba8a77ab9e89ea7080c16e171e.
- 검증 브랜치: feature/cvss-core-jhm-main-review.
- 검증 Worktree: C:/Users/Public/Documents/ESTsoft/CreatorTemp/SecureOps-cvss-main-review-854703a2d5fe.
- 기준 origin/main 및 검증 HEAD: d1f7534b3d0d3b9978d15bbea3ae9633eaf43d75.
- 백업: C:/Users/Public/Documents/ESTsoft/CreatorTemp/SecureOps-cvss-backup-854703a2d5fe.
- 백업 manifest.json 및 files/에 원본 core/tests/docs/의 파일과 의존성·README·.gitignore를 보관했다.
- 백업 대상 57개 파일의 개수·SHA-256을 모두 대조했다.
  CVSS 과거 증거 15개와 Git에서 제외된 로그 11개가 포함된다.
- 작업 종료 검증에서도 원본 57개와 백업 57개의 SHA-256이 일치했다.
  원본 Git 상태 및 기존 feature/core-jhm, feature/cvss-core-jhm, main, origin/main 참조가 그대로임을 확인했다.
- 검증 Worktree에 복사한 소스·테스트·의존성 11개도 백업과 SHA-256이 일치한다.
- 과거 CVSS 증거 15개는 전체가 백업과 일치하며 덮어쓰지 않았다.
- PR #18 정책·계약·Schema·MOCK 4개는 복사하지 않았다. main checkout의 파일을 유지했다.
  선별한 Core 4개를 제외한 모든 기존 main 추적 파일은 복사 전후 해시가 동일하다.

세부 증거: [이전 manifest](transfer-manifest.json), [최종 보존 검증](final-verification.json).
공통 SSH 모듈, B/C 담당 코드 및 기존 테스트 원본은 수정하지 않았다.
Commit, Push, PR 생성, Merge, Rebase는 수행하지 않았다.

## main 대비 기능 변경

| 구분 | 파일 |
|---|---|
| 기존 D Core 최소 수정 | core/main.py, core/runner.py, core/storage.py, core/remote_result.py |
| 신규 독립 모듈 | core/cvss.py, core/cvss_validation.py, core/cvss_assessment.py |
| 신규 테스트 | tests/test_cvss.py, tests/test_cvss_v12.py, tests/test_cvss_assessment.py |
| 테스트 의존성 | requirements-test.txt |
| 증거 추가 | docs/evidence/cvss-v1.2/의 과거 자료 사본 및 이 main-review-20261110 하위의 신규 검증 자료 |

기능 파일은 원래 구현을 그대로 복사했다. 새 구현이나 정책 변경을 하지 않았다.
최신 main 위에서 수정한 것은 위 기능 11개와 검증용 증거뿐이다.
git diff --check는 종료 코드 0이었다.
git diff --stat origin/main은 추적 파일 4개, 76줄 추가·23줄 삭제를 표시했다.
Git diff 통계에 미추적 신규 파일은 포함되지 않으므로 별도 파일 목록도 기록했다.
명령 원문: [Git 검사 로그](logs/10-git-review-checks.log).

## 재실행 결과

Windows 11 / AMD64 / CPython 3.14.2 / unittest / jsonschema 4.25.1에서 실행했다.

| 검증 | 통과 | 건너뜀 | 실패 | 오류 |
|---|---:|---:|---:|---:|
| CVSS 공식 계산·Vector·Roundup | 11 | 0 | 0 | 0 |
| JSON v1.2 Schema·런타임·통합 | 28 | 0 | 0 | 0 |
| 메트릭 근거·null 평가 생성 | 13 | 0 | 0 | 0 |
| 기존 v1.1 Core | 70 | 0 | 0 | 0 |
| 기존 v1.1 원격 JSON 파서 | 14 | 0 | 0 | 0 |
| 기본 환경 전체 | 136 | 3 | 0 | 0 |
| 고정 B/C 실제 판정 함수 오프라인 | 3 | 0 | 0 | 0 |
| 고정 B/C 소스 제공 전체 | 139 | 0 | 0 | 0 |

신규 52개와 기존 87개를 합쳐 139개이다. 중복 실행 행의 건수는 합산하지 않는다.
기본 환경의 건너뜀 3개는 main에 B/C 실제 소스가 없기 때문이다.
v1.2 MOCK CLI도 종료 코드 0이며, 이행률 25.0%, critical 1개를 출력했다.
점수·등급 일치, 상태 조합, 미평가 null, 저장·이력·details 및 입력 원본 보존을 포함한다.
v1.1 검증 함수의 AST 본문이 기존 main과 동일함을 확인했다.

JSON Schema의 구조 검사는 실제 실행했다. 이 환경에는 선택적 date-time format checker가 없으므로,
달력 날짜·시간대의 의미는 D 런타임 테스트에서 별도로 검증했다.
실행 중 기능·테스트·fixture 파일의 해시가 변경되지 않았음을 확인했다.

공식 대조 결과:

- FIRST Examples §3~§7의 기대 점수 6.4 / 3.1 / 9.9 / 4.2 / 7.2에 모두 일치했다.
- PR #18 MOCK Vector는 9.8 / critical이다.
- Scope U/C, PR 가중치, Roundup 경계, 오류 Vector, 0.0과 null의 구분도 통과했다.
- 2592개 Base 조합의 범위·정밀도 불변식을 검증했지만 모든 조합을 독립된 공식 기대값과 대조한 것은 아니다.
- 원래 테스트에 기록된 출처: https://www.first.org/cvss/v3-1/examples 및
  https://www.first.org/cvss/v3-1/specification-document.

테스트별 원문은 logs/01~09에 있으며 [환경 기록](environment-and-results.json)에 각 파일을 연결했다.

## 증거 수집기의 줄바꿈 비교

과거 수집기를 수정하지 않고 새 래퍼에서 출력 경로와 정책 기준 커밋만 지정해 재사용했다.
과거 수집기의 raw Git blob 비교는 LF blob과 CRLF checkout 때문에 정책 4개를 불일치로 표시하고
종료 코드 1을 반환했다. 개별 테스트 프로세스는 모두 종료 코드 0이었다.
초기 확인 기록은 [별도 보존](attempts/checkout-newline-check/environment-and-results.json)했다.

검증 래퍼는 이 사실을 숨기지 않고 historical_runner_exit_code와 raw 비교 결과를 그대로 기록한다.
별도로 main 내용의 줄바꿈 정규화 비교, 정책 checkout 파일의 복사 전후 정확한 해시,
기존 추적 파일 및 과거 증거의 보존을 검사한다. 이 검증은 모두 통과했고
main_review_verification_passed=true, 검증 래퍼 종료 코드 0이다.
정책 파일이나 과거 로그를 변경하여 비교를 통과시키지 않았다.

## B/C 호환성과 미완료 범위

이번 통과 결과의 실제 함수 소스는 이전 회귀 기준에 사용한 다음 고정 커밋이다.

- B: cfbd37b4dbd102ec894a2150d47f751ad5c74afa.
- C: 6bb330feccfc6541bc145db9b6e18f24b4bce394.

최신 B 브랜치와의 호환성을 이번 단계에서 재실행하지 않았다.
과거 최신 B 시도는 필수 criteria.vulnerable_values와 기대 판정 변경 때문에 기존 오프라인 테스트에 실패했다.
그 과거 실패 자료는 ../attempts/current-bc-20261110 아래에 그대로 보존했다.
현재 문제를 해결했거나 최신 B/C 전체가 통과했다고 주장하지 않는다.
기존 B/C 실제 함수 오프라인 검증은 v1.1이고, 신규 v1.2 파이프라인은 합성 입력이다.

최신 B 인터페이스에 맞는 테스트 입력 정합성, B/C 실제 v1.2 어댑터, E 연계는 미완료다.
실제 SSH/VM 수집·진단·조치·재검증, Linux 실환경 및 Python 3.12 실행도 미실행이다.

## 검토 준비와 재현

최신 main 기준의 CVSS 기능 및 고정 기준선 회귀 검토 자료는 준비됐다.
PR 설명에는 위 미완료 범위를 포함해야 한다. 기존 작업 브랜치를 교체하거나 main에 반영하지 않았다.
Commit/Push/PR 생성은 사용자 승인 전까지 실행하지 않는다.
로그는 .gitignore 대상이므로 향후 증거 파일을 Git에 포함할 때 별도로 확인해야 한다.

검증 Worktree 루트에서 실행:

```powershell
python -B -X utf8 docs/evidence/cvss-v1.2/main-review-20261110/run-main-review-evidence.py
git diff --check
git diff --stat origin/main
```

래퍼는 이 main-review 하위의 이번 실행 로그를 갱신하고, 과거 증거는 변경하지 않는다.
로그에서 저장소·임시·Python 설치 경로는 치환했으며 인증정보·실제 서버 출력은 저장하지 않았다.
