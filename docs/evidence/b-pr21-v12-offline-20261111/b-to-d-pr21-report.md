# B PR #21 → D JSON v1.2 오프라인 연동 검증

## 검증 범위

미병합 B PR #21의 고정 소스를 D main 코드와 연결한 오프라인 검증이다.
**공식 main에 B가 병합된 상태의 연동 검증을 완료했다는 의미가 아니다.**

- D 기준: `42783699356325aa08cfb7187bfaf06ed8519019` (PR #19 병합 포함).
- PR #19 HEAD: `8ae2ca1ba09f45c6b0f4a6c49a6a1572f0caca95`.
- PR #19 병합 후 최신 main에는 C PR #15가 추가됐으나 core/와 tests/ 내용 차이는 없다.
- B: [PR #21](https://github.com/YJH-secure/SecureOps/pull/21), `feature/json-v1.2-cjw`.
- B 고정 커밋: `9f58ee2efca3189866548219e05b732d254e279f` (조회 시 PR HEAD와 일치).
- 의존: [PR #10](https://github.com/YJH-secure/SecureOps/pull/10), `3eda5a56ed3e9fd56d162676507c526ea0d1a1c1`.
  해당 커밋이 B 고정 커밋의 조상임을 확인했다. 조회 시 두 PR 모두 미병합이다.
- 별도 Worktree 브랜치: `feature/b-d-v12-pr21-review-jhm`.
- 기존 C → D Draft PR #20 및 해당 Worktree는 변경하지 않았다.

실제 B 소스/정책/단위 테스트는 Git 고정 커밋에서 별도 디렉터리로 내보냈다.
B 파일을 D 저장소의 checks/account/에 복사하거나 수정하지 않았다.
세 파일의 SHA-256은 [최종 환경 기록](final/environment-and-results.json)에 있다.

## 실제 실행 경로

실제 `run_check(result_version="1.2")` → 실제 정책 loader/판정/직렬화 → JSON 문자열 →
`parse_result_json(schema_version="1.2", exit_code=0, execution_succeeded=True)` →
`run_target(mode="mock", schema_version="1.2")` → D 집계/ReportStore 저장/load/DiagnosisAggregator 재조회.

오직 운영 수집 경계인 `find_sshd`, `get_sshd_output`, `read_config_text`에 합성 입력을 제공했다.
`run_check`, `run_check_v1_1`, `check_ssh_01`, CVSS/details 생성 및 정책 판정은 대체하지 않았다.
외부 명령·네트워크 fallback은 차단했다. 실제 SSH/VM 및 서버 설정 조회는 수행하지 않았다.

## 상태 및 집계

같은 SSH-01의 여러 관측은 서로 다른 scan_id의 독립 보고서로 검증했다.
중복 check_id가 들어가는 통합 보고서를 임의 생성하지 않았다.

| 합성 관측 | B status | CVSS 상태 | version/vector/base_score/rating | D 집계 및 이행률 |
|---|---|---|---|---|
| global/root no | pass | not_applicable | 모두 null | pass 1, 100.0% |
| global/root yes | vulnerable | pending | 모두 null | vulnerable 1, 0.0% |
| global 수집 실패(None) | error | not_applicable | 모두 null | error 1, N/A |
| global/root no + Address Match에서 yes 가능 | needs_review | not_applicable | 모두 null | needs_review 1, N/A |
| sshd 미설치 입력 | not_applicable | not_applicable | 모두 null | 별도 저장·재조회 통과 |

네 가지 정책 취약 값 yes/prohibit-password/without-password/forced-commands-only는 모두
vulnerable/pending으로 수신했다. source도 null이며 정책 rationale은 보존된다.
scored 및 CVSS 점수는 생성하지 않았다. 모든 보고서의 scored 등급별 취약 건수는 0이다.
severity를 CVSS 등급으로 변환하지 않았다.

유효한 진단 error JSON은 성공적인 전송 입력으로 수신해 error_count에만 반영했다.
프로세스 실패 종료 코드 1/255 또는 execution_succeeded=False는 같은 JSON이라도 거부했다.
깨진/배열/중복 키/로그 혼합/다중 JSON, 부적절한 CVSS(null/빈 객체/배열, pending 숫자·bool 점수,
임의 등급, 불완전 scored, 부분 Vector, 빈 근거, pass+pending)도 거부했다.
거부 시 RunFailed의 원인은 RemoteResultError이며 보고서는 생성되지 않았다.

## details 및 비식별화

setting, expected, global_value, root_value, root_evaluation, match_rules를 저장 원본과 비교했다.
global=yes + Match User root no의 실제 root_output=no는 pass이며 global/root 값과 Match 근거가 보존된다.
수집 전 오류와 sshd 미설치 때 details가 없는 것은 B 인터페이스의 의도된 출력이다.
중첩 match_rules 변경으로 저장 보고서가 바뀌지 않는 복사 독립성도 확인했다.

테스트 host는 `.invalid` 합성 이름이고 주소는 RFC 5737 문서 예시 대역이다.
이 값과 Match 주소, 정책의 예시 host/addr가 실제 B 결과에 포함되지 않음을 단언했다.
결과에는 비밀번호·키·토큰 등 인증 필드가 없고, 증거의 실제 서버·접속 정보는 사용하지 않았다.
root는 공개 SSH-01 정책의 검사 대상 계정 이름이며 실제 인증정보가 아니다.

## v1.1 회귀와 저장

동일 합성 관측을 B의 인자 기본값(v1.1)과 v1.2로 실제 실행해 status/evidence/recommendation을 비교했다.
v1.1은 기존 필수 5필드와 severity를 유지하며 CVSS는 없다.
D parser/runner의 schema_version 기본값(v1.1)으로도 수신·저장·재조회했다.

최종 집중 실행의 실제 보고서 21개를 [saved-reports](final/saved-reports)에 저장했다.
각 원본과 load 결과가 일치하고 target 이력이 21개임을 확인했다.
[B 실제 결과·D 보고서·집계·저장 해시](final/actual-b-results-and-d-reports.json)에 사례별 연결이 있다.

## 실제 최종 실행 결과

2026-11-11 10:35:58–10:36:11 KST. Windows 11/AMD64, CPython 3.14.2, jsonschema 4.25.1.
현재 소스로 새 Python 프로세스를 실행했다. 과거 로그로 성공을 판단하지 않았다.

| 범위 | 발견 | 통과 | 건너뜀 | 실패 | 오류 | 로그 |
|---|---:|---:|---:|---:|---:|---|
| 신규 B PR21 → D | 10 | 10 | 0 | 0 | 0 | [01](final/logs/01-b-pr21-to-d.log) |
| B 원본 단위 테스트 | 47 | 47 | 0 | 0 | 0 | [02](final/logs/02-original-b-unit.log) |
| 기본 D 전체 | 159 | 136 | 23 | 0 | 0 | [03](final/logs/03-default-d-full.log) |
| 고정 소스 제공 D 전체 | 159 | 159 | 0 | 0 | 0 | [04](final/logs/04-d-full-with-fixed-sources.log) |

159개 = 기존 D 149개 + 신규 10개. 기존 CVSS 52개, v1.1 84개를 포함한다.
기본 skip 23개 = 과거 B/C 3개 + 기존 최신 B 10개 + PR21 신규 10개 소스 부재다.
소스 제공 회귀의 과거 B/C 및 PR10 최신 B는 PR21 소스와 다른 루트로 분리했다.
기존 FIRST 공식 5개 사례와 MOCK 9.8 Critical 테스트도 전체 실행에 포함됐다.
B 원본 47개는 별도 실행이며 D 전체 159개에 더해 표현하지 않는다.
C Draft PR #20의 신규 ZIP 테스트 9개 및 C 자체 단위 테스트는 이 실행 범위에 포함하지 않았다.

정확한 명령·커밋·환경·시각은 [최종 환경/결과](final/environment-and-results.json)에 기록했다.

```powershell
python -B -X utf8 docs/evidence/b-pr21-v12-offline-20261111/run-evidence.py --b-source-root <FIXED_B_SOURCE> --output-dir <NEW_EVIDENCE_DIRECTORY>
```

스크립트는 증거가 있으면 덮어쓰지 않는다. 고정 Git 객체를 사용할 수 있는 저장소가 필요하다.
직접 실행 시 `SECUREOPS_B_PR21_SOURCE_ROOT`를 지정한 후 아래 명령을 사용할 수 있다.

```powershell
python -B -X utf8 -m unittest discover -s tests -p test_b_pr21_v12_offline_integration.py -v
```

## 초기 테스트 작성 오류 기록

10:34:15–10:34:30의 최초 실행은 새 테스트에서 기존 D의 na_count를
not_applicable_count로 잘못 참조했다. 하나의 메서드 내 네 subtest가 KeyError를 냈다.
초기 [집중 로그](logs/01-b-pr21-to-d.log)와 [전체 로그](logs/04-d-full-with-fixed-sources.log)를 보존했다.
초기 환경 JSON의 passed=6/155는 오류 이벤트 수를 빼서 계산한 부정확한 파생값으로 사용하지 않는다.
원시 출력의 errors=4는 네 subtest 오류 이벤트이며 네 개의 독립 테스트 메서드 오류를 뜻하지 않는다.
새 테스트의 집계 키 참조만 수정했고, 수집·판정·D 운영 코드는 수정하지 않았다.
증거 스크립트도 실패 실행에서는 통과 메서드 수를 추정하지 않도록 수정했다.
위 최종 결과는 별도 final/ 경로에서 새 프로세스로 재실행한 실제 결과다.

## 결론과 남은 사항

고정 B PR21 소스와 D의 v1.1/v1.2 경로는 이번 합성 사례에서 운영 코드 수정 없이 호환됐다.
소스·정책·CVSS 계산기·기존 테스트·과거 증거의 변경은 없으며 B 파일 해시도 유지됐다.
버전 선택은 양쪽에서 명시적으로 맞춰야 하고 진단 error와 전송 실패를 구분해야 한다.

- PR10/PR21 병합 후 최종 main 커밋 기준 재검증이 필요하다.
- PR21의 선택적 cvss_assessment 정책 필드는 B PR의 검토 대상이다. D가 운영 승인을 추가 확정하지 않았다.
- 실제 CVSS scored 근거와 OS/applies_to 선택은 향후 담당 실행 계층의 확인 사항이다.
- 실제 SSH/VM, Ubuntu/Rocky 실환경은 미실행이다.
- Commit·Push·PR 생성·Merge 및 PR #20 수정은 수행하지 않았다.
