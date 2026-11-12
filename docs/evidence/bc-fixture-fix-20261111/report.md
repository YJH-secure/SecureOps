# B/C 오프라인 fixture 오류 수정 검증

- 기준 main: `66495d0506391a7a259accf558c822d28be3b219`.
- 수정 브랜치: `fix/bc-offline-fixture-jhm`.
- 실제 실행일: 2026-11-11 KST.
- Windows 11 / CPython 3.14.2 / jsonschema 4.25.1.
- 운영 코드 변경 없이 `tests/test_bc_offline_integration.py`만 11행 추가·3행 삭제했다.

## 원인과 최소 변경

구형 합성 B 정책은 criteria.vulnerable_values와 criteria.test_connection을 제공하지 않았다.
현재 B 판정 함수가 vulnerable_values를 읽으면서 KeyError를 발생시키고 D runner가 RunFailed로 전달했다.
같은 원인으로 세 메서드에서 오류 이벤트 6개가 발생했다.

1. test_actual_bc_functions_to_validated_report_summary_and_storage: 1개.
2. test_file_details_and_inputs_preserved_without_shared_mutation: 1개.
3. test_pass_error_and_needs_review_are_counted_independently: subtest 4개.

이는 진단 status=error 여섯 건이 아니다. [수정 전 traceback](logs/before-target.log),
[중첩 원인](before-root-cause.json), [수정 전 결과](before-results.json)를 남겼다.

합성 정책에 main B 정책과 동일한 네 취약 값 yes/prohibit-password/without-password/forced-commands-only 및
문서용 접속 조건 user=root, host=mock-offline.invalid, addr=192.0.2.10을 추가했다.
prohibit-password 사례의 기대 상태를 needs_review에서 vulnerable로, 집계를 passed=1/vulnerable=1로 변경했다.
기존 집계 단언이 이행률 50.0%와 high 취약 1건도 검증한다.
실제 B validate_policy와 main 정책 비교도 통과했다([정책 확인](policy-check.json)).

기존 3개 테스트와 네 상태 조합, FILE details·입력 원본 보존, JSON 수신·집계·저장·재조회,
외부 명령/네트워크·수집 차단 범위는 유지했다. 테스트 삭제·Skip 추가·단언 완화는 하지 않았다.

## 실제 새 프로세스 실행 결과

| 실행 | 원시 Ran | OK 메서드 | 실패 | 오류 이벤트 | Skip | 로그 |
|---|---:|---:|---:|---:|---:|---|
| 수정 전 통합 | 3 | 0 | 0 | 6 | 0 | [before](logs/before-target.log) |
| 수정 후 통합 | 3 | 3 | 0 | 0 | 0 | [target](logs/after-target.log) |
| 수정 후 기본 전체 | 171 | 171 | 0 | 0 | 1* | [default](logs/after-default-full.log) |
| 수정 후 D 소스 명시 전체 | 173 | 173 | 0 | 0 | 0 | [full](logs/after-full-with-d-source.log) |

수정 전: 19:17:31 KST. 수정 후: 19:18:38–19:18:48 KST.
*기본 출력은 `Ran 171 tests`, `OK (skipped=1)`이다. 171개 메서드 OK와 별도로 E의 setUpClass Skip이 1개 기록된다.
클래스 Skip은 testsRun에 포함되지 않으므로 171에서 1을 빼서 통과 메서드 수를 만들지 않았다.
건너뜀 사유는 `SECUREOPS_D_SOURCE`에 고정 D 경로 미지정이다. 기존 동작이며 새 Skip을 추가하지 않았다.

추가 실행은 SECUREOPS_D_SOURCE에 현재 기준 D Worktree를 지정해 E 연동 2개까지 포함했다.
B/C는 모두 현재 main Worktree 소스다. 과거 B/C 커밋으로 교체해 통과시킨 결과가 아니다.
기존 CVSS 52개와 v1.1 84개도 전체 회귀에 포함된다.

정확한 명령:

```powershell
python -B -X utf8 -m unittest discover -s tests -p test_bc_offline_integration.py -v
python -B -X utf8 -m unittest discover -s tests -v
# 아래 실행만 E 연동 클래스까지 포함한다.
$env:SECUREOPS_D_SOURCE = '<CURRENT_D_WORKTREE>'
python -B -X utf8 -m unittest discover -s tests -v
```

기본 실행에서는 외부 SECUREOPS 소스 환경변수를 제거했다. 명령·환경·시간·fixture SHA는
[수정 후 결과](after-results.json)에 기록했다. [run-evidence.py](run-evidence.py)의 before/after 모드는
기존 증거가 있으면 덮어쓰지 않는다. before는 기준 파일, after는 수정 파일에서 실행해야 한다.

## 보존과 비식별화

B/C 운영 소스·정책, D Core, CVSS, 공통 SSH 및 다른 기존 테스트는 변경하지 않았다.
기존 PR20/25와 11/12 준비 보고서·공식 C 검증 자료를 변경하지 않았다.
실제 SSH/VM·서버 설정 조회/변경은 수행하지 않았다.

새 로그에는 개인 경로를 표시자로 바꾸고 UTF-8/LF 및 후행 공백 제거만 적용했다.
traceback의 예외·파일명·행 번호·호출 내용과 테스트 수치는 보존했다.
공백 정리 전 비식별 stdout의 SHA-256도 각 실행 기록에 있다.
기존 원시 증거 파일을 정리하거나 덮어쓴 작업이 아니다.
문서용 주소와 합성 호스트 외에 실제 서버·인증정보를 포함하지 않는다.

현재 main B 계약을 검증하는 fixture로 수정했으므로 과거 prohibit-password를 needs_review로 보던
옛 B 커밋에 이 수정 테스트를 적용한 결과와 과거 증거를 혼동하지 않는다.
