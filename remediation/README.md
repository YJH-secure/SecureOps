# E 파트 · SSH-01 모의 조치 및 재검증

대상 환경: Ubuntu 24.04 LTS  
구현 범위: SSH-01 MOCK 조치, 승인, 백업, 재진단, 복구

공통 진단 JSON v1.1 및 v1.2를 바탕으로 SSH root 원격 로그인 제한의 조치 흐름을 검증한다. 실제 서버를 변경하지 않고 메모리 기반 MOCK 백엔드를 사용한다.

## 실행 환경 및 명령

- 최근 확인 환경: Windows PowerShell, Python 3.11.9
- 테스트는 프로젝트 루트에서 실행
- 현재 E 단위 테스트는 Python 표준 라이브러리 `unittest` 사용

~~~powershell
python -B -m remediation
python -B -m remediation --mock
python -B -m remediation --mock --deny
python -B -m remediation --mock --skip
python -B -m remediation --mock --fail-at backup
python -B -m remediation --mock --fail-at apply
python -B -m remediation --mock --fail-at verify_service
python -B -m remediation --mock --fail-at validate
python -B -m remediation --mock --fail-at recheck
python -B -m unittest discover -s tests -v
~~~

기본 실행은 dry-run으로 계획만 출력하며 설정을 변경하지 않는다. `--mock`은 내장 샘플과 가상 승인을 사용한다. 외부 진단 결과의 계획 확인은 `python -m remediation --report <JSON파일>`을 이용한다.

## 실행 흐름

1. 공통 JSON v1.1 검증 및 `build_plan()`을 통한 SSH-01 조치 계획 생성
2. 대상 및 점검 항목 허용 목록 확인
3. 실행 계획에 대한 승인 검증
4. MOCK 설정 백업, 적용 및 변경 내용 검증
5. MOCK 서비스 상태 확인 및 새로운 `scan_id`로 재진단
6. 비교 결과 및 조치 이력 반환
7. 실패 유형에 따라 MOCK 복구 및 복구 검증

기존 `build_plan(report, check_id)` 및 `Remediator.run(report, plan, ...)` 인터페이스를 유지한다.

## 상태 필드

| 필드 | 의미 |
| --- | --- |
| `outcome=planned` | dry-run 계획 |
| `outcome=success` | MOCK 조치 및 재검증 성공 |
| `outcome=rejected` | 승인 거부 등으로 조치 중단 |
| `outcome=skipped` | 조치 대상 또는 허용 정책에서 제외 |
| `outcome=failed` | 실행, 검증 또는 재진단 실패 |
| `stopped_stage` | rejected/skipped의 중단 단계 |
| `failed_stage` | failed의 실패 단계 |
| `execution_id` | 실행별 고유 식별자 |
| `plan_id` | 변경 계획 식별자 |

`failure_reason`에는 중단 또는 실패 이유가 기록될 수 있다. 진행된 단계는 `completed_steps`에 남긴다.

## 재진단 실패 시 MOCK 복구

재진단 실행 오류 또는 재진단 결과가 개선되지 않은 경우 MOCK 백업 설정의 복구를 시도하고, 복구 상태와 서비스 상태를 검증한다.

- `backup` 및 `backup_id`: 백업 상태와 식별자
- `rollback=not_needed`: 복구가 필요하지 않았음
- `rollback=verified`: MOCK 설정 복원과 복구 검증 절차 성공
- `rollback=failed`: 복구 또는 복구 검증 실패
- `rollback_failed_stage`, `rollback_failure_reason`: 복구 실패의 단계와 원인

`rollback=verified`는 MOCK 백엔드의 검증 결과이지 실제 서버의 최종 상태에 대한 실측이 아니다. 실제 SSH 서버에 자동 복구를 적용하는 정책은 승인되지 않았으며, 이 구현은 실제 설정 변경이나 서비스 재시작을 수행하지 않는다.

## after_report, comparison 및 최종 상태

`after_report`는 **조치 적용 후 재진단 시점**의 보고서이며 입력과 같은 JSON 버전을 사용한다. 재진단 이전에 중단되거나 재진단 실행·검증이 실패하면 `null`일 수 있다.

재진단 결과가 개선되지 않아 그 뒤 MOCK 복구를 진행했다면, `after_report`는 **복구 전의 재진단 결과**일 수 있다. 따라서 `after_report`나 `comparison`을 복구 후 서버의 최종 상태로 해석하지 않는다. 복구 결과는 별도 `rollback`으로 표현하며, 복구 후 별도의 최종 보안 재진단이 수행되었다는 뜻도 아니다.

`comparison`은 조치 전후 진단 결과의 비교이며, 동일한 `target_id`와 `check_id`를 기준으로 서로 다른 `scan_id`를 비교한다.

## D 모듈 연동

E 조치 실행 이력에는 다음 항목을 포함한다.

- `execution_id`, `plan_id`
- `target_id`, `check_id`, `before_scan_id`
- `outcome`, `stopped_stage`, `failed_stage`
- `backup`, `backup_id`, `rollback`
- `after_report`, `comparison`

공통 진단 JSON v1.1과 E 조치 실행 이력은 **별도 데이터**로 저장한다. 거부·제외·실패 결과도 조치 이력으로 보존할 수 있도록 D 담당과 필드, null 처리 및 저장 방식을 맞춰야 한다.

## 테스트 현황과 재현 조건

기존 E 단위 테스트 22개와 D↔E 통합 테스트 2개를 보존한다. 고정 D 커밋과 최신 main D 코드 기준으로 각각 24개를 검증한다. 신규 v1.2 테스트는 입력 검증, 승인·실패 복구, CLI 및 D 저장·재조회·전후 비교를 확인한다.

테스트는 메모리 MOCK과 임시 저장소를 사용한다. 아래 실행 명령으로 같은 검증을 재현할 수 있으며, 고정 커밋 실행에는 해당 Git 객체가 필요하다.

## 검증 한계

- MOCK 설정 변경, 백업 및 복구만 검증
- 실제 SSH 접속, 설정 변경, reload, 접속 영향 미검증
- 실제 서버 자동 복구 정책 미승인
- D의 진단 보고서 저장 연동은 MOCK으로 검증, E 조치 실행 이력 저장은 후속 협의 필요
- FILE-01의 실제 조치는 현재 E 모듈 범위에 포함하지 않음

## JSON v1.2 개발

기존 v1.1 실행 방식과 테스트를 보존하며, v1.2 검증은 core.cvss_validation.validate_report에 위임한다. v1.2 재진단 보고서는 DiagnosisAggregator.from_results(..., schema_version="1.2")로 생성한다. E는 CVSS 점수를 계산하지 않으며 평가 결과를 근거와 함께 보존한다. assess_cvss는 D의 별도 평가 경로이며 E 재진단마다 자동 호출하지 않는다.

    python -B -m remediation --mock --result-version 1.2
    python -B -m remediation --report tests/fixtures/sample-result-v1.2-MOCK.json
    python -B -m unittest discover -s tests -p test_remediation_v12.py -v

v1.2 내장 시연은 main의 공식 MOCK fixture를 사용한다. SSH-01의 점수는 pending/null이며, pass 재진단에는 CVSS not_applicable/null을 기록한다. 계산기 검증용 CVSS-MOCK-01은 허용된 조치 항목에 포함되지 않는다. 외부 JSON의 v1.2 텍스트는 중복 키를 거부하는 D 파서로 확인한다.

### 기존 24개 회귀와 최신 D 확인

    python -B tests/run_de_mock.py
    python -B tests/run_de_mock.py --d-ref origin/main

기본 실행은 기존 D 고정 커밋 994d20c를 사용한다. --d-ref는 로컬에서 확인할 D 버전을 선택한다. 두 명령 모두 기존 E 단위 테스트 22개와 v1.1 통합 테스트 2개를 실행한다. 각 테스트 묶음은 별도 프로세스에서 실행해 D 버전의 import 혼합을 방지한다. v1.2 신규 테스트는 새 브랜치에 반영한 main의 실제 D 코드를 사용하며 별도로 실행한다.

### 조치 기준과 후속 협의

조치 후보는 기존 진단 status와 승인된 항목·허용 목록으로 판단한다. CVSS pending/not_applicable의 null은 0점으로 바꾸지 않는다. CVSS scored의 높은 점수는 조치 승인을 대신하지 않는다. CVSS를 이용한 운영 우선순위는 팀 정책 확정 후 구현한다.

D의 ReportStore에는 after_report만 저장한다. E 실행 이력 저장 규격, B/C 실제 재진단 연결과 실제 SSH 조치는 별도 후속 작업이다.


## 공통 실행 계층 MOCK 콜백

기존 run(report, plan, ...)에 선택 인자 recheck_report=callback을 추가했다. 생략하면 기존 v1.1/v1.2 동작을 유지한다. 콜백은 v1.2 MOCK 실행에서만 사용하며, 승인·허용 목록·백업·조치·설정 검증을 통과한 뒤 호출한다.

callback(request, mock_state)의 입력:
- request: target_id, os, check_id, before_scan_id, schema_version
- mock_state: files, root_login의 복사본. 실제 백엔드·승인·명령 실행 권한은 전달하지 않음

콜백 반환값은 개별 결과가 아니라 D에서 검증·집계·저장·재조회한 전체 JSON v1.2 보고서다. E는 보고서 버전·대상·검사 항목·새 scan_id·진단 시각을 다시 확인하고, 조치 항목이 vulnerable에서 pass로 바뀐 경우만 성공 처리한다. 다른 항목의 오류는 해당 항목의 결과로 보존한다. 재진단·검증·저장 실패 또는 조치 항목의 미개선 시 기존 MOCK 복구를 수행한다.

테스트 전용 MockExecutionLayer는 최초 진단과 재진단에 같은 execute() 경로를 사용한다. B/C 합성 결과 → D DiagnosisAggregator → ReportStore.save/load를 거쳐 E에 반환한다. 저장소는 TemporaryDirectory만 사용한다. E는 B/C 호출·SSH 연결·저장을 중복 구현하지 않는다.

    python -B -m unittest discover -s tests -p test_remediation_execution_integration.py -v

이 콜백은 신뢰된 로컬 테스트 코드의 주입 지점이며 Python 코드를 격리하는 보안 샌드박스는 아니다. 임의 코드나 실제 원격 실행기를 연결하지 않는다. 실제 공통 실행 계층의 요청 형식·B/C 실행 방식·저장소 책임과 실패 정책은 팀 인터페이스 확정 후 별도로 연결한다. 기존 MockBackend 정확한 타입 검사와 실제 조치 금지는 유지한다.


## E 실행 이력과 D scan_id 연결 (추가 확정 사항)

E에서 생성한 execution_id에 before_scan_id, after_scan_id, post_rollback_scan_id를 연결한다. 16b545c 시점에는 이력이 반환 객체에만 존재하여 별도 저장·조회 요구가 미충족이었다. 아래의 ExecutionHistoryStore 보완으로 E 전용 파일에 저장하고 독립 조회할 수 있다. D JSON v1.2와 ReportStore API는 변경하지 않으며 E 이력을 D 진단 보고서로 저장하지 않는다.

새 연결은 remediation.recheck.MockRecheckAdapter(diagnose, store)를 run(..., recheck_adapter=adapter)에 전달한다. 기존 recheck_report 콜백과 동시에 사용하지 않는다. diagnose(request, mock_state)는 신뢰된 MOCK 코드이며 **아직 저장하지 않은 전체 D v1.2 보고서**를 반환한다. D 집계 함수로 보고서를 만들 수 있으나 store.save/load는 어댑터가 담당한다. 기존의 저장까지 수행하는 콜백을 그대로 중첩하면 안 된다. 저장 단계 전에 ID를 관찰할 수 없는 기존 불투명 콜백 대신 이 어댑터를 사용해야 한다.

ReportStore.save(report)는 경로를 반환하므로 ID로 사용하지 않는다. 어댑터는 검증된 report["scan_id"]를 저장 시도 전에 확보하고, 단계별 recheck_attempts에 다음을 기록한다.

- execution_id, phase(after/post_rollback), target_id, check_id, scan_id, scanned_at
- save_status와 load_status: not_attempted / attempted / success / failed
- report_verified: 재조회 결과까지 원본과 일치하는지 확인
- failure_stage, failure_reason: 실패 단계와 예외 종류. 개인 경로가 섞일 수 있는 예외 원문은 제외

save 성공 후 load 실패여도 after_scan_id는 유지한다. store.load(result["target_id"], result["after_scan_id"])로 같은 보고서를 재조회할 수 있다. 다시 조회한 복구 전 pass를 복구 후 최종 pass로 바꾸지는 않는다. save가 예외를 낸 경우에는 일부 I/O가 끝났을 수도 있으므로 save_status=failed를 보고서가 절대 존재하지 않는다는 의미로 해석하지 않는다.

복구 후 보안 재진단은 기본적으로 실행하지 않는다. post_rollback_recheck=True와 MOCK 어댑터를 함께 전달하면 rollback=verified 이후 새 scan_id로 진단하고 post_rollback_scan_id에 연결한다. 복구가 실패하면 후속 재진단을 실행하지 않는다. 이전 scan_id 재사용 및 앞선 진단보다 오래된 시각은 거부한다.

- 복구 후 보안 재진단 없음: final_security_status=null, final_security_verified=false
- 복구 후 저장·조회·검증 실패: 새 ID를 확보한 단계까지 보존하며 최종 보안 상태는 null/false
- 복구 후 pass 또는 vulnerable 진단: 해당 status와 final_security_verified=true. true는 상태 확인을 뜻하며 vulnerable이 조치 성공이라는 뜻은 아님
- 복구 후 error/needs_review/not_applicable 진단: 해당 status와 final_security_verified=false

원래 조치가 실패했다면 복구 후 pass를 확인해도 outcome=failed를 유지한다. after_report는 조치 후 진단 당시 결과이고 post_rollback_report는 별도의 복구 후 결과다. rollback 필드명을 유지하며 rollback_status를 추가하지 않는다. 기존 승인·허용 목록·정확한 MockBackend 타입 검사·MOCK 복구 절차는 유지한다.

이 요청·반환 어댑터는 E 전용 MOCK 연결이며 공통 SSH 실행 계층의 최종 계약이 아니다. 실제 통합 시 어댑터만 조정할 수 있도록 격리했다. 실제 SSH·서버 설정 변경 및 점수 임의 계산은 수행하지 않는다.

    python -B -m unittest discover -s tests -p test_remediation_execution_history.py -v


### 16b545c 시점의 추가 규격 검증 결과 (과거 137개, 2026-11-11)

기존 회귀 117개(24+18+19+52+4)와 신규 실행 이력 MOCK 테스트 20개를 구분해 실제 실행했으며 모두 통과했다. 실패·오류·건너뜀은 각각 0개다. 과거 PR #23의 117개 증거를 새 실행 로그로 재사용한 결과가 아니다. 기존 테스트 파일은 수정하지 않았다. 현재 origin/main 기준은 e4af8a6이며 Python 3.12.14, jsonschema[format] 4.26.0 환경을 사용했다.

    python -B tests/run_de_mock.py --d-ref e4af8a6659a695a5d7e0152b8c0d831e7736fef1
    python -B -m unittest discover -s tests -p test_remediation_v12.py -v
    python -B -m unittest discover -s tests -p test_remediation_execution_integration.py -v
    python -B -m unittest discover -s tests -p 'test_cvss*.py' -v
    python -B -m unittest discover -s tests -p test_remediation_b_v12_integration.py -v
    python -B -m unittest discover -s tests -p test_remediation_execution_history.py -v

이 결과는 오프라인 MOCK 검증이다. 실제 SSH 실행 및 D 저장 API 변경은 없다. 이번 작업은 로컬까지만 반영하며 Push·PR 업데이트는 하지 않는다.


## E 전용 ExecutionHistoryStore 저장·조회 보완

반환 객체만으로는 프로세스 종료 후 조회할 수 없으므로 E 전용 파일 저장소를 추가했다. 저장소는 remediation/history.py에 있으며 from remediation import ExecutionHistoryStore로 사용한다. 기존 Remediator.run()의 입력·반환 결과·조치 흐름은 변경하지 않는다. 실행 후 호출 측에서 명시적으로 save(result)를 수행한다.

```python
from tempfile import TemporaryDirectory
from remediation import ExecutionHistoryStore

# result는 기존 Remediator.run(...)에서 반환받은 E 실행 결과
with TemporaryDirectory(prefix="secureops-e-history-") as directory:
    writer = ExecutionHistoryStore(directory)
    writer.save(result)
    execution_id = result["execution_id"]
    # 새 인스턴스는 메모리 캐시가 아니라 디스크에서 독립 조회
    reader = ExecutionHistoryStore(directory)
    restored = reader.load(execution_id)
```

- save(result): E 실행 결과를 별도 JSON 파일에 추가하고 저장 경로 반환. 조회 키는 반환 경로가 아니라 result["execution_id"].
- load(execution_id): 같은 디렉터리의 과거 실행 결과를 새 인스턴스·새 프로세스에서도 조회.
- 동일 execution_id는 내용이 같아도 FileExistsError로 거부. 임시 파일 완성 후 배타적 하드링크 게시로 부분 파일 노출과 동시 덮어쓰기 방지.
- E의 성공·실패·거부·제외·Dry-run, rollback 및 진단 ID 연결을 그대로 보존. 원본 반환 객체는 수정하지 않음.
- Dry-run의 plan.actions tuple은 기존 CLI JSON과 같은 배열로 저장·조회. 새로 태그나 변환 규격을 D에 추가하지 않음.
- 손상된 JSON, 중복 JSON 키, 파일 내용의 execution_id 불일치, D 진단 보고서의 직접 저장을 거부.
- 저장·조회 오류는 예외로 호출 측에 전달. 저장 실패가 이미 완료된 보안 조치의 성공/실패를 바꾸지는 않으며, 조치 재실행이나 자동 롤백을 수행하지 않음.

E 이력 디렉터리는 D ReportStore 디렉터리와 별도로 지정한다. 기존 E 반환값의 after_report/post_rollback_report 스냅샷이 E 파일에 포함될 수 있지만, D 보고서에 E 필드를 주입하거나 D 저장 API를 변경하지 않는다. 저장 오류가 발생하면 execution_id와 원래 결과를 보존하고 같은 ID를 우선 조회한 뒤 저장 재시도 여부를 판단한다. 게시 이후 정리 중 오류가 발생하면 최종 파일이 존재할 수도 있으므로 예외만으로 데이터가 없다고 단정하지 않는다.

MOCK 테스트는 TemporaryDirectory만 사용한다. 디렉터리가 유지되는 동안 프로세스를 바꿔도 기록은 남지만, TemporaryDirectory 정리 후까지 보관되는 것은 아니다. 실제 유지 경로 사용 시 전용 접근 권한과 보관 정책을 별도로 정해야 한다. 로컬 하드링크를 지원하는 파일시스템이 필요하며, 암호화·서명 기반 변조 방지나 운영 감사 시스템을 구현한 것은 아니다.

### 49c3e0f 저장소 보완 당시 검증 (과거 기록, 2026-11-11)

- 기존 117개 회귀: 24+18+19+52+4 통과
- 16b545c 실행 이력 테스트: 기존 20개 통과
- 이번 신규 저장소 테스트: 18개 통과
- 합계 155개 통과, 실패·오류·건너뜀 각각 0개

신규 테스트는 tests/test_execution_history_store.py에 추가했다. 새 인스턴스·새 Python 프로세스 조회, 중복·동시 저장, 실패·롤백 이력 보존, 저장·조회 I/O 오류, D 조회 실패의 scan_id 연결 보존을 확인한다. 초기 검증에서 Dry-run tuple을 과도하게 거부하던 문제를 CLI와 같은 JSON 배열 저장으로 수정한 뒤 신규 18개가 모두 통과했다. 위 건수는 수정 후 결과이며 초기 실패를 통과로 집계하지 않았다.

    python -B -m unittest discover -s tests -p test_execution_history_store.py -v

기존 회귀 명령은 위 16b545c 검증 절에 그대로 기재되어 있다. 이번에도 같은 여섯 묶음을 실제 재실행했으며 D/B/C 코드와 기존 137개 테스트 파일은 수정하지 않았다. Python 3.12.14와 jsonschema[format] 4.26.0 환경을 사용했고 실제 SSH 조치는 없다.

원격 PR #23은 201e557 상태다. 16b545c의 ID·최종 보안 상태 구현과 이번 저장소 보완은 로컬 작업으로 구분하며, 이번 요청에서 Push·PR 업데이트·main 병합은 하지 않는다.


## 최신 main 6bf80bb 기준 최종 재검증

PR #22가 반영된 main 6bf80bb114458994bec7d640b4fe4ec53b97bb10을 현재 E 브랜치에 일반 merge했다. 실제 테스트 HEAD는 bb050165b21dade0285372745c92cd5dd996123d이며 충돌은 없었다. E 실행 코드·테스트는 49c3e0f와 동일하고 D/B/C 코드는 해당 main과 동일하다.

이번에 실제 재실행한 결과는 기존 117개 + 실행 이력 20개 + 저장소 18개 = E 155개 통과다. PR #22 C 테스트는 FW 17개·LOG 12개, 별도 29개 통과다. 전체 선택 실행 184개의 실패·오류·건너뜀은 모두 0개다. 과거 검증 결과를 이번 결과로 대체하지 않고 별도 폴더에 기록했다.

[최신 검증 보고서·실행 명령·전체 로그](../reports/e-history-final-main-6bf80bb-20261111/README.md)를 참조한다. ExecutionHistoryStore의 저장·중복 거부·새 인스턴스/새 Python 프로세스 조회, D load 실패의 ID 보존, 복구 후 미확인 상태 및 post_rollback_scan_id 연결을 기존 테스트에서 재확인했다. 이번에 실행 코드나 새로운 테스트를 추가하지 않았다.

원격 PR #23의 HEAD는 201e557 그대로다. 새 main 반영과 이번 검증 자료는 로컬 커밋까지만 진행하며 Push·PR 업데이트·main으로의 E 병합은 수행하지 않는다.


## 9ab4a64 시점 승인 ID·시각 필드 보완 (당시 버전 보류)

0eb97bd까지는 최상위 approval_id와 started_at/finished_at이 누락되어 있었다. 이번 보완은 아래 세 필드만 추가하며 기존 Remediator.run()의 공개 호출 방식과 D 진단 JSON을 변경하지 않는다.

- approval_id: 승인 검증을 통과해 실제 사용한 기존 approval 객체의 ID와 동일. Dry-run·제외·거부·승인 누락·승인 확인 실패는 null. 승인 이후 백업·조치가 실패한 경우 사용한 승인 ID는 유지.
- started_at: E run() 진입 시 기록한 UTC ISO8601 시각.
- finished_at: 재진단·필요한 복구 및 후속 처리까지 마친 정상 반환 직전의 UTC ISO8601 시각.

두 시각은 시간대(+00:00)를 포함한다. 승인 만료 검사용 now 인자를 감사 시각으로 복사하지 않는다. malformed 입력 등 예외로 종료되는 호출은 기존 검증 예외 경로를 유지하며 정상 반환 기록을 새로 만들어내지 않는다.

ExecutionHistoryStore는 새 필드가 있는 기록에서 최상위 approval_id와 기존 approval의 일치, 시각의 시간대 및 시작·종료 순서를 검증한다. 과거 필드가 없던 기록은 저장·조회 호환성을 유지하며 승인 ID나 시각을 추정해서 채우지 않는다. 새 메타데이터의 저장·조회 후 값도 보존한다.

9ab4a64 시점에는 E schema_version의 의미·값이 미확정이라 보류했고 저장소 거부 정책을 유지했다. 이는 과거 작업 상태다. 이후 팀장 최종 승인으로 E 이력 1.0과 별도 diagnosis_schema_version 규칙을 확정했으며, 현재 동작은 아래 절을 따른다. D 보고서는 현재도 E 이력 저장소에 직접 저장할 수 없다.

### 이번 실제 검증

- 기존 E 및 C 회귀: 184개 통과 (기존 E 155 + C 29)
- 신규 tests/test_execution_history_fields.py: 10개 통과
- 합계 194개 통과, 실패·오류·건너뜀 각각 0개

정상 조치·Dry-run·거부·제외·승인 확인 오류·백업/조치/재진단/복구 실패 등 정상 반환 경로의 필드를 확인했다. v1.1/v1.2 D 보고서 필드가 바뀌지 않는 점, 저장 후 메타데이터 보존, 과거 미기재 기록 조회, 시간대·시각 순서·승인 ID 불일치 검증도 포함한다.

    python -B -m unittest discover -s tests -p test_execution_history_fields.py -v

기존 184개는 main 66495d0506391a7a259accf558c822d28be3b219의 D 소스를 지정해 기존 아홉 묶음을 실제 재실행했다. Python 3.12.14와 jsonschema[format] 4.26.0 환경이며 과거 184개 로그를 새 결과로 재사용하지 않았다. 이번 원본 회귀 로그는 저장소 밖에 별도로 보관했다. 이전 검증 보고서는 해당 시점 기록으로 보존한다.

이번 변경은 로컬 커밋까지만 반영하며 Push·PR 업데이트·main 병합은 수행하지 않는다. D/B/C 코드·ReportStore·기존 테스트·.bak는 수정하지 않는다.


## 확정된 E 이력 버전 1.0과 진단 버전 분리

신규 E 실행 이력은 schema_version="1.0"으로 기록한다. 이는 **E 실행 이력 자체의 계약 버전**이며 D 진단 JSON의 버전이 아니다. diagnosis_schema_version은 조치 전 실제 D 보고서의 schema_version에서 복사하며 "1.1"과 "1.2"를 모두 지원한다. 진단 버전을 "1.2"로 고정하거나 E 버전을 진단 버전에서 추측하지 않는다. 기존 승인·백업·조치·재진단·복구 흐름과 공개 함수 호출 방식은 바꾸지 않았다.

- v1.1 D 입력 → E schema_version="1.0", diagnosis_schema_version="1.1"
- v1.2 D 입력 → E schema_version="1.0", diagnosis_schema_version="1.2"
- Dry-run·거부·제외·실패 등 정상 반환 결과도 동일한 버전 규칙 적용
- after_report/post_rollback_report의 D JSON 버전과 내용은 기존 계약 유지

ExecutionHistoryStore는 두 필드를 문자열로 검증한다. E 버전은 "1.0"만, 진단 버전은 "1.1"/"1.2"만 허용한다. 한 필드만 있는 불완전한 쌍, 잘못된 값·자료형, 진단 스냅샷과의 버전 불일치를 거부한다. D 보고서 최상위의 results 및 E 필수 식별 필드를 기준으로 D 진단 JSON 자체의 직접 저장은 계속 거부한다.

두 버전 필드가 모두 없는 과거 E 기록은 기존 형식으로 저장·조회할 수 있으며, 조회 시 버전 값을 추가하거나 파일을 다시 쓰지 않는다. 과거 기록의 진단 버전을 스냅샷 등으로 추정해서 채우지 않는다. 실행 이력 저장소에 버전이 없는 기록과 새 버전 기록이 함께 존재할 수 있다.

### 이번 버전 확정 보완 검증 (2026-11-11)

- 기존 194개 회귀: 모두 통과
- 신규 tests/test_execution_history_versions.py: 10개 통과
- 합계 204개 통과, 실패·오류·건너뜀 각각 0개

기존 필드 테스트 10개 중 버전 보류를 전제로 했던 두 단언을 승인된 규칙으로 갱신했다. 기존 테스트를 삭제하거나 건수를 줄이지 않았다. 신규 테스트는 v1.1/v1.2 입력과 정상 반환 경로, 저장·조회, 과거 무버전 기록의 파일 불변성, 손상 데이터·부분 버전 쌍·D 보고서 거부를 확인한다.

    python -B -m unittest discover -s tests -p test_execution_history_versions.py -v

기존 194개는 D 소스 66495d0506391a7a259accf558c822d28be3b219 기준으로 이전 아홉 묶음과 test_execution_history_fields.py를 실제 재실행했다. Python 3.12.14와 jsonschema[format] 4.26.0 환경이며 원본 출력은 저장소 밖의 별도 폴더에 보존했다. 이전 검증 기록은 해당 시점 기록으로 유지한다.

이번 보완은 로컬 커밋까지만 진행하며 Push·PR 수정·main 병합을 수행하지 않는다. D/B/C 운영 코드·ReportStore·.bak·과거 저장 기록은 변경하지 않는다.
