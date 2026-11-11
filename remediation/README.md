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

E의 반환 객체가 진단 보고서와 별개인 실행 이력이다. E에서 생성한 execution_id에 before_scan_id, after_scan_id, post_rollback_scan_id를 연결한다. D JSON v1.2와 ReportStore API는 변경하지 않는다. E 이력을 D의 진단 보고서로 저장하거나 새로운 영속 저장 규격을 추가하지 않는다.

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


### 이번 추가 규격 검증 결과 (2026-11-11)

기존 회귀 117개(24+18+19+52+4)와 신규 실행 이력 MOCK 테스트 20개를 구분해 실제 실행했으며 모두 통과했다. 실패·오류·건너뜀은 각각 0개다. 과거 PR #23의 117개 증거를 새 실행 로그로 재사용한 결과가 아니다. 기존 테스트 파일은 수정하지 않았다. 현재 origin/main 기준은 e4af8a6이며 Python 3.12.14, jsonschema[format] 4.26.0 환경을 사용했다.

    python -B tests/run_de_mock.py --d-ref e4af8a6659a695a5d7e0152b8c0d831e7736fef1
    python -B -m unittest discover -s tests -p test_remediation_v12.py -v
    python -B -m unittest discover -s tests -p test_remediation_execution_integration.py -v
    python -B -m unittest discover -s tests -p 'test_cvss*.py' -v
    python -B -m unittest discover -s tests -p test_remediation_b_v12_integration.py -v
    python -B -m unittest discover -s tests -p test_remediation_execution_history.py -v

이 결과는 오프라인 MOCK 검증이다. 실제 SSH 실행 및 D 저장 API 변경은 없다. 이번 작업은 로컬까지만 반영하며 Push·PR 업데이트는 하지 않는다.
