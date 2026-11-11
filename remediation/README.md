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
