# E 파트 · SSH-01 모의 조치 및 재검증

대상 환경: Ubuntu 24.04 LTS  
구현 범위: SSH-01 MOCK 조치, 승인, 백업, 재진단, 복구

공통 진단 JSON v1.1을 바탕으로 SSH root 원격 로그인 제한의 조치 흐름을 검증한다. 실제 서버를 변경하지 않고 메모리 기반 MOCK 백엔드를 사용한다.

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

`after_report`는 **조치 적용 후 재진단 시점**의 공통 JSON v1.1 보고서다. 재진단 이전에 중단되거나 재진단 실행·검증이 실패하면 `null`일 수 있다.

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

현재 저장소의 `tests/test_remediation.py`에서 단위 테스트 **22개가 최신 main 병합 후 통과**했다.

과거 별도 환경에서 단위 테스트 22개와 연동 테스트 3개, 총 25개를 실행한 기록은 있으나, 현재 저장소에는 3개 연동 테스트의 원본 파일이 없다. 따라서 현재 환경에서 **25개 모두 재실행했다는 뜻이 아니다**.

다른 개발자 환경에서 연동 테스트를 재현하려면 연동 테스트 파일, B/D 팀원 코드의 고정 버전이나 커밋, 입력 fixture 및 실행 명령을 저장소에 제공해야 한다. 개인 로컬 Git 객체에만 의존하는 방식은 재현 조건으로 충분하지 않다. 이 항목은 최종 통합 이전의 후속 과제다.

## 검증 한계

- MOCK 설정 변경, 백업 및 복구만 검증
- 실제 SSH 접속, 설정 변경, reload, 접속 영향 미검증
- 실제 서버 자동 복구 정책 미승인
- 현재 저장소에서 연동 테스트 3개 재실행 불가
- D 모듈 영속 저장 연동은 후속 협의 필요
- FILE-01의 실제 조치는 현재 E 모듈 범위에 포함하지 않음
