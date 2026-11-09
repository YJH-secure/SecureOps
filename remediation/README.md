# E 파트 · SSH-01 모의 조치 및 재검증

박태준 · 1차 시연 · Ubuntu 24.04 LTS

팀 기준표와 공통 JSON v1.1을 바탕으로 SSH root 원격 로그인 제한의 조치 흐름을 검증한다. 취약으로 판정된 SSH-01만 조치 후보로 삼는다. 모의 조치는 메모리의 가상 설정값을 바꾼다.

## 실행

프로젝트 루트에서 Python 3.12로 실행.

    python -m remediation
    python -m remediation --mock
    python -m remediation --mock --deny
    python -m remediation --mock --skip
    python -m remediation --mock --fail-at backup
    python -m remediation --mock --fail-at apply
    python -m remediation --mock --fail-at verify_service
    python -m remediation --mock --fail-at validate
    python -m remediation --mock --fail-at recheck
    python -B -m unittest discover -s tests -p test_remediation.py -v

기본 실행은 변경 계획만 출력한다. 팀의 v1.1 결과 파일은 python -m remediation --report <JSON 파일>로 읽어서 계획을 미리 볼 수 있다. --mock은 내장 샘플과 가상 승인만 사용한다.

## 실행 흐름

1. 공통 JSON 검증 및 취약 SSH-01 변경 계획 생성.
2. 대상·항목 허용 목록과 해당 계획의 가상 승인 확인.
3. 가상 설정 백업, 변경 적용, 변경 설정 검증.
4. 동일 target_id와 check_id로 새 scan_id의 재진단 결과와 비교.
5. 승인 내역, 조치 전후 판정, 재진단 결과, 백업 ID와 복구 여부를 JSON에 출력.

| 조치 상태 | 의미 |
| --- | --- |
| success | 승인, 백업, 모의 조치와 필수 검증 완료 |
| rejected | 승인 거부 또는 유효한 승인 확인 불가 |
| skipped | 조치 대상·정책·허용 목록 기준에서 제외 |
| failed | 조치, 필수 검증 또는 재진단 실패. 복구 여부는 rollback에 별도 기록 |

Dry-run에서 조치 가능한 계획을 미리 보면 planned를 반환한다. 백업 상태는 backup, 복구 상태는 rollback에서 각각 확인한다. 재진단 실행 오류는 failed에 실패 원인을 기록하고, 설정 검증을 통과한 상태에서 자동 복구를 시도하지 않는다.

완료한 단계는 completed_steps, 실패한 단계와 이유는 failed_stage와 failure_reason에서 확인. 복구 확인에 실패하면 rollback_failed_stage와 rollback_failure_reason도 출력. --fail-at verify_service는 조치에 먼저 실패한 뒤 복구 후 서비스 점검 실패를 재현한다.

build_plan(report, check_id)는 정상 보고서에서 조치 계획을 반환한다. 조치 제외 시에는 작업이 비어 있고 skip_reason이 있다. Remediator.run(report, plan, ...)은 이를 skipped 결과로 반환한다. 잘못된 진단 JSON은 검증 오류로 처리한다.

after_report가 있으면 공통 JSON v1.1 보고서다. 승인 거부, 조치 제외, 재진단 실행 오류에서는 null이다. 바깥쪽 승인·복구·비교 정보는 E 파트의 모의 조치 기록이다. 공유용 출력은 민감정보를 제거한 샘플로 생성한다.

## 통합 전에 확인할 사항

팀원 진단 모듈 호출 방식, 실제 관리자 승인 확인, 실습 VM 변경 및 복구 검증은 팀장과 협의 후 진행. FILE-01은 파일별 기준 확정 후 범위 결정.
