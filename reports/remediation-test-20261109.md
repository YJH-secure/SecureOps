# E 모듈 테스트 및 재검증 보고서

검증일: 2026-11-09  
작업 브랜치: `feature/remediation-ptj`  
확인 환경: Windows PowerShell, Python 3.11.9  
범위: SSH-01 MOCK 조치 및 재검증

## Git 반영 상태

E 모듈의 기능 코드는 원격 작업 브랜치에 Push했다. 이후 `origin/main`을 로컬 작업 브랜치에 충돌 없이 병합했고, 병합 후 단위 테스트를 재실행했다. README와 이 보고서는 최신 구현 동작에 맞춰 수정했다.

## 단위 테스트: 22개

프로젝트 루트 실행 명령:

~~~powershell
python -B -m unittest discover -s tests -v
~~~

최신 main 병합 및 문서 수정 후 실제 확인한 결과:

~~~text
Ran 22 tests in 0.013s

OK
~~~

- 단위 테스트 22개 성공
- 실패 0개, 오류 0개
- 승인·허용 목록·dry-run·입력 검증·변경 실패·재진단 실패·복구 등 검증

## 과거 연동 테스트: 3개 (현재 재실행 미확인)

별도 이전 실행 환경에 22개 단위 테스트와 B/D 팀원 코드 연동 테스트 3개, 총 25개 통과 기록이 있었다. 다만 현재 Git 저장소에 있는 테스트 소스는 `tests/test_remediation.py`이며, **연동 테스트 3개의 원본은 포함돼 있지 않다**.

따라서 최신 main 반영 후에 검증된 것은 22개 단위 테스트다. 3개 연동 테스트는 **미실행**으로 구분한다. 다른 환경에서 재현하려면 다음이 필요하다.

1. 연동 테스트 원본 파일과 실행 명령
2. B/D 팀원 코드의 재현 가능한 고정 버전(커밋 또는 동등한 소스)
3. 입력 JSON fixture 및 기대 결과
4. 개인 로컬 Git 객체를 요구하지 않는 실행 구성

현재는 이 재현 조건이 완료되지 않았으며, 최종 통합 전에 후속 정리가 필요하다.

## MOCK 수동 실행 확인

| 시나리오 | outcome | rollback |
| --- | --- | --- |
| 정상 조치·재진단 | `success` | `not_needed` |
| 조치 적용 실패 | `failed` | `verified` |
| 재진단 실행 실패 | `failed` | `verified` |

별도 확인 사항:
- 기본 dry-run: `planned`, 실제 변경 없음
- 서로 다른 실행에서 고유 `execution_id` 생성
- 승인 거부: `rejected`, `stopped_stage=approval`
- 조치 제외: `skipped`, `stopped_stage=plan`
- 실제 실패: `failed_stage` 및 `failure_reason` 사용

재현 명령:

~~~powershell
python -B -m remediation
python -B -m remediation --mock
python -B -m remediation --mock --fail-at apply
python -B -m remediation --mock --fail-at recheck
~~~

## 재진단 결과와 복구 결과의 의미

`after_report`는 조치 적용 후 재진단 시점의 결과이며, 존재하면 공통 진단 JSON v1.1 형식을 따른다. 재진단 전 중단·실행 실패 등으로 `null`일 수 있다. 이후 복구가 이루어진 경우라도 `after_report`는 복구 후 최종 서버 상태를 나타내지 않는다.

복구 성공·실패는 `rollback`으로 별도 기록한다. `rollback=verified`는 MOCK 복구 검증 성공이지 실제 서버를 다시 스캔했다는 뜻이 아니다. `comparison`도 복구 후 최종 상태 판정이 아니라 조치 전후 재진단 결과 비교다.

## D 모듈 연동 시 공유할 필드

`execution_id`, `target_id`, `check_id`, `before_scan_id`, `outcome`, `stopped_stage`, `failed_stage`, `backup`, `rollback`, `after_report`, `comparison`

진단 JSON v1.1과 조치 이력은 별개 데이터로 저장한다. 성공·실패·중단 상태의 기록 방식과 영속 저장은 D 담당자와 추가 검증이 필요하다.

## 검증 한계

- 실제 Ubuntu 서버의 SSH 설정 변경·reload·접속 시험 미실시
- 설정 백업·조치·복구는 MOCK 환경으로 제한
- 실제 서버 자동 복구 정책 미승인
- 최신 main 병합 후 연동 테스트 3개 미실행
- D 모듈 저장 기능 및 end-to-end 연동 미완료
