# D↔E JSON v1.2 최종 증거 제출 패키지

팀장 검토용 준비 자료다. 기존 검증 결과를 보존해 복사·분석했으며 GitHub에는 제출하지 않았다.
이번 정리 작업에서 3.14 unittest를 재실행하지 않았다. 로그의 실행 시각은 원래 11/12 실행 시각을 유지했다.
Python 3.12는 로컬 실행기를 찾지 못해 **미실행**이다.

## 고정 기준과 최신 main 확인

- D: `62d1bf72ef52c7455bc0c2dd624206eb8350f925`.
- E PR23: `b0ef73a1613ebc40fdd596edcbaf0413d32309b8`.
- E 기능 기준 `7730f4ff6d8fc666bd68093f072e7971c79e358a` 이후 제출 HEAD까지는 README만 변경됐다.
- 이번 fetch 후 origin/main도 D 고정 기준 62d1bf7과 같다. 다른 main SHA를 검증했다고 표시하지 않았다.
- 기존 D/E Worktree와 PR20/25, 운영 코드·기존 테스트는 변경하지 않았다.
- [main 조회 기록](main-status.json), [재현 입력·소스 스냅샷 해시](reproduction-inputs.json).

## 실행 환경·명령·결과

원래 최종 실행: 2026-11-12 09:19:14–09:19:50 KST.
Windows 11 / CPython 3.14.2 / 별도 가상환경 / E 지정 `jsonschema[format]==4.26.0`.
[전체 의존성](python-3.14/dependencies.txt), [기준 SHA·명령·시각·결과 JSON](python-3.14/environment-and-results.json).

| 실제 실행 묶음 | 통과 | 실패 | 오류 | Skip | 기존 실행 로그 사본 |
|---|---:|---:|---:|---:|---|
| E 조치·v1.1/v1.2·D 연동·B 계약 | 85 | 0 | 0 | 0 | [01](python-3.14/logs/01-e-remediation.log) |
| E 이력 저장·승인/시각·버전 | 38 | 0 | 0 | 0 | [02](python-3.14/logs/02-e-history.log) |
| D CVSS·Schema | 52 | 0 | 0 | 0 | [03](python-3.14/logs/03-d-cvss.log) |
| C FW/LOG 별도 회귀 | 29 | 0 | 0 | 0 | [04](python-3.14/logs/04-c-fw-log.log) |
| D 독립 통합 | 8 | 0 | 0 | 0 | [05](python-3.14/logs/05-independent.log) |
| 최신 D 기존 173개 + 독립 통합 8개 | 181 | 0 | 0 | 0 | [06](python-3.14/logs/06-d-full.log) |

E 123개는 첫 두 행 85+38이다. E123 + D52 + C29가 204개 범위다.
각 worker는 기존 unittest discovery를 사용하고 새 프로세스에서 실행됐다. E 코드는 E checkout,
D core는 main checkout에서 import했으며 그룹별 imports JSON에 실제 경로와 SHA-256을 남겼다.
SECUREOPS_D_SOURCE를 공식 D로 지정해 E v1.1 연동 클래스도 건너뛰지 않았다.

원래 재현 명령:

```powershell
<PYTHON_314> -m pip install -r <E_CHECKOUT>/reports/e-v12-pr23-feedback-20261111/requirements-test.txt
<PYTHON_314> -B -X utf8 docs/evidence/de-pr23-independent-20261112/run-review.py --e-root <E_CHECKOUT> --output-dir <NEW_OUTPUT_DIRECTORY>
```

worker별 정확한 명령은 환경 JSON과 각 로그 첫 행에 있다. 범위는 E tests/의 test_remediation*.py와
test_execution_history*.py, D tests/의 test_cvss*.py, C 방화벽·로그 모듈, 독립 테스트 파일, D tests/ 전체다.
재현 소스 두 파일은 reproduction-sources/에 원본 그대로 보존했다.
이 사본 경로에서 직접 실행하지 말고 reproduction-inputs.json의 required_repository_path에 배치한
별도 D checkout에서 실행한다. 기존 결과 출력 경로를 덮어쓰지 않는다.

## 실제 테스트 ID로 확인한 중복

추정 건수나 파일 수로 계산하지 않았다. 여섯 최종 verbose 로그의 OK 테스트 ID 393개 발생을 추출하고,
각 ID에 실행 명령·checkout·파일 경로·줄바꿈 정규화 소스 해시를 연결했다.
[전체 ID 목록](test-id-inventory.json), [교집합·고유 ID](test-overlap.json).

| 관계 | 실제 ID 수 |
|---|---:|
| E123 + D52 + C29 합집합 | 204 |
| 위 204와 D 독립 8 교집합 | 0 |
| 204와 결합 181 교집합 | 76 = E 기존 v1.1/연동 24 + D CVSS 52 |
| 독립 8과 결합 181 교집합 | 8 |
| 결합 181에만 있는 나머지 | 97 |
| 여섯 실행의 수행 횟수 합 | 393 |
| 여섯 실행의 고유 테스트 ID 합집합 | 309 |

즉 181 = 중복 76 + 독립 8 + 나머지 D 97이다. 204+8+181을 서로 다른 393개 테스트로 부르지 않는다.
동일 ID와 소스 파일 해시를 함께 센 수도 309여서, 이 실행들 사이의 중복 ID는 동일 파일 내용으로 확인됐다.
단위 테스트 ID가 같다는 사실만으로 운영 환경 전체의 독립성을 보장한다는 의미는 아니다.

## 태준님 204개 보고와 비교

E의 현재 PR/README는 Python 3.12.14, D 66495d0 기반으로 총 204개 실행을 보고한다.
공개된 과거 완전 로그 묶음은 tested_head bb050165, D 6bf80bb의 **184개**다.
이 공개 로그에서 실제 184개 ID를 확인했고 모두 D 담당자의 204개 실행 ID에 포함됐다.
추가 20개는 test_execution_history_fields.py 10개와 test_execution_history_versions.py 10개다.
현재 E 소스·보고 표와 저희 실제 실행에서 이 20개를 확인했다.

다만 E가 이후 수행한 **최신 204개 전체 원본 stdout·원래 실행 시각·실행 바이너리 해시**는 공개 자료에서
확인하지 못했다. README는 원본 로그가 저장소 밖에 보관됐다고 설명한다.
과거 184개 로그를 최신 204개 로그로 바꾸거나 Python 3.12 독립 재실행 증거로 사용하지 않았다.
구형·신형의 ID가 같아도 소스 기준 커밋은 다를 수 있으므로 과거 184개를 현재 코드 실행 증거로 치환하지 않는다.
[작성자 비교 데이터](e-author-comparison.json), [공유용 비교 요약](comparison-for-e.md).

## Python 3.12 확인

런처 py -0p, 일반 Python 설치 위치, 저장소 가상환경, 기존 검증 가상환경 및 E 공개 자료에 나온
관리 런타임 후보를 점검했다. 발견한 실행기들은 3.14.2이며 실행 가능한 3.12는 없었다.
[환경 확인 기록](python-3.12-availability.json).

- Python 3.12 테스트: **미실행**, 실패나 unittest Skip 결과가 아님.
- 코드 호환성: 이 자료로 Python 3.12 성공·실패를 판정할 수 없음.
- 환경 사유: Python 3.12 실행기 부재. 새 Python 인터프리터 다운로드·설치는 하지 않음.
- 후속: 3.12 환경이 제공되면 별도 venv에 같은 E 요구 의존성을 설치하고 새 출력 디렉터리에서 재실행.
  그때의 결과는 기존 3.14 결과와 별도로 추가해야 함.

## D 진단 16건 / E 이력 9건과 상태 연결

[D 진단 저장소](python-3.14/d-diagnoses), [E 실행 이력 저장소](python-3.14/e-executions),
[원래 독립 결과](python-3.14/independent-results.json), [패키지 사본 새 프로세스 재조회](scan-links-and-reload.json).

기존 저장물을 바이트 동일하게 복사하고 새 읽기 전용 프로세스로 16/9건을 모두 재조회했다.
이는 새 조치 실행이 아니라 기존 JSON 사본의 저장·링크 검증이다.

- E는 schema_version=1.0, diagnosis_schema_version=1.1/1.2를 기록한다. D 보고서는 자신의 1.1/1.2 계약을 유지한다.
- execution_id/plan_id/approval_id와 before/after/post_rollback scan ID는 별도 식별자다.
- 핵심 7개 사례의 before와 생성된 after/post 보고서는 패키지에 있고 같은 ID로 조회된다.
- 버전 호환 두 사례는 after 보고서와 E 이력만 보존했다. E의 before_scan_id는 기록돼 있지만 그 before
  스냅샷을 이 패키지가 포함하거나 재조회했다고 표시하지 않았다. 해당 값은 scan-links JSON에서 명확히 구분한다.
- 롤백 후 새 진단이 없거나 조회 검증이 실패하면 final_security_status=null, final_security_verified=false다.
- save 성공/load 실패에도 after_scan_id 또는 post_rollback_scan_id가 유지되고 후속 조회가 가능했다.
  이후 pass 보고서를 읽어도 이를 롤백 후 상태로 승격하거나 E outcome을 success로 바꾸지 않았다.
- 롤백 후 별도 합성 pass를 확인한 사례도 원래 조치 outcome=failed를 유지했다.
- 기존 before 바이트 보존, 동일 scan_id/execution_id 덮어쓰기 거부는 독립 테스트에서 확인했다.

## 보존·미해결·제출 범위

기존 증거 59개는 파일 해시 기준으로 보존했다. python-3.14/의 42개 파일은 기존 final/의 정확한 사본이다.
초기 수집기의 테스트 탐색/JSON 비교 문제는 initial-harness-diagnostics/에 별도 보존했으며 최종 통과 결과와 구분한다.
원래 결과 숫자·시각·원본 테스트 기대값·Skip 조건을 변경하지 않았다.

미해결/협의:

1. Python 3.12 독립 실행 환경 및 E 측 최신 204개 전체 원본 결과 공유 여부.
2. MockRecheckAdapter와 실제 공통 실행 계층의 계약 인수·매핑.
3. E 결과는 명시적 save(result)가 필요하므로 운영 호출부의 실패/거부 포함 저장 책임.
4. D/E 저장 경로 분리·권한·보관·하드링크·장애 복구 정책.
5. 실제 SSH/VM·운영 조치/복구·Rocky·실환경 E2E는 **미검증**.

파일 저장소는 암호화·서명 기반 감사 저장소가 아니며 이번 MOCK 통과가 운영 배포 승인은 아니다.
실제 SSH/VM 실행, 운영 코드 수정, Commit·Push·PR 생성·수정·Merge는 하지 않았다.
GitHub에 포함할 최종 파일 범위는 팀장님이 이 패키지를 검토한 뒤 결정한다.
