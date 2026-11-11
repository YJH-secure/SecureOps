# C JSON v1.2 어댑터 및 재현 방법

FILE-01·SVC-01·FW-01·LOG-01은 기본으로 JSON v1.1 개별 결과를 출력한다.
다음과 같이 출력 버전을 명시하면 v1.2를 출력한다.

```bash
python3 -m checks.system.file_check --result-version 1.2
python3 -m checks.system.service_check --result-version 1.2
python3 -m checks.system.firewall_check --result-version 1.2
python3 -m checks.system.log_check --result-version 1.2
```

진단 함수는 기존 v1.1 결과를 생성하고 CLI 출력 경계에서 어댑터를 적용한다.
v1.2 결과는 severity를 제거하고 cvss를 포함한다. status·evidence·recommendation과
details는 보존한다. 정책 JSON에 있는 severity는 기존 정책 검증에 사용한다.

| 진단 상태 | CVSS 평가 상태 |
| --- | --- |
| pass·error·needs_review·not_applicable | not_applicable |
| vulnerable | 기본 pending |
| vulnerable 중 CVSS 평가에 부적합하다고 검토된 정책 위반 | 명시한 검토 사유가 있으면 not_applicable |

프로그램 호출자는 검토한 정책 위반에 한해
`adapt_result(result, '1.2', policy_only_rationale='검토 근거')`를 사용할 수 있다.
CLI는 근거가 확정되지 않은 레거시 취약 결과를 pending으로 출력한다.
기존 severity를 CVSS 점수나 등급으로 변환하지 않는다.
pending·not_applicable은 version·vector·base_score·rating·source가 null이며
rationale에 이전 상태와 평가 이유가 있다. C는 scored 결과를 산정하지 않는다.

유효한 진단 JSON을 출력하면 status=error여도 종료 코드 0으로 전달한다.
잘못된 실행 인자와 프로그램 실행 실패는 기존 CLI의 비정상 종료로 구분한다.
C는 개별 객체를 반환하고 D가 상위 보고서를 생성·검증·집계한다.

## 공식 커밋 기준 로컬 재현

이 저장소와 D의 검증 기준 커밋을 확인한 후 저장소 루트에서 실행한다.

```bash
python3 -m pip install -r checks/system/requirements-dev.txt
python3 -B -m unittest discover -s checks/system/tests -v
python3 -B -m checks.system.verify_json_scenarios --code-commit <FULL_C_SHA>
```

D의 다른 checkout을 지정하려면 다음 인자를 추가한다.

```bash
python3 -B -m checks.system.verify_json_scenarios \
  --code-commit <FULL_C_SHA> --d-root /path/to/SecureOps-D
```

--code-commit은 기록용 표식이다. 도구가 그 문자열과 실행 파일의 일치를 자동
검증하지 않으므로 checkout과 Git blob 해시를 별도로 확인한다.
증거 제출에는 실제 실행 커밋과 D 커밋을 함께 기록한다.
기본 출력은 verification-runs/json-v12 아래 새 디렉터리이며 기존 실행을 덮어쓰지 않는다.

## 검증 항목

공식 코드용 시나리오는 이전에 팀장이 재실행한 v1.1 및 v1.2 ZIP의 입력을
동일하게 사용한다. 필수 결과 필드를 비교하고 전체 details의 변환 전후 보존,
미평가 null, 원본 v1.1 불변, 기존 severity와 CVSS 분리를 확인한다.
각 진단 상태와 CVSS 상태를 따로 집계한 D 보고서의 저장·재조회도 비교한다.

| 시나리오 | 함수 실행 방식 |
| --- | --- |
| FILE pass | 실제 판정 함수에 MOCK 정책·메타데이터 주입 |
| SVC vulnerable | 실제 판정 함수에 MOCK 금지 서비스·활성 유닛 주입 |
| FW error | 실제 수집 함수에 MOCK nft 권한 오류 주입 |
| LOG needs_review | 실제 수집 함수에 MOCK 조회 성공·미승인 정책 주입 |
| FILE not_applicable | 공통 결과 생성기의 적용 제외 계약 fixture |

FW·LOG의 운영 정책 기반 pass/vulnerable 판정과 FILE의 운영 제외 자동 판정은
이 시나리오의 구현 완료 범위가 아니다. 각 경우는 별도 scan_id로 저장한다.
중복 FILE-01을 한 보고서에 합치지 않는다.

잘못된 CVSS 조합·누락·severity 유출·미평가 점수와 Vector, 잘못된 JSON·중복 키,
비표준 수·실행 실패·전송 실패·버전 불일치의 28개 입력을 거부하는지 확인한다.
거부 테스트의 합성 점수·Vector는 유효한 평가 결과가 아니다.

재현 도구는 실제 진단 명령 실행을 차단하고 임시 MOCK 정책·설정만 사용한다.
SSH 실행·운영 정책 승인·sudoers 적용·시스템 설정 변경은 별도 검증 단계다.

## 이전 ZIP과의 차이

어댑터와 네 CLI의 출력 변경, 어댑터 테스트는 검증된 로컬 구현을 재사용했다.
시나리오 입력은 동일하며 독립 ZIP의 두 runner를 저장소 모듈로 옮겼다.
경로는 checks/system/scenarios로, 기본 D는 저장소 core로 연결했다.
외부 D checkout 지정과 커밋 표식 기록을 제공한다.
동봉 D 코드나 과거 실행 결과를 새로운 공식 실행 결과로 복사하지 않는다.
새 커밋의 재실행 로그와 이전 ZIP의 비교 근거는 별도 evidence 문서에 기록한다.
