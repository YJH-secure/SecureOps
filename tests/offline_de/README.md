# D/E Q09 격리 MOCK 재현

이 테스트는 외부 고정 소스가 필요합니다. 순수 main만으로 FILE-01 통합을 실행할 수 없습니다. 필요한 파일을 임의 생성하거나 stub으로 대체하지 않습니다. `run_tests.py`는 누락·해시 불일치 시 실패합니다. 일반 unittest discovery에는 이 외부 의존 작업을 자동 포함하지 않습니다.

## 고정 소스

- D: `0cab3a247d2143fc5556e37f6651440e109eef70`
- E PR #43: `57362706701a540247d2eb448099400e6b561749`
- E 선행 #35: `03573429825e02e6400257f19c67f337e454dd71` → #23: `b0ef73a1613ebc40fdd596edcbaf0413d32309b8`
- C: `2fac2a02edb1edf08cf4435138f4a1d543e33ba2`
- C Bridge: `497ac6a21270f517ad94041dcd7769eef3aa2a1c16b956df81e931fb1d698714`
- D FILE-01 callback: `4812dc4da5b660fbc5e4eb5c349905f6ccc28cbdcd8b0acb7b949d9c0f26ad58` (별도 전달 소스, 이 PR에 포함하지 않음)

`sources.json`은 Git commit SHA, E LF Git blob SHA-1, 파일 SHA-256을 구분합니다. E 9개 실제 구현 파일은 PR #43의 Git blob과 대조합니다. 문서·CLI를 포함한 전체 E checkout의 동일성을 주장하지 않습니다.

## 실행

실제 확인 환경: Windows / Python 3.14.2. 이미 설치된 jsonschema 및 의존성을 사용했습니다. 패키지 설치는 수행하지 않았습니다. Python 3.12·Linux·실제 SSH·VM·운영 권한은 이번 검증 범위가 아닙니다.

외부 E checkout은 `remediation/`을, C checkout은 `checks/system/`을, Bridge 루트는 `file01_pilot/`을 포함해야 합니다. callback 파일은 위 SHA와 일치해야 합니다. 아래 경로는 팀원이 승인된 로컬 사본 위치로 지정합니다.

```powershell
$env:SECUREOPS_DE_E_ROOT = '<E43 checkout root>'
$env:SECUREOPS_DE_C_ROOT = '<C checkout root>'
$env:SECUREOPS_DE_BRIDGE_ROOT = '<C Bridge root>'
$env:SECUREOPS_DE_CALLBACK_FILE = '<verified callback file>'
$env:SECUREOPS_DE_RESULTS_DIR = '<new isolated evidence folder>'
python -B tests/offline_de/run_tests.py
```

```sh
export SECUREOPS_DE_E_ROOT='<E43 checkout root>'
export SECUREOPS_DE_C_ROOT='<C checkout root>'
export SECUREOPS_DE_BRIDGE_ROOT='<C Bridge root>'
export SECUREOPS_DE_CALLBACK_FILE='<verified callback file>'
export SECUREOPS_DE_RESULTS_DIR='<new isolated evidence folder>'
python -B tests/offline_de/run_tests.py
```

Linux 명령은 재현 제안이며 실행 완료 기록이 아닙니다. 결과 폴더는 새 경로를 사용해 과거 로그를 보존합니다. runner는 실제 import 파일, 소스 해시, 테스트별 결과 및 종료 코드를 기록합니다. 네트워크·subprocess·chmod/chown 호출은 테스트 동안 차단합니다. 저장소는 임시 디렉터리만 사용합니다.

## 판정

- 일반 P01~P13: 과거 목적 유지, P13 코드 동일. P03은 E43의 FILE-01 지원 추가에 맞춰 미지원 합성 항목을 SVC-01로 교체했고 단언은 변경하지 않았습니다.
- 신규 Q01~Q13: 실제 고정 C Bridge·D callback·E 엔진/어댑터와 공통 호출부를 결합합니다. 변조 입력과 I/O 오류는 명시적 합성 주입입니다.
- callback은 미저장 보고서만 반환합니다. E 어댑터가 phase별 저장·재조회, 공통 호출부가 E 이력 저장·재조회만 담당합니다.
- 중복 scan_id·execution_id 거부 및 단일 실행 내부 호출 횟수를 검증합니다. 프로세스 재시작 후 조치 재실행 방지 저장소는 구현하지 않습니다.
