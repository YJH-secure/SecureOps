# SecureOps E FILE-01 최종 제출 자료

## 기준과 범위

- 제출 브랜치 기준 시작점: PR #35 `03573429825e02e6400257f19c67f337e454dd71`
- 검증된 E 소스 기준: `2d776a52faf692f13ebca2f00a591bcfa805b8fb`
- C 기준: `2fac2a02edb1edf08cf4435138f4a1d543e33ba2`
- C Bridge SHA-256: `497ac6a21270f517ad94041dcd7769eef3aa2a1c16b956df81e931fb1d698714`
- D callback 전달본 SHA-256: `4812dc4da5b660fbc5e4eb5c349905f6ccc28cbdcd8b0acb7b949d9c0f26ad58`
- D Core 기준 commit의 존재와 주요 Core/규격 파일 6개 blob 일치는 후속 검토에서 확인했다. 전달 callback 및 테스트가 그 commit tree 또는 최종 통합 tree에 연결되는지는 미확인이다.

이 자료는 E FILE-01의 격리 MOCK 구현과 검증 결과를 검토하기 위한 것이다. 실제 서버 파일 권한 변경, SSH 연결, 원격 자동 조치는 수행하지 않았다.

## 제출물

- `evidence/SecureOps_E_FILE01_Final_Evidence_20261126_rev1.zip`: manifest 크기와 경로 참조를 보완한 비식별 증거 사본.
- `evidence/SHA256SUMS.txt`: 제출 ZIP의 표준 체크섬 목록. `evidence` 폴더에서 `sha256sum -c SHA256SUMS.txt`로 확인한다.
- 기존 ZIP은 제출 트리 밖에 로컬 보관하며, 보존용 SHA-256은 `evidence-manifest.json`에 기록한다.
- `presentation-guide-20261126.md`: 발표 순서, 시연 설명 및 예상 질문.
- `final-freeze-20261126.md`: 구현 동결 범위, 검증 근거와 잔여 한계.
- 상위 저장소 변경 E 코드 8개는 기준 checkout 및 304건 검증 src와 바이트 해시가 일치하도록 고정했다. 변경 파일 목록과 SHA-256은 Git diff 및 `evidence-manifest.json`을 참조한다.

## 검증 수치 읽는 법

304건은 E/C 266건과 D callback 38건의 기존 교차 검증 결과다. 이번 제출 준비에서 회귀 테스트를 재실행하지 않았다. D04 정상 복구와 D05 실패 롤백의 후속 실행은 각 1건 PASS였으나 기존 테스트 ID를 다시 실행한 것이므로 304건에 더하지 않았다. 스크린샷의 FILE-01 두 장은 D04/D05 결과 JSON을 요약해 출력한 캡처이며 실시간 실행 화면이 아니다.

## 재현 절차와 필요한 자료

11/25 독립 교차 검증은 격리한 `src`에 고정 E/D Core 소스, 고정 C `checks`, 패키지 형태의 C Bridge와 전달 D callback을 배치하고 기존 `dependencies-readable`을 사용했다. 아래의 경로 구성은 그 환경에서 실제 import로 확인했다. 304건과 D04/D05의 실행 결과는 11/25 기록이며, 이번 보완에서는 import와 파일 해시를 검증했다.

### 필요한 자료와 출처

| 자료 | 확보 방법 및 검증값 |
|---|---|
| E 소스 | 비공개 SecureOps 저장소의 제출 브랜치 `feature/remediation-file01-submit` 또는 PR #43에서 확보. FILE-01 변경 E 코드·테스트 8개는 `evidence-manifest.json`의 SHA-256과 대조한다. 검증 당시 E 기준 commit은 `2d776a52faf692f13ebca2f00a591bcfa805b8fb`이다. |
| Python 및 패키지 | Windows x64 Python 3.12.14 및 기존 `dependencies-readable` 디렉터리의 `jsonschema` 4.26.0과 전이 의존성을 사용한다. 동일 환경이 필요하면 11/25 검증 담당자에게 이 디렉터리와 기준 해시를 요청한다. 확인한 대표 SHA-256은 `jsonschema/__init__.py`의 `a7e470e134bfd0e3c76482722260d6b1d5a099de823d61cc5cbabb06e4314c67`, `rpds/rpds.cp312-win_amd64.pyd`의 `f2151350525864528ac0664f461ea49444b787834f05a0c96f34fb3ac2690046`이다. |
| C 소스/Bridge | C 담당자에게 고정 C `2fac2a02edb1edf08cf4435138f4a1d543e33ba2`의 `checks/`와 검증에 사용한 `file01_pilot/` Bridge 패키지를 요청한다. SHA-256은 `checks/system/file_check.py`가 `26c2ed2c553e4031317933af512e887739be5601cf22dd54fdf416685dc29cd2`, `checks/system/result_adapter.py`가 `50388632296bc54c5ed26fe902472373f5076b95a208745722afb6888802b539`, `file01_pilot/c_mock_bridge.py`가 `497ac6a21270f517ad94041dcd7769eef3aa2a1c16b956df81e931fb1d698714`이다. |
| D callback | D 담당자에게 승인된 비공개 경로로 `file01_mock_callback.py`와 테스트를 요청한다. 전달 callback SHA-256 `4812dc4da5b660fbc5e4eb5c349905f6ccc28cbdcd8b0acb7b949d9c0f26ad58`, 테스트 SHA-256 `ea09f0c096ad5d9b28250ceeaf3d11c7d5137bda72ec47e616ce44a080347ec1`을 대조한다. D Core 기준은 `0cab3a247d2143fc5556e37f6651440e109eef70`이다. 후속 검토에서 이 commit과 `core/main.py`, `core/storage.py`, `core/cvss_validation.py`, `core/cvss_assessment.py`, `core/cvss.py`, JSON Schema 파일의 blob 일치를 확인했다. 전달 callback이 그 commit tree 또는 최종 통합 tree에 포함·연결되는지는 확인되지 않았다. |

C Bridge, 고정 C 소스, 전달 D callback 및 Python 의존성은 제출 ZIP 밖에서 확보해야 한다. 팀원이 접근할 수 있는 공유 위치는 확인되지 않았다. 각 담당자에게 승인된 비공개 전달 경로로 위 파일을 요청한다. 아래 절차는 해당 자료를 확보한 환경을 전제로 한다.

### 격리 환경 준비

11/25 검증에 사용한 `src`와 `dependencies-readable`을 확보한 경우 그대로 지정한다. 별도 준비가 필요하면 빈 검증 폴더에 `src`를 만들고, 제출 E 소스의 `remediation/`, `tests/`와 기준 D Core의 `core/`, `docs/`를 배치한다. `src/checks/`에는 고정 C 자료만 배치하고 `src/file01_pilot/`에는 Bridge 패키지를 배치한다. 제출 저장소의 `checks/`와 기존 checkout은 별도 위치에 둔다. 전달 D callback을 실행할 때는 검증 사본의 `src/core/file01_mock_callback.py`와 `src/tests/test_file01_mock_callback.py`에 전달 파일을 배치한다. 복사한 파일은 위 기준 해시와 대조한다.

PowerShell에서 변수를 채운다. 두 경로 모두 격리 `src`에서 실행한다. 이 작업 위치와 경로 구성을 사용하면 저장소의 `checks`가 고정 C 소스를 가리는 문제가 발생하지 않는다.

```powershell
$Python = (Resolve-Path '<Python 3.12.14 실행 파일>').Path
$Src = (Resolve-Path '<격리 검증 src 디렉터리>').Path
$Deps = (Resolve-Path '<dependencies-readable 디렉터리>').Path
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONDONTWRITEBYTECODE = '1'
$Output = Join-Path ([IO.Path]::GetTempPath()) ('secureops-file01-' + [guid]::NewGuid())
$Imports = 'import sys, importlib, hashlib; from pathlib import Path; from importlib.metadata import version; sys.path.insert(0, str(Path.cwd() / "tests")); print(sys.version.split()[0], "jsonschema", version("jsonschema")); print("checks", list(importlib.import_module("checks").__path__)); files = [Path(importlib.import_module(name).__file__).resolve() for name in sys.argv[1:]]; [print(p, hashlib.sha256(p.read_bytes()).hexdigest()) for p in files]'
$Common = @('checks.system.file_check', 'checks.system.result_adapter',
    'core.main', 'core.storage', 'core.cvss_validation', 'remediation.engine',
    'remediation.file01', 'jsonschema', 'rpds.rpds')
```

### E 테스트용 D 호환 stub

11/25의 E/C 회귀 중 FILE-01 시나리오와 callback 바인딩에 대응한다. `c_mock_bridge`를 최상위 모듈로 불러오므로 `src/file01_pilot`을 경로에 추가한다. 첫 명령은 import만 확인한다. `checks`와 C/D/E 모듈은 `$Src`, `jsonschema`와 `rpds`는 `$Deps` 아래에 있어야 한다. 출력된 해시를 위 기준과 대조한 뒤 필요한 경우 선택 테스트를 실행한다.

```powershell
$env:PYTHONPATH = $Src, (Join-Path $Src 'file01_pilot'), $Deps -join [IO.Path]::PathSeparator
Push-Location $Src
try {
    $Imports | & $Python -B -X utf8 - @Common c_mock_bridge file01_callback_stub test_file01_integration test_file01_callback_contract
    if ($LASTEXITCODE -ne 0) { throw 'E stub import failed' }
    # 선택 실행
    $env:FILE01_INTEGRATION_EVIDENCE = Join-Path $Output 'stub'
    & $Python -B -X utf8 -m unittest discover -s tests -p test_file01_integration.py -v
    if ($LASTEXITCODE -ne 0) { throw 'FILE-01 integration tests failed' }
    & $Python -B -X utf8 -m unittest discover -s tests -p test_file01_callback_contract.py -v
    if ($LASTEXITCODE -ne 0) { throw 'FILE-01 callback contract tests failed' }
} finally { Pop-Location }
```

### 전달 D callback 선택 검증 경로

D callback은 `file01_pilot.c_mock_bridge`로 로드한다. 패키지의 부모인 `src`를 경로에 두면 된다. import 출력에서 두 전달 파일과 Bridge의 해시를 확인한다.

```powershell
$env:PYTHONPATH = $Src, $Deps -join [IO.Path]::PathSeparator
Push-Location $Src
try {
    $Imports | & $Python -B -X utf8 - @Common file01_pilot.c_mock_bridge core.file01_mock_callback test_file01_mock_callback
    if ($LASTEXITCODE -ne 0) { throw 'Delivered D callback import failed' }
    # 11/25 선택 실행에 사용한 두 테스트 명령
    $env:SECUREOPS_FILE01_CALLBACK_EVIDENCE = Join-Path $Output 'delivered-D'
    & $Python -B -X utf8 -m unittest discover -s tests -p test_file01_mock_callback.py -k test_D04 -v
    if ($LASTEXITCODE -ne 0) { throw 'D04 failed' }
    & $Python -B -X utf8 -m unittest discover -s tests -p test_file01_mock_callback.py -k test_D05 -v
    if ($LASTEXITCODE -ne 0) { throw 'D05 failed' }
} finally { Pop-Location }
```

11/25 D callback 38건에 실제 사용한 명령은 `python -B -X utf8 -m unittest discover -s tests -p test_file01_mock_callback.py -v`다. 그 실행과 D04/D05 선택 실행은 ZIP의 `verification/304/D01-D38/`와 `verification/selected/D04-D05/`에 기록돼 있다. 위 절차로 선택 테스트를 재현할 경우 결과는 `$Output` 아래에 보관한다. 이번 보완에서 실행한 범위는 두 경로의 import와 로딩 파일 해시 확인까지다.

검토자는 archive 내부 README와 SHA 목록, `final-freeze-20261126.md`의 미검증 범위를 함께 확인한다.

## 독립 감사 후속 반영

최초 재검토 결과는 BLOCKER 0건, MAJOR 1건, MINOR 4건이었다. 재현 절차는 11/25 격리 `src`를 기준으로 보완하고 두 경로의 import와 파일 해시를 확인했다. 팀원 환경에서 실행하려면 위 외부 자료가 필요하다. 승인 callback 도중 동일 MOCK 객체의 대상 또는 OS를 바꾸는 경우는 향후 방어 강화 관찰로 기록한다.
