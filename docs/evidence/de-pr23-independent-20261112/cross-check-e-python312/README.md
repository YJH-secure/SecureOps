# SecureOps PR #23 최신 main 통합 검증

2026-11-12 09:27 KST · Windows 11 x64 · Python 3.12.14 · jsonschema[format] 4.26.0

- GitHub main `62d1bf72ef52c7455bc0c2dd624206eb8350f925`
- GitHub PR #23 HEAD `b0ef73a1613ebc40fdd596edcbaf0413d32309b8`
- 검증 트리 `6f98efbf940ef05a8d3307835a059990c408de85`

임시 복제본의 detached HEAD에서 두 커밋을 충돌 없이 결합했다. `remediation/`은 PR HEAD와 동일하고 `core/`, `checks/`는 최신 main과 동일했다. 원본 저장소 브랜치와 Git 상태를 유지했고, 미추적 `.bak` 2개는 실행 전후 SHA-256이 일치했다.

## 실행 결과

| 검증 묶음 | 통과 | 로그 |
|---|---:|---|
| E v1.1 및 D↔E v1.1 연동 | 24 | [01](01-e-v11.log) |
| E v1.2 | 18 | [02](02-e-v12.log) |
| 공통 실행 계층 MOCK | 19 | [03](03-e-execution.log) |
| D CVSS·스키마 | 52 | [04](04-d-cvss.log) |
| B SSH-01 입력 계약 | 4 | [05](05-b-contract.log) |
| E 실행 이력·롤백 | 20 | [06](06-e-history.log) |
| E 이력 저장소 | 18 | [07](07-e-store.log) |
| C 방화벽 | 17 | [08](08-c-firewall.log) |
| C 로그 | 12 | [09](09-c-log.log) |
| E 승인 ID·시각 | 10 | [10](10-e-history-fields.log) |
| E 이력·진단 버전 분리 | 10 | [11](11-e-history-versions.log) |
| 추가 MOCK 통합 시나리오 | 4 | [12](12-full-mock-flow.log) |

기존 회귀 204개와 추가 4개 모두 통과. 실패·오류·건너뜀 0. 각 묶음의 실제 명령, 종료 코드 및 집계는 [results.json](results.json)에 기록했다. 명령과 로그의 작업 경로는 자리표시자로 치환했다. 초기 통합 실행기에서 가져온 기존 B 테스트 클래스 4개가 중복 수집되어, 모듈 단위 import로 정정하고 전체를 다시 실행했다. 위 집계와 로그는 정정 후 실행 결과다.

## 통합 확인 사항

- **v1.2 성공** — B의 SSH-01 판정에 합성 SSH 출력을 입력하고 D 보고서를 생성·저장·조회. 승인과 MOCK 조치 후 재진단한 D 보고서를 별도 인스턴스에서 재조회하고, E 실행 이력을 별도 저장소에 저장해 새 인스턴스에서 `execution_id`로 재조회. SSH-01의 `pass` 및 CVSS `not_applicable`, 별도 점수 평가 항목의 CVSS·근거 보존 확인.
- **롤백 후 재진단** — 최초·조치 후·롤백 후 `scan_id`가 모두 다름. `post_rollback_scan_id`로 D 보고서 조회 성공. E 이력에 `outcome=failed`, `final_security_status=vulnerable`, `final_security_verified=true` 기록. `true`는 취약 상태까지 확인했다는 뜻.
- **롤백 후 재진단 생략** — 복구 자체를 확인했어도 `post_rollback_scan_id=null`, `final_security_status=null`, `final_security_verified=false` 유지. 회귀에서는 D 저장 후 재조회 실패 시에도 발급된 ID를 유지하고 성공으로 처리하지 않는 경로까지 확인.
- **v1.1 호환** — 기존 MOCK 재진단 경로 사용. D 진단과 E 실행 이력의 별도 저장·조회 및 기존 `severity` 유지 확인. v1.2용 재진단 어댑터는 이 경로에 사용하지 않았다.

실제 SSH·서버 변경, 운영 환경 E2E, 공통 SSH 계층 최종 계약은 미검증. 이번 로컬 D 저장·조회 경로를 검증하는 데 추가 D 담당자 협의는 필요하지 않았다. 운영 실행에서의 호출 주체와 이력 보존 정책은 별도 확인 대상이다.

## 재현

아래 명령은 PowerShell에서 **별도 임시 복제본**으로 실행한다. `$evidence`에는 이 문서와 두 Python 스크립트가 있는 폴더의 절대경로를 지정한다. 이미 결과가 들어 있는 폴더에 실행하면 그 폴더의 로그와 `results.json`이 갱신된다.

```powershell
$verify = Join-Path ([IO.Path]::GetTempPath()) ("secureops-verify-" + [guid]::NewGuid())
git clone --no-checkout https://github.com/YJH-secure/SecureOps.git $verify
Set-Location $verify
git fetch --no-tags origin refs/heads/main refs/pull/23/head
git switch --detach b0ef73a1613ebc40fdd596edcbaf0413d32309b8
git -c user.name=Verification -c user.email=verification@example.invalid -c core.hooksPath=NUL merge --no-ff --no-commit 62d1bf72ef52c7455bc0c2dd624206eb8350f925
git write-tree
python -m pip install "jsonschema[format]==4.26.0"
python -B (Join-Path $evidence "run_verification.py")
```
