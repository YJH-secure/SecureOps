# C 모듈 — FILE-01 v6.2（팀장 요청 1~4 재검토）

팀 공통 결과 계약 v1.1에 맞춘 읽기 전용 파일 소유자·권한 진단입니다.
저장소 루트 README, docs/architecture, tests/fixtures는 팀 main 원본을 유지합니다.

## 실행

아래 명령은 저장소 루트에서 실행합니다.

```bash
python3 -m unittest discover -s checks/system/tests -v
python3 -m checks.system.file_check
```

Linux VM 통합 검증은 아래 명령으로 실행합니다.

```bash
bash checks/system/verify_vm.sh
```

검증 전 도구 설치가 필요하면 운영체제에 맞춰 실행합니다.

```bash
# Ubuntu
sudo apt update
sudo apt install acl python3-venv
# Rocky
sudo dnf install acl python3-pip
```

실행기는 저장소 루트의 .venv를 사용합니다. 검증용 jsonschema 의존성은
checks/system/requirements-dev.txt를 사용하며, 진단 코드 자체는 표준 라이브러리 기반입니다.
main의 docs/architecture/json-result-schema-v1.1.schema.json 및
tests/fixtures/sample-result-v1.1-MOCK.json을 검증에 사용합니다.

## 구현과 제한

- FILE-01: /etc/passwd 및 /etc/shadow 메타데이터 수집, 정책 로딩, OS별 선택,
  허용 권한 비트 검사, ACL 유효 권한 계산, 제한된 읽기 전용 링크 대상 검사.
- 결과 필수 5필드: check_id/status/severity/evidence/recommendation.
  상세 증거는 details에 보존합니다.
- shadow 후보 정책, passwd 그룹, 확장 ACL 접근 승인, 링크 대상 승인은 최종 확정 대기입니다.
  명시적 승인이 없는 항목은 needs_review를 유지합니다.
- 승인된 합성 정책으로 ACL·링크 pass/vulnerable/error 동작을 테스트하는 것과
  실제 운영 정책 승인은 별개입니다. 조회 오류는 error로 남깁니다.
- SSH 연결·인증은 팀장 공통 모듈 담당, 최상위 JSON 집계는 D 담당입니다.
  D 브랜치에 Rocky 결과를 전달하는 로컬 호환성 검증을 통과했습니다.
  공통 SSH 원격 수집과 자동 조치 통합 검증은 대기입니다.
- 시스템 파일 내용이나 비밀번호 해시는 수집하지 않고 설정을 변경하지 않습니다.

## 검증 기록

TEAM_REQUEST_REVIEW.md, POLICY_REVIEW_DRAFT.md, VM_EVIDENCE_GUIDE.md와 TEST_RESULTS.md를 참고하세요.
새 수정은 이름 shadow 부재와 필수 조회 실패를 구분하며 로컬 단위 테스트는 105개입니다.
Ubuntu 24.04.5와 Rocky 9.8에서 각각 105개, 임시 시나리오 13개, JSON 결과 14개를 검증했습니다.
VM 검증은 사용자가 실행해 전달한 로그를 근거로 기록했습니다.
기존 네 오류 수정과 진단 결과 JSON 규격은 유지했습니다.

검증 로그는 루트 verification-runs/에 저장됩니다. .venv, 캐시, 생성 결과, ZIP은
업로드 대상이 아닙니다. 팀 공통 .gitignore는 수정하지 않았으며 필요하면
로컬 .git/info/exclude에 생성 경로를 등록하거나 업로드 파일을 명시적으로 선택하세요.
실제 결과 JSON은 환경정보 포함 여부를 검토한 뒤 공유하세요.
