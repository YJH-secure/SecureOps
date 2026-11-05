# SecureOps 공통 SSH 원격 수집 모듈 설계 v0.1 (구현 초안)

- 담당: 양지혁 / 경로: `common/ssh_client.py`
- 작성: 2026-11-05
- 상태: **로컬 테스트 대상 프로토타입**. 실제 Ubuntu/Rocky 연결·권한 검증 완료 아님
- 참고: [아키텍처](system-architecture.md), [결과 계약](json-result-contract-v1.md)

## 1. 목적과 역할 분리

중앙 관리 서버의 하나의 SSH 수집 인터페이스를 계정·시스템 진단 코드에서 공유한다.

- **양지혁**: SSH 접속·호스트 키 검증·정보 수집·실패 처리 등 공통 전송 계층
- **김민우**: 대상 VM, SSH 계정·방화벽·네트워크·최소 권한 설정 및 연결 검증 지원
- **최종욱**: 계정/SSH 점검 정책·판정 코드 (`checks/account/`); 접속 함수 중복 구현 지양
- **김서후**: 파일/서비스/방화벽/로그 정책·판정 코드 (`checks/system/`)
- **조효민**: 두 진단 모듈의 표준 결과 객체 검증·집계
- **박태준**: 승인·백업·조치·재진단 (진단용 읽기 전용 인터페이스와 별도 권한)

## 2. 목표 인터페이스

```python
from common.ssh_client import run_readonly, SSHCollectionError

try:
    collected = run_readonly(
        target_id="ubuntu-a",
        host="192.168.10.20",
        username="secureops-scan",
        operation="os_kernel",
    )
    print(collected["stdout"])
except SSHCollectionError:
    # 개별 진단 모듈에서는 상황에 맞게 status="error"로 변환
    print("SSH 원격 정보 수집 실패")
```

**반환 예시:** `{"target_id": "ubuntu-a", "operation": "os_kernel", "stdout": "Linux", "exit_code": 0}`

이 반환 데이터는 **수집 데이터**이지 공통 **진단 결과 JSON**이 아니다. 담당 검사 모듈이 정책 `criteria`에 따라 판정하고 `check_id/status/severity/evidence`를 반환해야 한다.

## 3. 초기 허용 작업(프로토타입)

| `operation` | 원격 실행 작업 | 목적 |
| --- | --- | --- |
| `os_kernel` | `uname -s` | 커널 종류 수집 |
| `os_release` | `cat /etc/os-release` | OS 배포판 정보 수집 |
| `current_user` | `id -un` | 접속 계정 확인 |
| `passwd_metadata` | `stat -c '%a %U %G' /etc/passwd` | 파일 권한·소유자 정보 읽기 |

- 개발 초기에는 임의 명령 문자열을 입력받지 않고 위에 **명시된 읽기 전용 작업**만 허용한다. 추후 검사 요구에 맞춰 작업 목록과 인자 검증을 확대한다.
- Python 표준 라이브러리 `subprocess`로 시스템의 OpenSSH 클라이언트를 호출한다. Python 제3자 SSH 라이브러리 설치는 필수가 아니다.
- SSH 클라이언트 실행 명령에 셸 인터프리터를 사용하지 않고 인자 리스트를 전달한다.
- `BatchMode=yes`: 비대화형 인증, `StrictHostKeyChecking=yes`: 이미 신뢰한 호스트 키만 허용, `ConnectTimeout`: 연결 제한 시간.
- SSH 계정 인증은 관리 서버의 기존 키 또는 SSH agent를 이용한다. 코드나 GitHub에 비밀번호·개인키를 기록하지 않는다.
- 최초 호스트 키 등록 시 관리자가 별도 신뢰 경로로 지문을 확인해야 한다. 검증 없이 호스트 키 검사 옵션을 끄지 않는다.
- 소스의 명령 허용목록은 안전장치 중 하나이며, **실제 최소 권한은 서버의 계정 권한 및 명령 접근 통제에서도 별도로 강제**해야 한다.
- OpenSSH 옵션이나 원격 환경에 따라 연결 테스트가 필요하다. 구현만으로 접속 성공을 보장하지 않는다.

## 4. 오류 처리와 로그

- 호출자가 전달한 대상·작업명이 부적절하면 `ValueError` 발생
- SSH 실행 불가·타임아웃·원격 오류는 `SSHCollectionError` 발생
- 인증 실패·호스트 키 불일치·명령 권한 거부 등의 원인은 진단 실패로 취급하며 `pass`나 `vulnerable`로 추정하지 않는다.
- 프로토타입은 SSH stderr 원문을 출력하지 않아 비밀 정보가 진단 JSON으로 유입되는 위험을 줄인다. 추후 원인별 오류 코드 추가 검토.
- 실패 사실이 실제 점검의 `status="error"`에 반영되도록 종욱·서후 모듈과 연결 테스트해야 한다.

## 5. 테스트 계획

```bash
python -m unittest discover -s tests -p 'test_ssh_client.py'
```

1. **Mock 단위 테스트**: 정상 명령 반환, 미허용 작업 차단, 부적절한 대상 입력 차단, SSH 종료 코드 실패 처리.
2. **민우 담당 서버 연동 테스트**: 관리 서버 → Ubuntu 대상(`192.168.10.20`) SSH 인증, 호스트 키 검증, 허용된 수집 작업 실행.
3. **공통 모듈 연동**: 종욱 SSH-01 및 서후 FILE-01 진단 코드가 공통 함수를 재사용하고 규격에 맞는 결과를 반환하는지 확인.
4. **Rocky 확장 테스트**: OS별 출력, 파일 경로, 권한 등 차이 확인.
5. **조치와 분리**: 진단 계정에서는 보안 설정 변경 권한이 없어야 하며, 별도 승인 기반 조치 인터페이스로만 변경하도록 검증.

## 6. 현재 범위와 미완료 사항

- [x] Python 프로토타입 및 Mock 테스트 코드 작성
- [ ] Mock 단위 테스트 실행 성공 확인
- [ ] 실제 Ubuntu 관리 서버에서 OpenSSH 동작 확인
- [ ] 김민우의 최소 권한·SSH 접속 검증
- [ ] 종욱·서후와 operation별 인터페이스 협의
- [ ] 실제 두 진단 모듈 연동 및 오류 처리 통합 검증
- [ ] 정책 버전·호스트 신뢰 정보·대상 자산 식별자 관리 방식 확정

**주의:** 정책 JSON에 임의 셸 명령을 두고 실행하는 설계, 원격 수정 명령 실행, SSH 호스트 키 검증 해제 등은 이 단계의 범위에서 제외한다.
