# SVC-01 서비스 진단

Ubuntu·Rocky 같은 systemd 환경에서 활성 `.service` 유닛, 유닛 파일 활성화 상태, 현재 네트워크 네임스페이스의 TCP·UDP 수신 소켓을 조회합니다. `systemctl list-units`, `systemctl list-unit-files`, `ss -lntup`을 읽기 전용으로 실행합니다. 위험도는 팀 기준표의 `medium`입니다.

저장소 루트에서 실행합니다.

```bash
python3 -m checks.system.service_check
python3 -m unittest checks.system.tests.test_service_check -v
```

`systemctl`과 `ss`가 동작하는 VM에서 실행합니다. 공통 JSON v1.1의 필수 5필드와 `details`를 갖는 개별 점검 결과를 표준 출력에 기록합니다. `details`에는 대상, 전체 인벤토리, 명시적 위반, 검토 사유 및 조회 오류가 들어갑니다.

진단 결과 JSON을 정상 출력하면 `status: error`를 포함해 종료 코드 `0`을 반환합니다. 진단 판정은 JSON의 `status`에서 확인합니다. 잘못된 실행 인자나 JSON 출력을 완료할 수 없는 프로그램 오류는 비정상 종료로 전달됩니다. D의 원격 결과 파서는 정상 종료된 JSON을 검증한 뒤 `error`와 `needs_review`를 각각 집계합니다.

## 정책 적용

배포 정책 `policies/service_policy.json`의 `policies` 배열은 비어 있습니다. 조회가 성공하면 `needs_review`, 필수 조회나 파싱이 실패하면 `error`를 반환합니다. MariaDB, FTP, DNS를 포함한 실제 서비스 허용 여부는 대상별 운영 담당자와 팀장 승인을 근거로 작성합니다.

OS ID와 버전은 진단 대상의 `/etc/os-release`에서 읽습니다. 실행 계층은 `--target-id`, `--role`, `--network-context`를 전달합니다. OS·버전·역할·망 환경이 정확히 일치하는 프로필을 사용합니다. 자산 정보가 빠졌거나 일치하는 승인 프로필이 없으면 `needs_review`로 기록합니다. OS 조회 실패는 `error`입니다. VMware NAT와 GNS3 프로필은 각각 작성합니다.

아래는 **테스트용 예시**입니다. 실환경 목록은 A의 자산·서비스 구성표와 팀장 승인 근거를 받아 별도로 작성합니다.

```json
{
  "policy_version": "mock-example",
  "policies": [
    {
      "check_id": "SVC-01",
      "description": "테스트용 승인 목록",
      "severity": "medium",
      "criteria": {
        "profiles": [
          {
            "os_id": "rocky",
            "os_version": "9.8",
            "role": "service-mock",
            "network_context": "vmware-nat",
            "approval_status": "approved",
            "unit_rules": {"example.service": "required"},
            "listener_rules": [
              {
                "protocol": "tcp",
                "port": 8080,
                "allowed_addresses": ["127.0.0.1"],
                "deny_unlisted_bindings": false
              }
            ]
          }
        ]
      }
    }
  ]
}
```

```bash
python3 -m checks.system.service_check --policy /path/to/approved-service-policy.json \
  --target-id rocky-mock --role service-mock --network-context vmware-nat
```

전체 활성 유닛은 기록하고, `unit_rules`에 명시한 유닛에만 `allowed`, `required`, `forbidden`을 적용합니다. `required`는 활성 상태를 요구하고, `forbidden`은 활성 상태를 금지합니다. `enabled`는 인벤토리 정보로 남깁니다.

소켓 규칙은 프로토콜·포트별로 적용합니다. 주소는 관측값과 정확히 대조합니다. `127.0.0.1`, `0.0.0.0`, `::`, `*`는 별개입니다. 규칙이 없거나 주소 승인이 불명확하면 `needs_review`입니다. 해당 포트에 승인된 `deny_unlisted_bindings: true`가 있고 관측 주소가 목록에 없을 때만 명시적 바인딩 위반으로 `vulnerable`을 반환합니다. 승인된 외부 바인딩도 원격 접근 범위 확인을 위해 `needs_review`로 남깁니다. 실제 접근은 적용 방화벽 정책과 허용·차단 접속 검증을 대조해야 합니다.

`ss`가 프로세스 이름을 제공하면 소켓의 `process_names`에 참고 정보로 보존합니다. 프로세스 이름과 systemd 유닛의 정확한 연결은 별도 증거가 필요합니다. 확인된 위반이 다른 조회 오류와 함께 발생하면 두 근거를 보존합니다. 공통 SSH 원격 실행과 D의 실제 집계·저장은 통합 테스트에서 검증합니다.

명령 문서: [systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html), [ss](https://man7.org/linux/man-pages/man8/ss.8.html).
