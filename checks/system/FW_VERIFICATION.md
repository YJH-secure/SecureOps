# FW-01 검증과 중앙 진단 계정 권한 검토

## 검증 결과

| 환경 | 실행 권한 | 관측값 | 진단 결과 |
|---|---|---|---|
| Rocky 9.8 | VM 일반 계정 | firewalld 서비스 정의 `cockpit`, `dhcpv6-client`, `ssh` 조회가 코드 253으로 거부됐습니다. nftables 조회도 권한 부족이었습니다. | `error` |
| Rocky 9.8 | VM 관리자 권한 | firewalld 실행 중, nftables 런타임 규칙 103개. `public` 존에 `cockpit`, `dhcpv6-client`, `ssh` 서비스가 등록돼 있습니다. 조회 오류 0건입니다. | `needs_review` |
| Ubuntu 24.04 | VM 관리자 권한 | UFW 비활성, 조회한 nftables 런타임 규칙 0개, 수신 소켓 10개. 조회 오류 0건입니다. | `needs_review` |

Rocky TCP 21은 `0.0.0.0`에서 수신하며 확인한 범위에서 규칙 참조가 없었습니다. TCP 22는 `0.0.0.0` 및 `::`에서 수신하며 `public` 존의 `ssh` 서비스와 nftables의 `accept` 참조가 있었습니다. 프로토콜·포트 기준 비교 결과입니다. 실제 차단 여부, 허용 출발지, IPv4/IPv6별 도달성은 A의 자산·망 정책과 접속 검증을 통해 확인합니다. Ubuntu도 별도 방화벽 경로 및 네트워크 정책을 확인할 때까지 `needs_review`입니다.

위 실측은 사용자가 각 VM에서 제공한 실행 결과와 요약 출력에 근거합니다. 중앙 진단 계정의 원격 실행 결과는 별도 검증 대상입니다. 로컬 Windows Python 3.12.14에서 FW-01 테스트 17개, C 전체 143개가 통과했고 `needs_review`와 `error`의 JSON v1.1 형식을 확인했습니다.

```bash
python3 -m unittest checks.system.tests.test_firewall_check -v
python3 -m unittest discover -s checks/system/tests
```

실습 VM에서 사용한 실행 명령입니다. 관리자 실행은 로컬 수집 검증용이며, 중앙 진단 계정은 필요한 조회 명령에 한해 권한을 적용합니다.

```bash
python3 -m checks.system.firewall_check > fw01-result.json
# Rocky 관리자 재검증
sudo python3 -m checks.system.firewall_check > fw01-rocky-privileged-result.json
# Ubuntu 관리자 검증
sudo python3 -m checks.system.firewall_check > fw01-ubuntu-result.json
```

## `secureops-scan` 권한 후보

[A 인프라 문서 `373c58c`의 sudoers 초안 v0](https://github.com/YJH-secure/SecureOps/blob/373c58cbf489c64d742a44acc5388213e7eb08bd/infrastructure/README.md#L239)과 현재 FW-01 호출을 대조했습니다. 아래 표는 승인 검토용입니다. 명령 경로는 대상 VM에서 확인합니다. [sudoers 인자 매칭 문서](https://manpages.ubuntu.com/manpages/noble/man5/sudoers.5.html)

| 대상·조회 | 초안 v0 | 현재 코드·검토 사항 |
|---|---|---|
| 공통 nftables | `/usr/sbin/nft list ruleset` | `/usr/sbin/nft -j list ruleset` 필요. `-j`가 추가돼 다른 인자 조합입니다. Rocky 일반 계정에서는 조회 거부를 관측했습니다. |
| Ubuntu UFW | `/usr/sbin/ufw status verbose` | 기존 명령을 사용합니다. 대상의 `secureops-scan` 계정으로 허용 여부를 확인합니다. |
| Rocky 상태 | `/usr/bin/firewall-cmd --state`, `--list-all` | 현재 `--state`를 사용합니다. `--list-all`은 아래 개별 조회 명령과 별개입니다. |
| Rocky 존 | 해당 명령 기재 없음 | `firewall-cmd --get-active-zones`, `--get-default-zone`, `--info-zone=public`을 호출합니다. Rocky 실습 VM 일반 계정에서 해당 단계의 오류는 보고되지 않았습니다. `secureops-scan`으로 확인 후 권한이 필요한 인자만 검토합니다. `public`은 이 VM에서 관측한 존입니다. |
| Rocky 서비스 | 해당 명령 기재 없음 | `firewall-cmd --info-service=cockpit`, `--info-service=dhcpv6-client`, `--info-service=ssh`가 이번 실측의 추가 후보입니다. 존이나 서비스가 바뀌면 A의 승인 대상 목록과 대조합니다. |
| 공통 수신 소켓 | `ss -lntup` | FW-01은 `ss -H -lntup`을 일반 권한으로 실행하며 소켓의 프로토콜·주소·포트를 사용합니다. 기존 실습 일반 계정에서 소켓 단계 오류는 없었습니다. `secureops-scan`으로 일반 실행을 확인한 뒤 필요성을 판단합니다. |

권한 추가가 필요한 경우 실행 파일 경로와 읽기 전용 인자 전체를 승인된 값으로 지정합니다. 동적 존·서비스를 지원해야 하면 A·팀장과 승인 목록을 고정하거나 관리자가 소유한 입력 검증형 조회 도구를 협의합니다. 전체 Python 실행 권한이나 가변 인자를 포괄하는 와일드카드 허용은 후보에서 제외합니다.

## 실제 연동 확인 순서

1. 대상 VM에서 `secureops-scan`의 `sudo -n -l`과 일반 권한 조회 결과를 확인합니다. 현재 인프라 문서와 실제 적용 권한을 대조합니다.
2. 팀장 승인 후 권한이 필요한 개별 조회 명령을 해당 계정으로 검증합니다. 예를 들어 승인된 대상에서 `sudo -n /usr/sbin/nft -j list ruleset`을 조회합니다. 경로와 인자가 승인 항목과 일치하는지 확인합니다.
3. 중앙 실행 계층에서 필요한 명령만 승인된 경로로 호출하도록 연동합니다. FW-01의 현재 기본 실행기는 명령을 직접 실행합니다. `sudo -n`을 이용한 운영 실행 경로, 실제 SSH 전송, D 집계 및 승인 정책 적용은 후속 검증입니다.
