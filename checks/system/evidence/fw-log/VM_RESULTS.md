# FW-01·LOG-01 읽기 전용 VM 검증 근거

이 문서는 사용자가 공유한 VM 출력과 이전 검증 기록을 요약한다.
실행 계정, 호스트명, 내부 주소와 전체 설정 원문은 포함하지 않았다.

| 환경·권한 | 확인한 FW 관측값 | 진단 상태 |
| --- | --- | --- |
| Ubuntu 24.04, 일반 계정 | UFW 및 nftables 조회 권한 부족 | error |
| Ubuntu 24.04, 관리자 로컬 조회 | UFW inactive, nftables 규칙 0개, 조회 오류 0건 | needs_review |
| Rocky Linux 9.8, 일반 계정 초기 조회 | firewalld 서비스 정의 조회 실패 및 nftables 권한 부족 | error |
| Rocky Linux 9.8, 관리자 로컬 조회 | firewalld running, nftables 규칙 103개, public 존의 cockpit·dhcpv6-client·ssh 서비스, 조회 오류 0건 | needs_review |

후속 Rocky 실행에서는 firewalld 상태 조회 타임아웃과 nftables 권한 부족이
기록됐다. 이후 수동으로 실행한 `timeout 15s firewall-cmd --state`는
`running`, 종료 코드 0을 반환했다.

Rocky TCP 21은 수신 소켓이 있었지만 수집된 비교 범위에서 허용 규칙 참조가
없었다. TCP 22는 SSH 서비스와 nftables accept 참조가 있었다.
참조 유무만으로 실제 접근 가능성·차단 여부를 확정하지 않는다.

Ubuntu의 LOG-01 초기 v1.1 조회 결과는 needs_review, 조회 오류 0건이었다.
systemd-journald.service, rsyslog.service, logrotate.timer는 active였다.
후속 Ubuntu·Rocky VM의 v1.2 출력 검증에서도 LOG-01의 진단 상태는
needs_review였다. 후속 실행은 기존 진단 결과를 v1.2로 내보낸 것이며,
이 PR의 FW·LOG CLI는 기본 JSON v1.1을 제공한다.

## 재현 명령

저장소 루트에서 해당 환경에 설치된 Python으로 실행한다.

```bash
python3 -m checks.system.firewall_check > fw01-result.json
python3 -m checks.system.log_check > log01-result.json
python3 -m unittest discover -s checks/system/tests -v
```

각 결과는 check_id, status, severity, evidence, recommendation을 포함하며,
구조화된 관측값과 오류는 details에 보존한다. 유효한 진단 JSON이 생성되면
진단 상태 error도 프로그램 종료 코드 0으로 전달한다.

## 후속 검증

운영 정책 승인, 중앙 진단 계정 권한, 실제 원격 실행·D 실서버 통합, 방화벽의
실제 접근 범위, 인증 이벤트 기록 여부와 로그 보관·순환 이력은 후속 범위다.
이번 제출 과정에서 VM을 다시 접속하거나 시스템 파일·권한·서비스·규칙을
변경하지 않았다. 기존 VM 근거와 공식 제출 커밋 기준 로컬 테스트를 함께 제공한다.
