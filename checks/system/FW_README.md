# FW-01 호스트 방화벽 초기 조회

Ubuntu와 Rocky에서 OS, 방화벽 관리 도구의 상태, 커널 nftables 런타임 규칙 요약, TCP·UDP 수신 소켓을 읽기 전용으로 수집합니다. 위험도는 팀 기준표의 `high`입니다. 공통 JSON v1.1 개별 결과를 표준 출력에 기록합니다.

```bash
python3 -m checks.system.firewall_check > fw01-result.json
python3 -m unittest checks.system.tests.test_firewall_check -v
```

Ubuntu에서는 `ufw status verbose`에서 상태, 기본 정책, 관리 규칙의 방향·대상·출발지·동작을 조회합니다. Rocky에서는 `firewall-cmd --state`로 실행 상태를 확인합니다. 실행 중이면 활성 및 기본 존의 인터페이스, 출발지, 서비스, 포트, rich rule과 서비스 정의의 포트를 조회합니다.

커널 조회는 `nft -j list ruleset`을 사용합니다. 테이블·체인·규칙 수, 베이스 체인의 훅·우선순위·기본 정책, 규칙에서 확인한 단순 주소·포트 조건과 동작을 기록합니다. 집합·간접 규칙 등 추가 분석이 필요한 표현은 별도 집계합니다. 결과에는 실습망 주소와 방화벽 설정 정보가 들어갈 수 있으므로 공유용 사본은 민감정보를 검토합니다.

수신 소켓은 SVC-01과 같은 `ss -H -lntup` 파서를 사용합니다. `details.listener_comparison`은 관측 소켓과 방화벽 설정에서 확인한 프로토콜·포트가 같은 경우, 그리고 포트 설정에 대응하는 수신 소켓이 관측되지 않은 경우를 보여줍니다. 이 비교는 주소 범위·존·규칙 순서·간접 체인까지 평가하지 않습니다. 허용과 차단 참조가 함께 나타날 수 있으며, 참조가 없다는 결과에도 실제 도달성 판단은 포함되지 않습니다.

- 운영 정책이 승인되기 전에는 정상 수집 결과를 `needs_review`로 남깁니다. 기존 배포 정책은 빈 목록입니다.
- 권한 부족, 필수 명령 누락, 파싱 실패는 `error`입니다. 조회 가능한 근거는 계속 남깁니다. UFW 또는 firewalld 도구가 설치되지 않은 경우에는 그 상태를 기록하고 커널 조회를 계속합니다.
- firewalld의 비실행 상태와 UFW의 비활성 상태는 관측값입니다. 방화벽 전체의 비활성 여부는 별도 근거를 확인합니다.
- 유효한 진단 JSON을 출력하면 `status: error`도 종료 코드 `0`을 반환합니다. 인자 오류나 출력 실패는 프로그램의 비정상 종료로 전달됩니다.

VM에서 `error`가 나오면 `details.errors`의 조회 단계와 사유를 확인합니다. 읽기 권한이 필요한 경우 팀의 진단 계정 권한을 먼저 확인합니다.

이 초기 구현은 nftables 규칙 식, iptables-legacy 규칙, 재부팅 후 지속 여부 또는 원격 도달성을 판정하지 않습니다. 승인된 자산·IPv4/IPv6 출발지·포트와 적용 규칙을 대조하고 허용/차단 접속 검증을 하는 작업은 별도입니다.

참고 문서: [UFW](https://manpages.ubuntu.com/manpages/noble/man8/ufw.8.html), [firewall-cmd](https://firewalld.org/documentation/man-pages/firewall-cmd.html), [nftables JSON](https://manpages.debian.org/bookworm/libnftables1/libnftables-json.5.en.html).
