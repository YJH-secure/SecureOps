# SecureOps 진단 실행 환경 인수인계 (2026-11-11)

**작성:** 김민우 (A · 서버·네트워크 인프라)  
**대상:** 팀장(통합), B·C·D 담당  
**기준:** 2026-11-11에 재구축한 VM 3대에서 **실제로 검증한 값만** 적었다. 검증하지 않은 항목은 "미확인"으로 표시한다.  
**관련 문서:** [인프라 README](README.md) (구성·구축 절차·증거), [JSON 결과 계약 v1.2](../docs/architecture/json-result-contract-v1.2.md)

> 이 문서는 접속 정보와 실행 환경만 제공한다. 공통 SSH 모듈(`common/ssh_client.py`)과 원격 실행 인터페이스는 팀장 담당이며, 여기서 구현하지 않는다.  
> 비밀번호, 개인키 내용, 토큰은 이 문서와 저장소에 넣지 않는다. 아래 키 정보는 공개해도 되는 **지문(fingerprint)**뿐이다.

## 1. 대상 인벤토리

| `target_id` | JSON `os` 값 | 호스트명 | OS (실측) | 커널 | IP | 역할 |
| --- | --- | --- | --- | --- | --- | --- |
| `central-mgmt` | `ubuntu-24.04` | central-management-ubuntu | Ubuntu 24.04.5 LTS Server | 6.8.0-149-generic | `192.168.10.10` | 중앙 관리: 진단 실행, 결과 수집·집계 |
| `ubuntu-a` | `ubuntu-24.04` | Target-Ubuntu | Ubuntu 24.04.5 LTS Desktop | 7.0.0-42-generic | `192.168.10.20` | 진단 대상 A |
| `rocky-b` | `rocky-9.8` | Target-Rocky | Rocky Linux 9.8 (Blue Onyx) Desktop | 5.14.0-687.66.1.el9_8.x86_64 | `192.168.10.30` | 진단 대상 B |

- `os` 값은 JSON v1.2 계약의 예시 형식(`ubuntu-24.04`, `rocky-9.8`)을 따랐다.
- `central-mgmt` 호스트명은 소문자로 설정되어 있다. 팀장 결정으로 현재 값을 유지한다.
- `central-mgmt` 커널은 2026-11-11 오전 6.8.0-139에서 6.8.0-149로 업데이트되었다(README 2장). 진단 결과에는 실행 시점의 `uname -r` 값을 쓴다.
- 네트워크: VMware VMnet8(NAT) 단일 구성, `192.168.10.0/24`, 게이트웨이·DNS `192.168.10.2`. 외부에서 VM으로 직접 들어오는 경로는 없다.
- 결과 JSON의 `ip_address`는 저장소 안(비공개)에서만 쓴다. 발표 자료 등 외부에 공개하는 사본에서는 계약 문서에 따라 지운다.

## 2. SSH 접속 방법 (`central-mgmt`의 `user1`)

### 2-1. 접속 별칭 (`~/.ssh/config`, 2026-11-11 `ssh -G`로 확인)

| 별칭 | 접속 계정 | 대상 IP | 포트 | 키 | 용도 |
| --- | --- | --- | --- | --- | --- |
| `ubuntu-a` | `secureops-scan` | `192.168.10.20` | 22 | `~/.ssh/id_ed25519_scan` | 진단 (읽기 전용) |
| `rocky-b` | `secureops-scan` | `192.168.10.30` | 22 | `~/.ssh/id_ed25519_scan` | 진단 (읽기 전용) |
| `ubuntu-a-fix` | `secureops-fix` | `192.168.10.20` | 22 | `~/.ssh/id_ed25519_fix` | 조치 (승인 후에만 사용) |
| `rocky-b-fix` | `secureops-fix` | `192.168.10.30` | 22 | `~/.ssh/id_ed25519_fix` | 조치 (승인 후에만 사용) |

네 별칭 모두 `IdentitiesOnly yes`이다.

### 2-2. 키 정보 (지문만 기재)

| 키 | 형식 | 지문 | passphrase |
| --- | --- | --- | --- |
| `id_ed25519_scan` | ED25519 256 | `SHA256:AUX6A1uvoK+vK+ocZl5nyDHxg/7ZFhErHLccznbF+NA` | 없음 (자동 진단용) |
| `id_ed25519_fix` | ED25519 256 | `SHA256:///ZMLW94cbqZaT4VsEYTTPdB154gp4O7fpzNhn+nq0` | 없음 (자동 진단용) |

- 키 파일 권한: 개인키 `600`, 공개키 `644`, `~/.ssh`는 `700`이다(2026-11-11 확인).
- 개인키는 `central-mgmt` 밖으로 복사하지 않는다. passphrase가 없으므로 **`central-mgmt` VM과 그 백업 전체를 민감정보로 취급**한다.
- 재구축으로 호스트 키가 바뀌었다. 다른 PC에서 접속하던 사람은 `ssh-keygen -R <IP>`로 이전 항목을 지운다(README 5-5).

### 2-3. 검증된 접속 결과 (2026-11-11)

| 확인 | 결과 | 증거 |
| --- | --- | --- |
| 키 직접 접속 4개 조합 (`BatchMode=yes`) | 모두 비밀번호 없이 성공, `whoami`·`hostname` 일치 | `evidence/central-mgmt/central-mgmt-sshkey-261111.png` |
| 별칭 접속 4개 | 모두 성공 | `central-mgmt-ssh-alias-261111.png` |
| sudo 허용·차단 | scan `sshd -T` 허용 / scan `cat /etc/shadow` 차단 / fix `id` 차단 / fix `sshd -t` 허용 | `central-mgmt-sudo-test-261111.png` |
| 진단 계정 읽기 권한 | 4-1 표와 같음 | `central-mgmt-scan-read-test-261111.png` |

### 2-4. SSH 출발지 IP와 실제 인증 키 (2026-11-12 09:20 확인)

`central-mgmt`의 `user1`에서 조회만 했다. 대상 쪽 로그는 sudoers v0에 이미 허용된 `tail -n 200` 명령으로 읽었다.

| 별칭 | 접속 계정 | 대상 호스트명 | 출발지 (`SSH_CONNECTION` 1번째 값) | 접속 주소 (3번째 값) |
| --- | --- | --- | --- | --- |
| `ubuntu-a` | `secureops-scan` | Target-Ubuntu | `192.168.10.10` | `192.168.10.20` |
| `rocky-b` | `secureops-scan` | Target-Rocky | `192.168.10.10` | `192.168.10.30` |
| `ubuntu-a-fix` | `secureops-fix` | Target-Ubuntu | `192.168.10.10` | `192.168.10.20` |
| `rocky-b-fix` | `secureops-fix` | Target-Rocky | `192.168.10.10` | `192.168.10.30` |

| 대상 로그 | `Accepted publickey` 기록 (09:20 접속분) | 2-2 지문과 일치 |
| --- | --- | --- |
| `ubuntu-a` `/var/log/auth.log` | `secureops-scan` from `192.168.10.10` ED25519 `SHA256:AUX6A1uv…`, `secureops-fix` from `192.168.10.10` ED25519 `SHA256:///ZMLW9…` | 일치 |
| `rocky-b` `/var/log/secure` | 위와 같음 | 일치 |

- `central-mgmt`에서 `ssh-keygen -lf`로 확인한 공개키 지문(scan·fix)도 2-2 표와 같다.
- 결론: 네 별칭 모두 `central-mgmt`(`192.168.10.10`)에서 출발하고, 대상 서버는 각 계정에 지정된 키(scan 키 / fix 키)로 인증했다. 다른 키나 비밀번호 인증 기록은 이번 조회 범위(최근 200줄)에 없었다.
- **로그 형식 차이 (LOG-01 참고):** Rocky 9.8의 인증 로그는 프로세스 이름이 `sshd`가 아니라 **`sshd-session[PID]`**로 기록된다. 시각도 Ubuntu는 ISO 8601(`2026-11-12T09:20:11.494728+09:00`), Rocky는 syslog 형식(`Nov 12 09:20:11`)이다. 로그를 파싱할 때 두 형식을 모두 고려해야 한다.
- 증거: `central-mgmt-ssh-source-261112.png` (출발지·지문), `central-mgmt-ssh-authlog-261112.png` (대상 로그)

```bash
# central-mgmt user1에서 실행 (조회만)
for h in ubuntu-a rocky-b ubuntu-a-fix rocky-b-fix; do echo "== $h"; ssh -o BatchMode=yes "$h" 'echo "user=$(whoami) host=$(hostname) client=${SSH_CONNECTION%% *} server=$(echo $SSH_CONNECTION | cut -d" " -f3)"'; done
ssh ubuntu-a 'sudo -n /usr/bin/tail -n 200 /var/log/auth.log' | grep 'Accepted publickey' | tail -n 4
ssh rocky-b 'sudo -n /usr/bin/tail -n 200 /var/log/secure' | grep 'Accepted publickey' | tail -n 4
```

### 2-5. 중앙 실행기 연동값과 SSH-01 평가 문맥 (2026-11-12 확인)

`ssh -G` 확인 결과 (`central-mgmt-ssh-g-261112.png`): 2-1 표와 같다. 키 지정(`IdentityFile`, `IdentitiesOnly yes`)은 **별칭에만** 걸려 있다.

| 확인 (`user1`로 각 대상 콘솔에서, 읽기 전용) | `ubuntu-a` | `rocky-b` |
| --- | --- | --- |
| `sshd` 경로 | `/usr/sbin/sshd` | `/usr/sbin/sshd` |
| `sshd -T`의 `usedns` | `no` | `no` |
| `Match` 블록 (`sshd_config`, `sshd_config.d/`) | 없음 (`Include sshd_config.d/*.conf`만 있음) | 없음 (`Include` → `50-redhat.conf` → crypto-policies `opensshserver.config`) |
| 전역 `permitrootlogin` | `without-password` | `without-password` |
| `sshd -T -C user=root,host=192.168.10.10,addr=192.168.10.10` | `without-password` | `without-password` |
| `/usr/local/sbin/secureops-ssh01-read` | 미설치 | 미설치 |
| `/etc/sudoers.d/` | `README`, `secureops-fix`, `secureops-scan` (SSH-01 전용 파일 없음) | `secureops-fix`, `secureops-scan` (`etc_t`, SSH-01 전용 파일 없음) |

- `UseDNS no`이면 sshd는 클라이언트 이름을 DNS로 찾지 않고, `Match Host`도 클라이언트 **IP 문자열**로 평가한다. 실제 출발지는 2-4의 `192.168.10.10`이다.
- Rocky의 crypto-policies 파일은 시스템이 만드는 암호 알고리즘 목록이라 이번 검색 범위에 넣지 않았다.
- 증거: `ubuntu-a-ssh01-context-261112.png`, `rocky-b-ssh01-context-261112.png`

**`targets.json` 권장값 (팀장 확정 대상, PR #26 `central_ssh01_runner.py` 기준)**

| 필드 | `ubuntu-a` | `rocky-b` |
| --- | --- | --- |
| `host` | `ubuntu-a` (별칭. IP를 넣으면 scan 키가 선택되지 않음) | `rocky-b` |
| `username` | `secureops-scan` | `secureops-scan` |
| `port` | 22 | 22 |
| `ssh01_context` | `user=root,host=192.168.10.10,addr=192.168.10.10` | 같음 |

- 수집기의 `ROOT_CONTEXT`와 `ssh01_context`는 글자까지 같아야 한다(다르면 실행기가 `context mismatch`로 거부).
- **PR #24 배포 안내 주의:** `deploy/ssh01/README.md`는 sudoers 예시를 `/etc/sudoers.d/secureops-scan`으로 설치하도록 되어 있다. 이 이름은 v0 scan 파일과 같아 그대로 설치하면 기존 허용 명령이 모두 사라진다. `/etc/sudoers.d/secureops-ssh01` 같은 별도 파일 사용을 제안했다(팀장 검토).

**원격 실행 시 권장**
- 비대화식 실행에는 `ssh -o BatchMode=yes <별칭> '<명령>'`을 쓴다. 키 문제가 생기면 비밀번호를 묻지 않고 바로 실패한다.
- sudo가 필요한 명령은 `sudo -n <전체 경로> <허용된 인자 그대로>`로 호출한다. `-n`이 없으면 허용되지 않은 명령에서 비밀번호 입력을 기다리며 멈출 수 있다.

## 3. 진단 실행 환경

### 3-1. `central-mgmt` (2026-11-11 16:01 확인)

| 항목 | 상태 | 비고 |
| --- | --- | --- |
| Python | 3.12.3 (`/usr/bin/python3`) | |
| `venv` 모듈 | import 가능 | 가상환경 생성 자체는 미확인. Ubuntu는 `python3.12-venv` 패키지가 없으면 생성이 실패할 수 있음 |
| `pip` | **없음** (`No module named pip`) | |
| `jsonschema` | 4.10.3 (시스템 패키지) | **`requirements-test.txt` 기준(`>=4.18,<5`) 미달**. V12SchemaTests 실행 전에 맞춰야 함 |
| Git | 2.43.0 | |
| OpenSSH 클라이언트 | 9.6p1 | |
| SecureOps 저장소 | **없음** (`~/SecureOps`, `~/secureops` 모두 없음) | |
| 루트 파일시스템 | 19G 중 6.9G 사용, 11G 여유 | VM 디스크는 40GB이지만 설치 기본값으로 LVM 루트에 19G만 할당됨 |
| 메모리 | 3.8Gi (사용 가능 3.3Gi), 스왑 3.8Gi | |

**실행 전 결정·준비가 필요한 것** (모두 아직 적용하지 않음)

1. **저장소를 `central-mgmt`에 받는 방법 (팀장 결정)**
   - 비공개 저장소라 인증이 필요하다.
   - 개인 토큰이나 개인 계정 키를 VM에 두지 않는 방식을 권장한다. 예: 이 저장소 전용 **읽기 전용 deploy key**, 또는 호스트 PC에서 받은 소스를 복사하는 방식.
   - 어떤 방식이든 인증 정보는 저장소와 문서에 남기지 않는다.
2. **Python 의존성**
   - 런타임 코어는 표준 라이브러리만 쓴다(`requirements-test.txt` 주석 기준).
   - 테스트용 `jsonschema>=4.18`이 필요하면 venv와 pip를 준비한다. 예: `sudo apt install python3.12-venv`, 그다음 `python3 -m venv` → `pip install -r requirements-test.txt`.
   - 패키지 설치는 VM 상태를 바꾸는 작업이므로, 하기 전에 `02-mgmt-ready` 스냅샷 계획(README 7장)과 함께 정한다.

### 3-2. 진단 대상

| 항목 | `ubuntu-a` | `rocky-b` |
| --- | --- | --- |
| Python (`secureops-scan`으로 확인) | 3.12.3 | **3.9.25** |
| SSH 서비스 이름 | `ssh` (소켓 활성화: unit file은 `disabled`이지만 `ssh.socket`으로 실행 중) | `sshd` |
| 방화벽 | `ufw` 비활성, nftables 규칙 없음 | `firewalld` 실행 중, `public` 존 |
| 보안 모듈 | AppArmor | SELinux |
| 인증 로그 | `/var/log/auth.log` | `/var/log/secure` |
| journal 저장 | `/var/log/journal` (영구) | `/run/log/journal`만 있음 (재부팅 시 사라짐) |
| VMware Tools | **설치되지 않음** (`vmrun` 게스트 명령 사용 불가) | `vmtoolsd` 실행 중 |

**Rocky Python 3.9 주의**
- 진단 코드를 대상 서버에서 Python으로 실행하는 방식을 택하면, Rocky에서는 3.10 이상 문법이 동작하지 않는다.
- 예: 클래스 정의에서 바로 평가되는 `str | None` 타입 표기, `match` 문.
- 현재 `main`의 `remediation/engine.py`에 `str | None` 필드가 있다. 다만 조치 엔진이 어디서 실행되는지는 팀장 인터페이스 확정 후 다시 확인한다.
- 대상 서버에서는 명령만 실행하고, 결과를 `central-mgmt`(3.12)에서 파싱하는 방식이면 이 문제는 없다.

## 4. OS별 명령 경로와 `secureops-scan` 권한

2026-11-11 14:34, `central-mgmt`에서 `secureops-scan`으로 실측했다. sudoers는 README 5-6의 **초안 v0**이며, 팀장 승인 없이 바꾸지 않는다.

### 4-1. 일반 권한으로 가능한 조회

| 확인 | `ubuntu-a` | `rocky-b` |
| --- | --- | --- |
| `/etc/passwd`, PAM 설정, `/etc/security/pwquality.conf` 읽기 | 가능 | 가능 |
| `/etc/ssh/sshd_config` 읽기 | 가능 | **불가** (sudo `cat` 허용) |
| `/etc/shadow` 읽기 | 불가 (허용하지 않음, 권한 확인은 `stat`) | 불가 |
| 인증 로그 읽기 | 불가 (sudo `tail -n 200` 허용) | 불가 (동일) |
| `ss -H -lntup` | 가능 (프로세스 정보 없음) | 가능 (동일) |
| `systemctl list-units` / `list-unit-files` / `show` | 가능 | 가능 |
| `systemd-analyze --no-pager cat-config systemd/journald.conf` | 가능 | 가능 |
| `journalctl --no-pager --disk-usage` | 실행됨. 단, 다른 사용자·시스템 journal은 보이지 않는다는 안내가 함께 출력되어 **전체 용량으로 확정할 수 없음** | **불가** (권한 부족) |
| `firewall-cmd --get-active-zones`, `--get-default-zone` | 해당 없음 | 가능 |
| `firewall-cmd --state`, `--list-all`, `--info-zone=…`, `--info-service=…` | 해당 없음 | **불가** (polkit `Authorization failed`) |
| `nft list ruleset` (`-j` 포함) | 불가 (root 필요) | 불가 |
| `ufw status verbose` | 불가 (root 필요) | 해당 없음 |
| `getfacl -n -p -P -- /etc/passwd /etc/shadow` (`/usr/bin/getfacl`) | **가능** (2026-11-12). 확장 ACL 없음, shadow `0:42 640` | **가능** (2026-11-12). 확장 ACL 없음, shadow `0:0 000` |
| `du -sh` journal 디렉터리 | **가능** — `/var/log/journal` 194M (2026-11-12, `journalctl --disk-usage`는 34.1M로 일부만 집계) | **불가** — 하위 디렉터리 `Permission denied`인데 `du`는 `0`을 출력함 (오류 시 0을 값으로 쓰면 안 됨) |

### 4-2. 현재 sudo로 허용된 명령 (경로·인자를 글자 그대로 써야 함)

| `ubuntu-a` | `rocky-b` |
| --- | --- |
| `/usr/sbin/sshd -T` | `/usr/sbin/sshd -T` |
| `/usr/bin/ss -lntup` | `/usr/sbin/ss -lntup` |
| `/usr/sbin/ufw status verbose` | `/usr/bin/firewall-cmd --state` |
| `/usr/sbin/nft list ruleset` | `/usr/bin/firewall-cmd --list-all` |
| `/usr/bin/tail -n 200 /var/log/auth.log` | `/usr/sbin/nft list ruleset` |
| | `/usr/bin/tail -n 200 /var/log/secure` |
| | `/usr/bin/cat /etc/ssh/sshd_config` |

**사용 시 주의**
- `ss`는 경로가 OS마다 다르다(Ubuntu `/usr/bin`, Rocky `/usr/sbin`).
- sudo `ss -lntup`은 첫 줄에 헤더가 붙는다(`-H`가 붙은 형태는 허용되지 않음).
- Rocky의 `firewall-cmd --list-all`은 **기본 존만** 보여 준다. 다른 활성 존과 서비스별 정의는 대체할 수 없다.

### 4-3. 승인 검토 중인 추가 후보 (미적용)

C 담당 검토(FW-01, LOG-01) 결과 팀장 승인을 요청할 후보다. 승인 전까지는 **허용되지 않은 상태**로 보고 개발한다.

> **2026-11-12 재측정** (`central-mgmt-c-permission-check-{1,2,3}-261112.png`): 두 대상의 `sudo -l`이 4-2 표(v0)와 같다. Rocky 기본 존·활성 존은 `public`(ens160) 하나, 서비스는 `cockpit dhcpv6-client ssh`로 11/11과 같다. 따라서 Rocky 후보는 아래 4개 명령으로 확정된다. `getfacl`과 Ubuntu journal 용량(`du`)은 일반 권한으로 가능해 후보에서 뺀다.

| 대상 | 후보 명령 | 비고 |
| --- | --- | --- |
| 공통 | `/usr/sbin/nft -j list ruleset` | 출력 형식만 JSON이고 읽는 정보는 기존 허용 명령과 같음. 지금은 거부됨(실측) |
| Rocky | `/usr/bin/firewall-cmd --info-zone=public`, `--info-service=ssh`, `--info-service=cockpit`, `--info-service=dhcpv6-client` | 존·서비스가 바뀌면 승인 목록도 갱신해야 함 |
| Rocky (선택) | journal 용량 | `journalctl --disk-usage`·`du` 모두 권한 부족. ① 정확한 sudo 명령 1개 허용(README 5-6에서 셸 탈출 위험으로 제외했던 `journalctl`은 재검토 필요), ② scan을 `systemd-journal` 그룹에 추가(전체 journal 읽기, 범위 넓음), ③ LOG-01에서 확인 불가(`error`) 처리 중 팀장 결정. Ubuntu는 `du`로 가능 |
| 공통 (PR #24) | `/usr/local/sbin/secureops-ssh01-read ""` | SSH-01 수집기 전용. 기존 v0 파일과 **별도 파일**로 설치 필요 (2-5) |

## 5. 네트워크 노출 현황 (2026-11-11 실측, `sudo ss -lntup`)

| 서버 | 외부 바인딩 수신 포트 | 로컬 전용 | 방화벽 |
| --- | --- | --- | --- |
| `ubuntu-a` | TCP 22 (sshd), UDP 5353·40089·42139 (avahi) | TCP 631 (cups), TCP·UDP 53 (resolved) | 없음 (ufw 비활성, nft 규칙 없음) |
| `rocky-b` | TCP 22 (sshd), UDP 5353 (avahi) | TCP 631 (cups), UDP 323 (chronyd) | firewalld `public`: `ssh`, `cockpit`, `dhcpv6-client` 허용, 출발지 제한 없음 |

- IPv6는 두 서버 모두 활성 상태이며 link-local 주소만 있다. TCP 22와 UDP 5353은 IPv6로도 수신한다.
- **미확인:** 다른 호스트에서 포트에 실제로 접속해 보는 시험은 하지 않았다. 체크리스트 G-12 원칙대로, 바인딩만으로 원격 노출을 단정하지 않는다.

## 6. 미검증·진행 중 사항

| 항목 | 상태 |
| --- | --- |
| VM 백업 ZIP 내부 구성, 7-Zip 검사, 원본 비교 | **완료** (README 7-1) |
| 백업 복원 시험 | **완료** (3대, README 7-2). 네트워크 격리는 작업자 확인 기준 |
| sudoers 파일 권한 `0440`, `visudo -c` 증거 | **완료** (`<id>-sudoers-perm-261111.png`) |
| `ubuntu-a` `autoinst.iso` 삭제, `user1` 비밀번호 변경 | **완료** (2026-11-12, 팀장 승인, README 7-3). `ubuntu-a` 일반 복구 기준은 `01-ssh-security-configured-passwd` 스냅샷과 `Target-Ubuntu-261112.zip`. 기존 스냅샷 `00`·`01`과 기존 백업에는 과거 해시가 남아 있어 일반 복구에 쓰지 않음 |
| 과거 해시가 남은 스냅샷·백업 삭제 | 팀장 별도 승인 대기 (현재 유지·접근 제한) |
| SSH-01 수집기 `/usr/local/sbin/secureops-ssh01-read` 및 전용 sudoers | 팀장 검토 후 적용 예정. 2026-11-12 재확인 시에도 두 대상 모두 미설치, 전용 sudoers 없음, 기존 scan sudoers 보존(2-5). 실행 조건(`/usr/bin/python3`, `/usr/local/sbin`)은 충족. Rocky sudo `secure_path`에 `/usr/local/sbin`이 없으므로 전체 경로로 호출 |
| `central-mgmt` 저장소 배치, 의존성 설치 | 미착수 (3-1의 결정 필요) |
| 대상 서버에 실제 포트 접속 시험 | 미실시 |
| sudoers 추가 후보 (4-3) | 팀장 승인 대기 |
| `secureops-fix` 조치 경로 | SSH-01 경로만 있으며, `/etc/secureops/approved/`는 아직 만들지 않아 실제로는 동작하지 않음 |

## 변경 이력

| 일자 | 내용 |
| --- | --- |
| 2026-11-11 | 최초 작성 (재구축 VM 검증 기준) |
| 2026-11-11 | `central-mgmt` 커널 6.8.0-149 정정, VMware Tools 현황, 백업·복원·sudoers 증거 완료 반영, SSH-01 수집기 확인 결과 추가 |
| 2026-11-12 | 2-4 SSH 출발지 IP·실제 인증 키 증거 추가 (Rocky `sshd-session` 로그 형식 참고 포함) |
| 2026-11-12 | 6장: `ubuntu-a` 비밀번호 변경·설치 미디어 삭제 완료, 신규 복구 기준 반영 (README 7-3) |
| 2026-11-12 | 2-5 중앙 실행기 연동값·SSH-01 평가 문맥·수집기 현황 추가, 4-1 `getfacl`·journal `du` 실측, 4-3 C 요청 재측정 결과로 후보 확정(PR #24 수집기 포함), 6장 수집기 상태 갱신 |
