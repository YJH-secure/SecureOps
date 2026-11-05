# SecureOps Infrastructure

### Linux 진단 환경 (VMware) 구축 및 검증

**담당:** 김민우 (A · 서버·네트워크 인프라)  
**관련 문서:** [시스템 아키텍처 설계서](../docs/architecture/system-architecture.md) · [프로젝트 README](../README.md)  
**상태:** 서버·네트워크 구성, 전용 계정, SSH 키 인증, `01-ssh-security-configured` 스냅샷 적용 완료 / 세부 권한 정책 및 검증 증거 확보 예정 — 적용 현황은 1장, 검증 상태는 6장 참고

## 1. 개요

이 폴더는 SecureOps의 진단 기능이 실행되는 **가상 서버와 네트워크 환경**을 정의한다. VM 파일 자체는 용량과 보안 문제로 GitHub에 올리지 않으며, 대신 **같은 환경을 다시 만들 수 있도록** 구성값, 설정 파일, 구축 절차, 검증 증거를 관리한다.

| 기준표 항목 | 이 폴더에서 다루는 내용 |
| --- | --- |
| 1장 담당 역할 | VM 구성/버전표, 서버 연결 증거, 스냅샷 증거 |
| 6장 통합 테스트 | T-01~T-04를 위한 접속 경로, 조치 전 스냅샷, OS 버전 정보 |
| 7장 확인 목록 | 실제 VM 버전·네트워크가 문서와 일치하는지 확인 |

### 적용 현황

이 문서의 내용은 **실제 서버에 적용 완료된 설정**과 **추후 적용·검증 예정인 설정**으로 구분한다.

**적용 완료** — 실제 서버에 설정됨

| 구분 | 내용 | 관련 장 |
| --- | --- | --- |
| 서버 | 3대 OS 설치 (Ubuntu 24.04.5 LTS Server/Desktop, Rocky Linux 9.8 Desktop) | 2장 |
| 서버 식별자 | `central-mgmt`, `ubuntu-a`, `rocky-b` 확정 | 2장 |
| 호스트명 | Central-Management-Ubuntu, Target-Ubuntu, Target-Rocky 설정 | 2장 |
| 네트워크 | VMnet8 NAT, `192.168.10.0/24` 고정 IP, 게이트웨이·DNS `192.168.10.2` | 3장 |
| 시간대 | 3대 모두 `Asia/Seoul` | 5-3 |
| SSH 서버 | 진단 대상 A/B에서 OpenSSH 서버 실행 | 5-4 |
| 비밀번호 정책 | 서버·계정별 서로 다른 16자 이상 비밀번호 | 5-5 |
| 계정 분리 | 진단 대상 A/B에 `secureops-scan`, `secureops-fix` 생성 | 5-5 |
| sudo 권한 | 두 전용 계정 모두 sudo 미부여 (sudoers 설정 없음) — 모든 sudo 명령 차단 | 5-6 |
| SSH 키 인증 | Ed25519 키 계정별 분리 생성, 공개키 등록, 4개 조합 키 접속 동작 확인 | 5-5 |
| 스냅샷 | `00-initial-setup` (초기 환경 복구용), `01-ssh-security-configured` (보안 설정 완료 상태) 생성 | 7장 |

**추후 적용·검증 예정** — 아직 서버에 적용되지 않음

| 구분 | 내용 | 적용 시점 |
| --- | --- | --- |
| 검증 증거 | 6장 체크리스트 중 미완료 항목(sudo 권한·차단, SSH 별칭 접속) 증거 캡처 | 증거 캡처 후 |
| SSH 설정 | root 직접 SSH 로그인 제한 등 `sshd_config` 변경 | 진단·조치 정책 확정 후 |
| 조치 계정 권한 | `secureops-fix`에 승인된 조치용 sudo 명령 부여 | 진단·조치 정책 확정 후 |
| 진단 계정 권한 | `secureops-scan`의 읽기 권한 범위 (`sshd -T`, `/etc/shadow` 등) | 진단·조치 정책 확정 후 |
| 스냅샷 | `02-vuln-baseline` 이후 단계 | 진단 항목 확정 후 |
| 설정 파일 | `network/`, `setup/` 스크립트 작성 | 구축 진행에 따라 |

## 2. 서버 구성

| 구분 | 서버 식별자 | 호스트명 | OS | 에디션 | IP | 커널 |
| --- | --- | --- | --- | --- | --- | --- |
| 중앙 관리 서버 | `central-mgmt` | Central-Management-Ubuntu | Ubuntu 24.04.5 LTS | Server | `192.168.10.10` | 6.8.0-147-generic |
| 진단 대상 A | `ubuntu-a` | Target-Ubuntu | Ubuntu 24.04.5 LTS | Desktop | `192.168.10.20` | 7.0.0-42-generic |
| 진단 대상 B | `rocky-b` | Target-Rocky | Rocky Linux 9.8 (Blue Onyx) | Desktop | `192.168.10.30` | 5.14.0-687.65.1.el9_8.x86_64 |

| 구분 | vCPU | RAM | 디스크 | 역할 |
| --- | --- | --- | --- | --- |
| 중앙 관리 서버 | 2 | 4096MB | 40GB | 진단 실행, SSH 연결 관리, 결과 통합·평가, 승인·조치 제어 |
| 진단 대상 A | 2 | 4096MB | 30GB | 1차 Linux 취약점 진단 및 재검증 |
| 진단 대상 B | 2 | 2048MB | 30GB | 다른 배포판의 점검 및 조치 호환성 검증 |

- 가상화: VMware Workstation
- 서버 식별자는 아키텍처 설계서 6장의 논리 식별자를 따르며, IP나 호스트명이 바뀌어도 유지한다.

> **Desktop 대상 주의:** 진단 대상 2대는 Desktop 에디션이라 Server보다 기본 서비스·패키지가 많다. SVC-01 등 서비스 관련 점검 결과에 차이가 생길 수 있다.

> **커널 차이:** 같은 Ubuntu 24.04.5라도 Server는 기본 커널(6.8), Desktop은 HWE 커널(7.0)이 설치된다. 서버 간 진단 결과가 다를 때 확인할 요소로 기록한다.

## 3. 네트워크 구성

| 항목 | 값 |
| --- | --- |
| 네트워크 | VMnet8 (NAT) 단일 구성 |
| 대역 | `192.168.10.0/24` (서브넷 마스크 `255.255.255.0`) |
| 게이트웨이 / DNS | `192.168.10.2` (VMware NAT 장치) |
| IP 할당 | 수동 지정 (VMnet8 DHCP 미사용) |
| 관리 접속 | 중앙 관리 서버 → 진단 대상 A/B, SSH TCP 22 |

| 주소 | 용도 |
| --- | --- |
| `192.168.10.1` | 호스트 PC의 VMnet8 가상 어댑터 (게이트웨이로 사용하지 않음) |
| `192.168.10.2` | VMware NAT 게이트웨이 및 DNS |
| `192.168.10.10` | 중앙 관리 서버 (`central-mgmt`) |
| `192.168.10.20` | 진단 대상 A (`ubuntu-a`) |
| `192.168.10.30` | 진단 대상 B (`rocky-b`) |

**NAT 단일 구성 근거:** VM 간 통신과 패키지 설치가 모두 가능하고, 외부에서 VM으로 직접 접근할 수 없어 실습 환경으로 격리된다. 진단 트래픽을 인터넷과 완전히 분리해야 하는 경우 Host-only(VMnet1) 어댑터를 추가 검토한다.

## 4. 배포판별 차이 (진단 담당 참고)

| 구분 | Ubuntu 24.04 | Rocky Linux 9.8 | 관련 항목 |
| --- | --- | --- | --- |
| 패키지 관리 | `apt` | `dnf` | SVC-01 |
| SSH 서비스명 | `ssh` | `sshd` | SSH-01, SSH-02 |
| PAM 설정 | `/etc/pam.d/common-*` | `/etc/pam.d/system-auth`, `password-auth` (**authselect 관리**) | ACC-01, ACC-02 |
| 방화벽 | `ufw` (기본 비활성) | `firewalld` (기본 활성) | FW-01 |
| 보안 모듈 | AppArmor | SELinux | FILE-01, SVC-01 |
| 인증 로그 | `/var/log/auth.log` | `/var/log/secure` | LOG-01 |
| 네트워크 설정 | netplan | NetworkManager (`nmcli`) | A |

> Rocky의 PAM 파일은 `authselect`가 생성·관리하므로 직접 수정하면 덮어써질 수 있다. 조치 전 관리 방식과 복구 절차를 먼저 확인한다.

> **OpenSSH 버전:** Ubuntu는 9.6, Rocky는 9.9로 표시되지만, 배포판은 버전 번호를 유지한 채 보안 패치를 적용(백포트)한다. 버전 번호만으로 취약 여부를 판정하지 않는다.

## 5. 구축 절차

### 5-1. VMnet8 설정 (호스트 PC)

VMware → **Edit → Virtual Network Editor → VMnet8**
- Subnet IP: `192.168.10.0`, Subnet mask: `255.255.255.0`
- NAT Settings의 Gateway IP가 `192.168.10.2`인지 확인
- "Use local DHCP service" 해제

### 5-2. 고정 IP 설정

**Ubuntu** — `/etc/netplan/` 아래 yaml 수정 후 `sudo netplan apply` (진단 대상 A 예시, 인터페이스 이름은 `ip a`로 확인)

```yaml
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.10.20/24]
      routes:
        - to: default
          via: 192.168.10.2
      nameservers:
        addresses: [192.168.10.2, 8.8.8.8]
```

**Rocky** — `nmcli`로 설정 (연결 이름은 `nmcli con show`로 확인)

```bash
sudo nmcli con mod ens160 ipv4.method manual ipv4.addresses 192.168.10.30/24 \
  ipv4.gateway 192.168.10.2 ipv4.dns "192.168.10.2 8.8.8.8"
sudo nmcli con up ens160
```

### 5-3. 기본 설정 (3대 공통)

```bash
# 패키지 최신화
sudo apt update && sudo apt upgrade        # Ubuntu
sudo dnf upgrade                           # Rocky

# 시간대 (JSON checked_at의 +09:00 기준)
sudo timedatectl set-timezone Asia/Seoul
```

### 5-4. OpenSSH 서버 (진단 대상)

```bash
# 진단 대상 A (Ubuntu Desktop은 기본 미설치)
sudo apt install openssh-server
sudo systemctl enable --now ssh

# 진단 대상 B (Rocky linux 기본 설치 여부 확인)
rpm -q openssh-server
sudo systemctl enable --now sshd
```

중앙 관리 서버는 접속하는 쪽이므로 `openssh-client`만 있으면 된다 (`ssh -V`로 확인).

### 5-5. 계정 및 SSH 키 인증

**SSH 인증 및 권한 원칙 (확정)**
- 중앙 관리 서버(`central-mgmt`)에서 진단 대상(`ubuntu-a`, `rocky-b`)으로 접속할 때 **SSH 공개키 인증(Ed25519)**을 사용한다. — **적용 완료**
- 진단·조치는 전용 계정(`secureops-scan`, `secureops-fix`)으로 분리해 수행한다. — **적용 완료**
- 전체 관리자 권한 대신 **최소 권한 원칙**을 적용한다. 실제 진단·조치 기능에 필요한 세부 권한은 정책 확정 후 적용한다. — **적용 예정**
- root 직접 SSH 로그인은 제한한다. — **적용 예정** (정책 확정 후)

**계정 구성**

| 계정 | 용도 | 위치 | 현재 상태 (적용 완료) | 추후 적용 예정 |
| --- | --- | --- | --- | --- |
| `user1` | 서버 관리용 | 3대 공통 | 관리자(sudo) | — |
| `secureops-scan` | 취약점 진단용 | 진단 대상 A/B | 계정·SSH 키 등록, sudo 없음 (일반 사용자 읽기 권한) | 진단에 필요한 읽기 권한 범위 |
| `secureops-fix` | 보안 조치용 | 진단 대상 A/B | 계정·SSH 키 등록, sudo 없음 | 승인된 조치에 한한 제한적 sudo |
| `root` | 시스템 관리자 | 3대 공통 | 기본 설정 유지 | 직접 SSH 로그인 제한 |

**적용 시점**

| 작업 | 상태 |
| --- | --- |
| 전용 계정 생성, SSH 키 생성·등록, 키 접속 확인 | 적용 완료 |
| root 직접 SSH 로그인 제한 등 `sshd_config` 변경 | 진단·조치 기능 및 정책 확정 후 적용 |
| `secureops-scan`, `secureops-fix`의 세부 권한 부여 | 진단·조치 기능 및 정책 확정 후 적용 |

**비밀번호 정책**
- 서버별로 서로 다른 비밀번호를 사용하고, 같은 서버의 `user1`과 `root`도 각각 다르게 설정한다.
- 16자 이상의 강력한 비밀번호를 사용한다.
- 비밀번호는 이 저장소, 문서, 팀 채팅방에 기록·공유하지 않는다.
- `secureops-scan`, `secureops-fix`는 비밀번호 없이 SSH 키로만 접속한다.

**1) 전용 계정 생성** — 진단 대상 A/B에서 `user1`로 실행

```bash
sudo useradd -m -s /bin/bash secureops-scan
sudo useradd -m -s /bin/bash secureops-fix
```

**2) SSH 키 생성** — 중앙 관리 서버에서 실행 (계정별로 키를 분리)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_scan -C "secureops-scan"
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_fix  -C "secureops-fix"
```

**3) 공개키 등록** — 전용 계정은 비밀번호가 없어 `ssh-copy-id`를 쓸 수 없으므로, `user1`을 통해 등록한다.

```bash
# 중앙 관리 서버에서 공개키 전송 (진단 대상 B는 192.168.10.30)
scp ~/.ssh/id_ed25519_scan.pub ~/.ssh/id_ed25519_fix.pub user1@192.168.10.20:/tmp/
```

```bash
# 진단 대상 A/B에서 user1로 실행
for u in scan fix; do
  sudo install -d -m 700 -o secureops-$u -g secureops-$u /home/secureops-$u/.ssh
  sudo install -m 600 -o secureops-$u -g secureops-$u /tmp/id_ed25519_$u.pub /home/secureops-$u/.ssh/authorized_keys
done
rm /tmp/id_ed25519_*.pub
sudo restorecon -R /home/secureops-*/.ssh   # Rocky(SELinux)만 해당
```

**4) 접속 확인** — 중앙 관리 서버에서 실행

```bash
ssh -i ~/.ssh/id_ed25519_scan secureops-scan@192.168.10.20
ssh -i ~/.ssh/id_ed25519_fix  secureops-fix@192.168.10.20
```

> 개인키(`~/.ssh/id_ed25519_scan`, `~/.ssh/id_ed25519_fix`)는 중앙 관리 서버 밖으로 복사하지 않으며 이 저장소에 커밋하지 않는다.

### 5-6. 계정 권한 및 sudo 설정 현황

현재 두 전용 계정에는 **sudo 권한을 부여하지 않았다.** `/etc/sudoers`와 `/etc/sudoers.d/`에 두 계정 관련 설정이 없으며, `sudo`·`wheel` 그룹에도 속하지 않는다. 진단·조치 기능별 세부 권한은 정책 확정 후 필요한 명령만 추가한다.

| 계정 | 그룹 | sudo 허용 명령 | 실제 적용한 sudoers 설정 |
| --- | --- | --- | --- |
| `secureops-scan` | 본인 그룹만 | 없음 | 없음 |
| `secureops-fix` | 본인 그룹만 | 없음 | 없음 |

**확인 명령** — 진단 대상 A/B에서 `user1`로 실행

```bash
id secureops-scan; id secureops-fix          # sudo/wheel 그룹 미포함 확인
sudo -l -U secureops-scan                    # "not allowed to run sudo" 확인
sudo -l -U secureops-fix
sudo grep -rn "secureops" /etc/sudoers /etc/sudoers.d/   # 출력 없음 확인
```

**sudo 차단 확인** — 중앙 관리 서버에서 실행

```bash
for ip in 192.168.10.20 192.168.10.30; do
  for u in scan fix; do
    echo "=== secureops-$u@$ip ==="
    ssh -i ~/.ssh/id_ed25519_$u -o BatchMode=yes secureops-$u@$ip 'sudo -n id 2>&1 || echo "sudo 차단됨"'
  done
done
```

4개 조합 모두 `sudo 차단됨`이 출력되면 정상이다.

### 5-7. 공통 SSH 모듈 연동 정보

`common/ssh_client.py`(양지혁 담당) 연동을 위한 접속 정보이다. **개인키 파일, 개인키 내용, 비밀번호는 이 저장소에 올리지 않는다.**

**1) 인증 방식**

| 항목 | 내용 |
| --- | --- |
| 방식 | OpenSSH 공개키 인증 (Ed25519) |
| 비밀번호 인증 | 전용 계정은 비밀번호가 없어 키로만 접속 가능 |
| 키 구성 | 계정별 분리 — `secureops-scan`용 키, `secureops-fix`용 키 |
| 키 비밀번호(passphrase) | 없음 (자동 진단용) |
| OpenSSH 기본 키와의 차이 | 키 파일명이 기본값(`id_ed25519`)이 아니므로, 중앙 관리 서버의 `~/.ssh/config`에서 대상별 키를 지정한다. 이 설정이 있으면 `ssh ubuntu-a`처럼 별칭만으로 접속되며, SSH agent 사용 시에는 `ssh-add`로 두 키를 등록한다. |

**2) 개인키 경로**

실제 경로는 환경마다 다를 수 있으므로 아래는 예시이며, 구체적인 경로는 중앙 관리 서버의 `~/.ssh/config`로 관리한다 (Git에 올리지 않음).

| 용도 | 경로 예시 (중앙 관리 서버 `user1`) |
| --- | --- |
| 진단용 | `~/.ssh/id_ed25519_scan` |
| 조치용 | `~/.ssh/id_ed25519_fix` |

```bash
# 실제 키 파일 확인
ls -l ~/.ssh/
# 별칭별로 실제 사용되는 키·계정·주소 확인
ssh -G ubuntu-a | grep -Ei "^(hostname|user|port|identityfile) "
```

`~/.ssh/config` 예시 (경로만 포함하며 비밀정보 없음):

```text
Host ubuntu-a
    HostName 192.168.10.20
    User secureops-scan
    IdentityFile ~/.ssh/id_ed25519_scan
    IdentitiesOnly yes

Host rocky-b
    HostName 192.168.10.30
    User secureops-scan
    IdentityFile ~/.ssh/id_ed25519_scan
    IdentitiesOnly yes

Host ubuntu-a-fix
    HostName 192.168.10.20
    User secureops-fix
    IdentityFile ~/.ssh/id_ed25519_fix
    IdentitiesOnly yes

Host rocky-b-fix
    HostName 192.168.10.30
    User secureops-fix
    IdentityFile ~/.ssh/id_ed25519_fix
    IdentitiesOnly yes
```

**3) 진단 대상 접속 정보**

| 서버 식별자 | IP | 포트 | 진단 계정 | 조치 계정 | SSH 별칭 (진단 / 조치) |
| --- | --- | --- | --- | --- | --- |
| `ubuntu-a` | `192.168.10.20` | 22 | `secureops-scan` | `secureops-fix` | `ubuntu-a` / `ubuntu-a-fix` |
| `rocky-b` | `192.168.10.30` | 22 | `secureops-scan` | `secureops-fix` | `rocky-b` / `rocky-b-fix` |

**4) 진단 계정 권한 범위**

- `secureops-scan`, `secureops-fix` 모두 **sudo 권한 없음** (5-6 참고).
- 실행 가능한 명령을 목록으로 제한하지는 않았으며, **일반 사용자 권한으로 읽을 수 있는 범위**에서만 동작한다.
- 따라서 root 권한이 필요한 점검은 현재 계정으로 수행할 수 없다. "확인 방법" 열이 **테스트**인 항목은 2026-11-05 아래 테스트 명령으로 실제 확인한 결과이고, **예상**인 항목은 배포판 기본 권한 기준이며 추후 확인한다.

| 점검 대상 | Ubuntu (`ubuntu-a`) | Rocky (`rocky-b`) | 확인 방법 | 관련 항목 |
| --- | --- | --- | --- | --- |
| `/etc/passwd` 읽기 | 가능 | 가능 | 테스트 | ACC-01, FILE-01 |
| PAM 설정 읽기 (`common-auth` / `system-auth`) | 가능 | 가능 | 테스트 | ACC-01, ACC-02 |
| `/etc/security/pwquality.conf` 읽기 | 가능 | 가능 | 테스트 | ACC-01 |
| `/etc/ssh/sshd_config` 읽기 | 가능 | **불가** | 테스트 | SSH-01, SSH-02 |
| `/etc/shadow` 읽기 | **불가** | **불가** | 테스트 | FILE-01 (권한 확인은 `stat`으로 가능) |
| 인증 로그 (`/var/log/auth.log` / `/var/log/secure`) | **불가** | **불가** | 테스트 | LOG-01 |
| `sshd -T` (유효 설정 확인) | **불가** (root 필요) | **불가** (root 필요) | 예상 | SSH-01, SSH-02 |
| `stat`으로 파일 소유자·권한 확인 | 가능 | 가능 | 예상 | FILE-01 |
| `systemctl list-units`, `ss -lntu` | 가능 (`ss -p` 프로세스 정보는 제한) | 가능 (동일) | 예상 | SVC-01 |
| 방화벽 규칙 조회 (`ufw status`, `nft list ruleset`, `firewall-cmd`) | **불가** (root 필요) | 확인 필요 | 예상 | FW-01 |

> 진단 담당 참고: Rocky는 `sshd_config` 자체를 읽을 수 없어 SSH-01·SSH-02는 현재 진단 계정으로 판정할 수 없다. 기준표 원칙에 따라 권한 부족은 임의로 양호 처리하지 않고 `error`로 기록하며, 필요한 읽기 권한은 정책 확정 시 검토한다.

```bash
# 중앙 관리 서버에서 실행 — 진단 계정의 파일 읽기 권한 확인
for h in ubuntu-a rocky-b; do
  echo "=== $h ==="
  ssh $h 'for f in /etc/passwd /etc/shadow /etc/ssh/sshd_config /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/security/pwquality.conf /var/log/auth.log /var/log/secure; do [ -e "$f" ] && { [ -r "$f" ] && echo "읽기 가능: $f" || echo "읽기 불가: $f"; }; done'
done
```

**5) SSH 접속 테스트**

| 테스트 | 결과 |
| --- | --- |
| `secureops-scan`, `secureops-fix` × `ubuntu-a`, `rocky-b` 키 접속 (4개 조합) | 2026-11-05 확인 (`central-mgmt-sshkey-261105.png`) |
| `~/.ssh/config` 별칭 접속 (`ssh ubuntu-a` 등 4개) | 2026-11-05 동작 확인 (증거 캡처 예정) |
| 진단 계정 읽기 권한 테스트 (위 명령) | 2026-11-05 확인, 4) 표에 반영 (`central-mgmt-scan-read-test-261105.png`) |

## 6. 검증 체크리스트

모든 항목은 **실제 테스트와 증거 캡처를 마친 뒤** 완료(`[v]`)로 표시한다. 1장 적용 현황의 "적용 완료"는 설정이 적용된 상태를 뜻하며, 이 체크리스트의 완료는 증거까지 확보된 상태를 뜻한다.

증거는 서버별 폴더에 `evidence/<서버 식별자>/<서버 식별자>-<항목>-YYMMDD.png` 형식으로 저장한다. 중앙 관리 서버에서 실행해 진단 대상을 함께 확인한 캡처(VM 간 통신, SSH 키 접속, 읽기 권한 테스트)는 `central-mgmt/`에 둔다. 아래 증거 열의 `<id>`는 `central-mgmt`, `ubuntu-a`, `rocky-b`를 뜻한다.

| 상태 | 확인 항목 | 명령어 | 정상 기준 | 증거 (2026-11-05) |
| --- | --- | --- | --- | --- |
| [v] | OS 버전 | `cat /etc/os-release` | 2장 버전표와 일치 | `<id>-os-261105.png` (3대) |
| [v] | 호스트명 | `hostnamectl --static` | 2장 호스트명과 일치 | `<id>-hostname-261105.png` (3대) |
| [v] | IP 할당 | `ip -4 a` | 2장 IP와 일치 | `<id>-ip-261105.png` (3대) |
| [v] | 기본 경로 | `ip route` | `default via 192.168.10.2` | `<id>-route-261105.png` (3대) |
| [v] | 시간대 | `timedatectl` | `Asia/Seoul` (3대 모두) | `<id>-timedate-261105.png` (3대) |
| [v] | 외부 통신 | `ping 8.8.8.8`, `ping google.com` | 응답 수신 | `<id>-outerping-261105.png` (3대) |
| [v] | VM 간 통신 | `ping 192.168.10.20`, `ping 192.168.10.30` | 중앙 관리 서버에서 응답 | `central-mgmt-innerping-261105.png` |
| [v] | SSH 키 접속 | `ssh -i ~/.ssh/id_ed25519_scan secureops-scan@192.168.10.20` / `.30` | `secureops-scan`, `secureops-fix` 모두 비밀번호 없이 로그인 성공 | `central-mgmt-sshkey-261105.png` |
| [v] | 패키지 관리 | `sudo apt update` / `sudo dnf check-update` | 오류 없이 완료 | `<id>-pkg-261105.png` (3대) |
| [ ] | scan 계정 권한 | `sudo -l -U secureops-scan` (진단 대상에서 `user1`로) | sudo 실행 권한 없음 | — |
| [ ] | fix 계정 권한 | `sudo -l -U secureops-fix` (진단 대상에서 `user1`로) | sudo 실행 권한 없음 (정책 확정 후 허용 명령 추가) | — |
| [ ] | sudo 차단 | 5-6의 차단 확인 명령 | 두 계정 모두 sudo 실행 거부 | — |
| [ ] | SSH 별칭 접속 | `ssh ubuntu-a whoami` 등 4개 별칭 | 각 계정으로 비밀번호 없이 접속 | — |
| [v] | 진단 계정 읽기 권한 | 5-7의 읽기 권한 확인 명령 | 결과를 5-7 표에 반영 | `central-mgmt-scan-read-test-261105.png` |
| [v] | 스냅샷 | Snapshot Manager | `00-initial-setup`, `01-ssh-security-configured` 생성 확인 | `<id>-snapshot-261105.png` (3대) |

중앙 관리 서버에서 진단 대상 2대의 정보와 SSH 연결을 한 번에 확인할 수 있다.

```bash
for ip in 192.168.10.20 192.168.10.30; do echo "=== $ip ==="; ssh -i ~/.ssh/id_ed25519_scan secureops-scan@$ip 'hostname; grep PRETTY_NAME /etc/os-release; hostname -I; systemctl get-default'; done
```

## 7. 스냅샷 규칙

스냅샷은 VM마다 따로 저장되므로 이름에 서버 식별자를 넣지 않고, **같은 단계는 3대 모두 같은 이름**을 사용한다.

| 이름 | 대상 | 생성 시점 | 상태 |
| --- | --- | --- | --- |
| `00-initial-setup` | 3대 공통 | 기본 설정, 비밀번호 설정, 네트워크 연결 확인 완료 후 — 초기 환경 복구용으로 유지 | **확정** |
| `01-ssh-security-configured` | 3대 공통 | 전용 계정·SSH 키 인증·호스트명 설정 및 권한 검증 완료 후 | **확정** |
| `02-mgmt-ready` | 중앙 관리 서버 | Python 3.12, Git 등 개발 도구 설치 후 | 제안 |
| `02-vuln-baseline` | 진단 대상 A/B | 진단 담당과 협의한 취약 설정 적용 후 | 제안 |
| `03-pre-remediation-YYMMDD` | 진단 대상 A/B | 관리자 승인 후 조치 직전 (T-03) | 제안 |
| `04-post-remediation-YYMMDD` | 진단 대상 A/B | 조치·재진단 완료 후 (선택) | 제안 |

- 반복될 수 있는 단계(03, 04)에만 날짜를 붙이고, 같은 날 두 번 생성 시 `-2`를 붙인다.
- Description에 날짜, 작업자, 작업 내용을 기록한다. 예: `261105 김민우 / 기본 설정, 비밀번호 설정, 연결 확인 완료`
- 기준점 스냅샷(00, 01, 02)은 `sudo poweroff`로 정상 종료한 뒤 생성한다.
- 스냅샷은 VM 폴더 안에 저장되므로 백업이 아니다. 중요한 시점에는 VM 폴더 전체를 외부 저장소에 복사한다.
- 복구는 Snapshot Manager → Go To로 하며, 복구 후 6장 체크리스트를 다시 확인한다.

## 8. 디렉터리 구조

```text
infrastructure/
├── README.md                     # 인프라 구성·구축 절차·검증 기준 문서 (이 문서)
├── network/                      # 서버별 고정 IP 설정 파일
│   ├── netplan-central-mgmt.yaml # 중앙 관리 서버 netplan 설정 (192.168.10.10)
│   ├── netplan-ubuntu-a.yaml     # 진단 대상 A netplan 설정 (192.168.10.20)
│   └── nmcli-rocky-b.sh          # 진단 대상 B nmcli 설정 명령 (192.168.10.30)
├── setup/                        # 기본 설정 자동화 스크립트 (비밀번호 설정 제외)
│   ├── ubuntu-ssh-setup.sh       # Ubuntu: 패키지 업데이트, 시간대, OpenSSH 서버 설치·실행
│   ├── rocky-ssh-setup.sh        # Rocky: 패키지 업데이트, 시간대, sshd 실행
│   └── ssh-key-setup.sh          # 전용 계정(secureops-scan/fix) 생성, Ed25519 키 생성 및 공개키 등록
└── evidence/                     # 검증 캡처 (<서버 식별자>-<항목>-YYMMDD.png)
    ├── central-mgmt/             # 중앙 관리 서버 확인 + 진단 대상 원격 확인(VM 간 통신, SSH 키, 읽기 권한)
    ├── ubuntu-a/                 # 진단 대상 A 확인 캡처
    └── rocky-b/                  # 진단 대상 B 확인 캡처
```

설정 파일과 스크립트는 구축을 진행하며 순차적으로 추가한다.

## 9. VM 공유 방법

VM 자체가 필요한 경우 VMware **File → Export to OVF**로 `.ova` 파일을 만들어 공유 저장소로 전달하고, 이 문서에는 **링크만** 기록한다. VM에 설정된 비밀번호는 5-5의 비밀번호 정책에 따라 공유하지 않으며, 접근 방식은 팀에서 별도로 정한다.

## 10. 팀 협의 필요 사항

- [x] 중앙 관리 서버의 서버 식별자 및 호스트명 (`central-mgmt` / Central-Management-Ubuntu)
- [x] 진단 대상 호스트명을 서버 식별자(`ubuntu-a`, `rocky-b`)와 맞출지 여부 (호스트명은 Target-Ubuntu, Target-Rocky 유지)
- [x] 전용 계정·SSH 키 등록 이후 스냅샷 이름 (`01-ssh-security-configured`)
- [ ] 스냅샷 `02` 이후 단계 이름 확정
- [ ] JSON 필드명 `target_id` / `server_id` 통일 (D · 조효민)
- [ ] `secureops-fix`에 허용할 sudo 명령 범위 (정책 확정 후 적용)
- [ ] `secureops-scan`으로 읽을 수 없는 점검 대상 파일(예: `/etc/shadow`) 처리 방식
- [ ] root 직접 SSH 로그인 제한 등 `sshd_config` 변경 적용 시점
- [ ] 계정별 SSH 키 분리 방식 (`id_ed25519_scan`, `id_ed25519_fix`) 확정
- [ ] `02-vuln-baseline`에 적용할 취약 설정 목록 (B · 최종욱, C · 김서후)
- [ ] 진단 대상 Desktop의 자동 업데이트 사용 여부 (재검증 일관성)

## 11. 변경 이력

| 버전 | 일자 | 변경 사항 |
| --- | --- | --- |
| v0.1 | 2026-11-05 | 서버 구성(실제 OS 버전·에디션·커널), 네트워크, 구축 절차, 비밀번호 정책, SSH 키 인증 및 계정 구성(user1, secureops-scan, secureops-fix), 검증 체크리스트, 스냅샷 규칙 초안 작성 (아키텍처 설계서 v0.2 기준), 공통 SSH 모듈 연동 정보 추가, 검토 반영 (`central-mgmt` 확정, 적용 완료·예정 구분, `01-ssh-security-configured` 스냅샷 및 계정 권한 현황 추가) |

---

본 환경은 허가된 실습 목적의 격리된 VM에서만 사용한다.
