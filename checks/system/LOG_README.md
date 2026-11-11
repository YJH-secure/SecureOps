# LOG-01 로그 수집·보관 상태 초기 조회

Ubuntu와 Rocky에서 로그 수집 서비스 상태, 로그 경로의 메타데이터, 보관·순환 설정을 읽기 전용으로 수집합니다. 위험도는 팀 기준표의 `medium`입니다.

```bash
python3 -m checks.system.log_check > log01-result.json
python3 -m unittest checks.system.tests.test_log_check -v
```

- `systemctl show`로 `systemd-journald.service`, `rsyslog.service`, `logrotate.timer`의 로드·활성·설치 상태를 확인합니다.
- `systemd-analyze cat-config systemd/journald.conf`에서 `[Journal]`의 보관 관련 명시 설정만 추립니다. 설정이 생략되면 배포판 기본값 또는 실제 적용값을 추정하지 않습니다.
- `journalctl --disk-usage`로 현재 계정에 보이는 활성·보관 저널의 사용량을 확인합니다.
- `/var/log/journal`, `/run/log/journal`과 Ubuntu의 `/var/log/auth.log`·`/var/log/syslog`, Rocky의 `/var/log/secure`·`/var/log/messages`의 존재·유형·모드·UID·GID를 확인합니다. 로그 파일 본문을 열거나 심볼릭 링크를 따라가지 않습니다.
- `/etc/rsyslog.conf`, `/etc/rsyslog.d/*.conf`, `/etc/logrotate.conf`, `/etc/logrotate.d/`의 일반 설정 파일에서 알려진 로그 경로와 보관 지시어만 추립니다. 이 근거는 설정 파일에서 관측한 값입니다. 전체 include 해석, 실제 rsyslog 라우팅, 로그별 logrotate 적용값 또는 타이머 실행 이력을 확인하려면 추가 검증이 필요합니다.

공통 JSON v1.1의 개별 결과를 표준 출력에 기록합니다. 승인된 운영 기준이 없으면 `needs_review`, 필수 조회 실패는 `error`입니다. 로그 파일이 없거나 선택 서비스가 설치되지 않은 상태는 관측값이며 journald 등 다른 수집 경로와 함께 검토합니다. 유효한 결과 JSON을 출력하면 `status: error`도 종료 코드 `0`을 반환합니다.

실제 인증 이벤트 기록 여부, 재부팅 후 유지, 승인 보관 기간·접근권한 충족은 별도 검증 대상입니다. 이 조회에서 인증 이벤트 생성, 설정 변경, 로그 순환, 서비스 재시작을 수행하지 않습니다.

참고 문서: [journald.conf](https://www.freedesktop.org/software/systemd/man/latest/journald.conf.html), [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html), [RHEL 9 로그 파일](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/configuring_basic_system_settings/assembly_troubleshooting-problems-using-log-files_configuring-basic-system-settings), [logrotate](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in).
