# SecureOps E FILE-01 최종 제출 자료

## 기준과 범위

- 제출 브랜치 기준 시작점: PR #35 `03573429825e02e6400257f19c67f337e454dd71`
- 검증된 E 소스 기준: `2d776a52faf692f13ebca2f00a591bcfa805b8fb`
- C 기준: `2fac2a02edb1edf08cf4435138f4a1d543e33ba2`
- C Bridge SHA-256: `497ac6a21270f517ad94041dcd7769eef3aa2a1c16b956df81e931fb1d698714`
- D callback 전달본 SHA-256: `4812dc4da5b660fbc5e4eb5c349905f6ccc28cbdcd8b0acb7b949d9c0f26ad58`
- D Core의 해당 SHA가 Git commit/tree에 연결되는지는 확인되지 않았다.

이 자료는 E FILE-01의 격리 MOCK 구현과 검증 결과를 검토·재현하기 위한 것이다. 실제 서버 파일 권한 변경, SSH 연결, 원격 자동 조치는 수행하지 않았다.

## 제출물

- `evidence/SecureOps_E_FILE01_Final_Evidence_20261126.zip`: 비식별 처리된 304건 검증 기록, D04/D05 선택 실행 결과, 발표 캡처 5장 및 파일별 해시 자료.
- `evidence/SHA256SUMS.txt`: 위 ZIP의 SHA-256.
- `presentation-guide-20261126.md`: 발표 순서, 시연 설명 및 예상 질문.
- `final-freeze-20261126.md`: 구현 동결 범위, 검증 근거와 잔여 한계.
- 상위 저장소 변경 E 코드 8개는 기준 checkout 및 304건 검증 src와 바이트 해시가 일치하도록 고정했다. 변경 파일 목록과 SHA-256은 Git diff 및 `evidence-manifest.json`을 참조한다.

## 검증 수치 읽는 법

304건은 E/C 266건과 D callback 38건의 기존 교차 검증 결과다. 이번 제출 준비에서 회귀 테스트를 재실행하지 않았다. D04 정상 복구와 D05 실패 롤백의 후속 실행은 각 1건 PASS였으나 기존 테스트 ID를 다시 실행한 것이므로 304건에 더하지 않았다. 스크린샷의 FILE-01 두 장은 D04/D05 결과 JSON을 요약해 출력한 캡처이며 실시간 실행 화면이 아니다.

## 재현 조건

ZIP은 결과와 증거를 검토할 수 있지만 단독 실행 패키지는 아니다. 코드를 재실행하려면 Python 3.12.14, `jsonschema` 4.26.0, 고정 E checkout, 고정 C 소스/Bridge 및 D callback 전달본이 필요하다. 이 제출 브랜치의 로컬 커밋으로 새 테스트를 실행했다는 뜻은 아니다. 검증된 E 소스 HEAD `2d776a5`를 가진 checkout과 승인된 의존성 경로를 확보한 뒤 기존 `reports/e-file01-mock-20261123/verify.py` 절차를 따라야 한다. D04/D05 선택 실행은 기존 `test_file01_mock_callback.py`와 D callback 전달본이 추가로 필요하다.

개발 동결 전 검토자는 archive 내부 README와 SHA 목록, `final-freeze-20261126.md`의 미검증 범위를 함께 확인한다.
