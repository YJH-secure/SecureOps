# 공식 GitHub 커밋 기준 테스트

코드 기준은 `896022fecb9adfb6d60fc1778e6f9d03d9e591e7`이다.
부모는 PR #15 Squash 병합을 포함한 main
`42783699356325aa08cfb7187bfaf06ed8519019`이다.

공식 GitHub 트리와 파일별 Git blob 해시가 일치하는 48개 검증 입력 파일을
로컬에 구성해 테스트를 실행했다. 실행 환경은 Windows Python 3.12.14다.

```bash
python -B -m unittest discover -s checks/system/tests -v
```

결과는 155개 통과다. FILE·SVC 회귀 테스트와 FW·LOG 테스트가 함께 포함된다.
원본 테스트 출력은 `unit-tests-896022f.txt`에 첨부한다.

뒤따르는 검증 자료 커밋은 코드·정책·테스트를 변경하지 않고 문서와 로그만 추가한다.
Ubuntu·Rocky 실행 근거는 사용자가 공유한 기존 VM 결과를 요약한 것이며,
이번 공식 커밋의 로컬 테스트와 출처를 구분해 `VM_RESULTS.md`에 기록했다.
