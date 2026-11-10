# 승인 후 실행할 명령 — 현재 단계에서는 실행하지 않음

검증 Worktree: C:/Users/Public/Documents/ESTsoft/CreatorTemp/SecureOps-cvss-main-review-854703a2d5fe.
브랜치: feature/cvss-core-jhm-main-review. 대상 PR base: main.
아래 스테이징·Commit·Push·PR 생성은 별도 사용자 승인 후에만 수행한다.

먼저 현재 작업 파일이 file-inventory.json의 SHA-256과 일치하는지 확인한다.
Git staged 변경이 추가로 있거나 origin/main이 검증 기준 d1f7534에서 바뀌었다면 실행을 중단하고 재검토한다.
git diff --check와 신규 파일·로그 목록도 확인한다.

```powershell
Set-Location 'C:/Users/Public/Documents/ESTsoft/CreatorTemp/SecureOps-cvss-main-review-854703a2d5fe'
git branch --show-current
git rev-parse HEAD origin/main
git diff --check
git diff --cached --name-only

git add -- core/main.py core/runner.py core/storage.py core/remote_result.py core/cvss.py core/cvss_validation.py core/cvss_assessment.py tests/test_cvss.py tests/test_cvss_v12.py tests/test_cvss_assessment.py requirements-test.txt
git add -- docs/evidence/cvss-v1.2

# .gitignore 대상 로그 21개를 정확한 목록으로 추가한다.
$evidenceLogs = Get-Content -LiteralPath 'docs/evidence/cvss-v1.2/pr-preparation/log-paths.txt'
foreach ($evidenceLog in $evidenceLogs) {
    git add -f -- $evidenceLog
    if ($LASTEXITCODE -ne 0) { throw 'Evidence log staging failed' }
}

git diff --cached --check
git diff --cached --stat
git diff --cached --name-only
# staged 목록이 file-inventory.json과 일치하고 정책·기존 테스트 변경이 없는지 확인한 뒤:
git commit -m "feat(core): add CVSS v3.1 Base scoring and JSON v1.2 validation"
git push --set-upstream origin HEAD:feature/cvss-core-jhm-main-review
```

PR 제목: feat(core): add CVSS v3.1 Base scoring and JSON v1.2 validation
PR 본문: docs/evidence/cvss-v1.2/pr-preparation/pr-description.md

GitHub CLI가 설치되어 있는 경우의 생성 명령:

```powershell
gh pr create --repo YJH-secure/SecureOps --base main --head feature/cvss-core-jhm-main-review --title "feat(core): add CVSS v3.1 Base scoring and JSON v1.2 validation" --body-file docs/evidence/cvss-v1.2/pr-preparation/pr-description.md
```

준비 시점에는 gh CLI가 발견되지 않았다. 승인 후 GitHub 연결 도구의 PR 생성 기능으로
동일한 base/head/title/body를 전달할 수 있으며, 위 명령과 중복 실행하지 않는다.
Merge·Rebase 및 기존 feature/core-jhm·main 변경은 이 절차에 포함하지 않는다.
