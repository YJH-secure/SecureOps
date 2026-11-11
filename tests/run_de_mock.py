"""프로젝트 루트에서 python -B tests/run_de_mock.py로 실행한다.

PR #8의 고정 커밋에서 D 원본을 임시 폴더에 추출하고 E 단위 테스트와
D↔E 통합 테스트를 함께 실행한다. D 커밋은 로컬 Git에 있어야 한다.
원격 다운로드나 브랜치 변경은 수행하지 않는다. Python 3.12 기준.
"""

from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory


D_COMMIT = "994d20c1d7a914ba8a77ab9e89ea7080c16e171e"


def main():
    repo = Path(__file__).resolve().parents[1]
    archive = subprocess.run(
        ["git", "archive", "--format=tar", D_COMMIT, "core"], cwd=repo,
        capture_output=True, check=False,
    )
    if archive.returncode:
        raise SystemExit(f"D 기준 커밋 {D_COMMIT}의 core 소스를 로컬 Git에서 읽지 못했습니다")

    # 소스와 보고서 모두 임시 디렉터리에서 사용하고 실행 후 정리한다.
    with TemporaryDirectory(prefix="secureops-d-source-") as directory:
        with tarfile.open(fileobj=BytesIO(archive.stdout)) as source:
            source.extractall(directory, filter="data")
        environment = dict(os.environ, SECUREOPS_D_SOURCE=directory)
        print(f"D 기준 커밋: {D_COMMIT}", flush=True)
        result = subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=repo, env=environment, check=False,
        )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
