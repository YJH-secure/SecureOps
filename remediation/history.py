"""D 진단 보고서와 분리된 로컬 E 실행 이력 저장소. 동일 ID는 덮어쓰지 않는다."""

from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate execution history JSON key")
        result[key] = value
    return result


def _check_object_keys(value):
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("execution JSON object keys must be strings")
        for child in value.values():
            _check_object_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _check_object_keys(child)


class ExecutionHistoryStore:
    """신뢰된 전용 디렉터리에 실행 결과를 저장하고 ID로 독립 조회한다.

    MOCK 테스트는 임시 디렉터리를 사용한다. Windows의 디렉터리 접근 권한은
    운영자가 별도로 관리한다. 변조 방지 서명·암호화·D 저장소 연동은 제공하지 않는다.
    """
    def __init__(self, root):
        root = Path(root).absolute()
        if root.is_symlink() or root.resolve() != root:
            raise ValueError("history directory cannot use symbolic links")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not root.is_dir():
            raise ValueError("history root must be a directory")
        self.root = root

    @staticmethod
    def _id(value):
        if not isinstance(value, str) or not value.strip():
            raise ValueError("nonempty execution_id required")
        return value

    def _path(self, execution_id):
        # 외부 ID를 경로로 사용하지 않아 ../ 같은 값도 저장소 밖으로 나갈 수 없다.
        name = sha256(self._id(execution_id).encode("utf-8")).hexdigest()
        return self.root / (name + ".json")

    @classmethod
    def _encode(cls, record):
        if not isinstance(record, dict):
            raise TypeError("E execution history must be an object")
        if "schema_version" in record or "results" in record:
            raise ValueError("D diagnosis reports do not belong in E history")
        for name in ("execution_id", "target_id", "check_id", "before_scan_id"):
            cls._id(record.get(name))
        for name in ("after_scan_id", "post_rollback_scan_id"):
            if name not in record:
                raise ValueError("execution scan links required")
            if record[name] is not None:
                cls._id(record[name])
        if record.get("outcome") not in {"planned", "success", "rejected", "skipped", "failed"}:
            raise ValueError("invalid execution outcome")
        if record.get("rollback") not in {"not_needed", "verified", "failed"}:
            raise ValueError("invalid rollback value")
        payload = json.dumps(record, ensure_ascii=False, indent=2, allow_nan=False)
        # Dry-run 계획의 tuple은 기존 CLI JSON 출력과 같은 배열로 저장한다.
        _check_object_keys(record)
        return payload

    def save(self, record):
        """실행 결과를 원자적으로 추가하고 경로를 반환한다. 중복 ID는 예외로 거부한다."""
        payload = self._encode(record)
        destination = self._path(json.loads(payload)["execution_id"])
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.root,
                                             prefix=".execution-", suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            # 완성된 파일만 게시한다. 기존 기록이 있으면 FileExistsError가 발생한다.
            os.link(temporary, destination)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return destination

    def load(self, execution_id):
        """이전 인스턴스가 저장한 결과도 같은 execution_id로 읽어 반환한다."""
        path = self._path(execution_id)
        if path.is_symlink():
            raise ValueError("history file cannot be a symbolic link")
        if not path.is_file():
            raise FileNotFoundError("execution history not found")
        try:
            record = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, ValueError):
            raise ValueError("invalid execution history JSON") from None
        self._encode(record)
        if record["execution_id"] != execution_id:
            raise ValueError("stored execution_id does not match the requested ID")
        return record
