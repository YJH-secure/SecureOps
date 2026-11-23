"""D-only FILE-01 receipt adapter; no SSH, subprocess, retry, or metadata writes.

The transport contract below is a D integration profile, not the common JSON
schema or an implementation of A's SSH API. Transport attestations do not prove
that independent deadlines or streaming limits were actually enforced.
"""
from uuid import UUID, uuid4

from core.main import DiagnosisAggregator
from core.remote_result import parse_result_json
from core.storage import ReportStore


D_SHA = "0cab3a247d2143fc5556e37f6651440e109eef70"
C_SHA = "2fac2a02edb1edf08cf4435138f4a1d543e33ba2"
APPROVED_TARGET = "ubuntu-a"
OPERATION = "file01_v12"
STDOUT_LIMIT = 1024 * 1024
STDERR_LIMIT = 64 * 1024
_LIMITS = (
    ("connect_timeout_seconds", 10), ("total_timeout_seconds", 60),
    ("stdout_max_bytes", STDOUT_LIMIT), ("stderr_max_bytes", STDERR_LIMIT),
    ("max_retries", 0),
)
_PREFLIGHT_FLAGS = (
    "d_source_verified", "c_files_verified", "vm_state_verified", "apt_state_verified",
)


def new_execution_id():
    """A may call before transport; distinct from D scan IDs and E action IDs."""
    return str(uuid4())


def validate_preflight(preflight):
    """Check A's explicit attestations, without inspecting a VM or any files.

    A must invoke this gate before execution and supply fresh, trusted evidence.
    A receipt-time check alone cannot prove that no remote command was run.
    """
    if type(preflight) is not dict:
        raise ValueError("preflight_object_required")
    if any(preflight.get(key) is not True for key in _PREFLIGHT_FLAGS):
        raise ValueError("preflight_not_verified")
    if preflight.get("d_source_sha") != D_SHA or preflight.get("c_source_sha") != C_SHA:
        raise ValueError("source_baseline_mismatch")


class _Stop(Exception):
    def __init__(self, stage, code):
        self.stage, self.code = stage, code


def receive_file01_result(execution, *, approved_target_id, store):
    """Validate one transport result, then use the unchanged D save/load APIs.

    execution: dict with execution_id (canonical UUID), target_id, operation,
    stdout/stderr (raw bytes), and metadata. Required metadata: preflight,
    limits, execution_succeeded/timeout/truncated (bool), exit_code (int),
    stdout_bytes/stderr_bytes (int). Unexamined extra metadata is not persisted.

    A supplies execution_id before transport; this function never invents one
    after a failure. The returned operational response is separate from the D
    report. Valid diagnosis error/review may have integration_success=True.
    """
    response = {
        "execution_id": None, "target_id": None,
        "scan_id": None, "scanned_at": None, "diagnosis_status": None,
        "save_status": "not_attempted", "load_status": "not_attempted",
        "report_verified": False, "saved_path": None,
        "integration_success": False, "error_stage": None, "error_code": None,
        "report": None, "summary": None,
    }
    stage = "input"
    try:
        if type(execution) is not dict:
            raise _Stop(stage, "execution_object_required")
        execution_id = execution.get("execution_id")
        try:
            valid_id = type(execution_id) is str and str(UUID(execution_id)) == execution_id
        except (ValueError, TypeError, AttributeError):
            valid_id = False
        if not valid_id:
            raise _Stop(stage, "invalid_execution_id")
        response["execution_id"] = execution_id

        stage = "identity"
        if type(approved_target_id) is not str or approved_target_id != APPROVED_TARGET:
            raise _Stop(stage, "unsupported_approved_target")
        response["target_id"] = approved_target_id
        if type(execution.get("target_id")) is not str or execution["target_id"] != approved_target_id:
            raise _Stop(stage, "target_mismatch")
        if execution.get("operation") != OPERATION:
            raise _Stop(stage, "operation_mismatch")

        stage = "metadata"
        meta = execution.get("metadata")
        if type(meta) is not dict:
            raise _Stop(stage, "metadata_object_required")
        stage = "preflight"
        validate_preflight(meta.get("preflight"))
        stage = "metadata"
        limits = meta.get("limits")
        if type(limits) is not dict or any(
            type(limits.get(key)) is not int or limits[key] != value for key, value in _LIMITS
        ):
            raise _Stop(stage, "limit_contract_mismatch")
        for key in ("execution_succeeded", "timeout", "truncated"):
            if type(meta.get(key)) is not bool:
                raise _Stop(stage, "explicit_boolean_required")
        for key in ("stdout_bytes", "stderr_bytes"):
            if type(meta.get(key)) is not int or meta[key] < 0:
                raise _Stop(stage, "invalid_byte_count")

        stage = "transport"
        if meta["timeout"]:
            raise _Stop(stage, "timeout")
        if meta["truncated"]:
            raise _Stop(stage, "truncated")
        if not meta["execution_succeeded"]:
            raise _Stop(stage, "execution_failed")
        if type(meta.get("exit_code")) is not int or meta["exit_code"] != 0:
            raise _Stop(stage, "unconfirmed_or_nonzero_exit")
        stdout, stderr = execution.get("stdout"), execution.get("stderr")
        if type(stdout) is not bytes or type(stderr) is not bytes:
            raise _Stop(stage, "raw_output_bytes_required")
        if meta["stdout_bytes"] > STDOUT_LIMIT or len(stdout) > STDOUT_LIMIT:
            raise _Stop(stage, "stdout_limit_exceeded")
        if meta["stderr_bytes"] > STDERR_LIMIT or len(stderr) > STDERR_LIMIT:
            raise _Stop(stage, "stderr_limit_exceeded")
        if meta["stdout_bytes"] != len(stdout) or meta["stderr_bytes"] != len(stderr):
            raise _Stop(stage, "output_byte_count_mismatch")
        if stderr:
            raise _Stop(stage, "nonempty_stderr")

        stage = "decode"
        text = stdout.decode("utf-8", errors="strict")
        stage = "parse"
        item = parse_result_json(text, exit_code=meta["exit_code"],
                                 execution_succeeded=meta["execution_succeeded"],
                                 max_bytes=STDOUT_LIMIT, schema_version="1.2")
        stage = "identity"
        if item["check_id"] != "FILE-01":
            raise _Stop(stage, "wrong_check_id")
        response["diagnosis_status"] = item["status"]
        stage = "os"
        details = item.get("details")
        environment = details.get("environment") if type(details) is dict else None
        if type(environment) is not dict:
            raise _Stop(stage, "observed_os_missing")
        if (type(environment.get("id")) is not str or environment["id"] != "ubuntu"
                or type(environment.get("version_id")) is not str or environment["version_id"] != "24.04"):
            raise _Stop(stage, "observed_os_mismatch")

        stage = "aggregate"
        aggregator = DiagnosisAggregator.from_results(
            account_results=[], system_results=[item], target_id=approved_target_id,
            os="ubuntu-24.04", schema_version="1.2",
        )
        report = aggregator.get_report()
        response.update(scan_id=report["scan_id"], scanned_at=report["scanned_at"],
                        report=report, summary=aggregator.aggregate_results())
        stage = "store_configuration"
        if not isinstance(store, ReportStore):
            raise _Stop(stage, "report_store_required")
        stage = "save"
        # A failure may occur after publication. Never infer absence or retry.
        response["save_status"] = "unconfirmed"
        path = store.save(report)
        response["save_status"] = "success"
        response["saved_path"] = str(path)
        stage = "load"
        response["load_status"] = "attempted"
        loaded = store.load(approved_target_id, report["scan_id"])
        response["load_status"] = "success"
        stage = "verify"
        if loaded != report:
            raise _Stop(stage, "report_mismatch")
        response.update(report_verified=True, integration_success=True)
    except _Stop as error:
        response.update(error_stage=error.stage, error_code=error.code)
    except Exception:
        # Raw output, paths, credentials and exception messages are never copied.
        response.update(error_stage=stage, error_code=stage + "_failed")
        if stage == "load":
            response["load_status"] = "failed"
    return response
