"""Provisional D receipt boundary for b_read_v1; no transport or B judgment.

The caller supplies trusted approval/context and the provided B collector_entry
function. Raw bytes are forwarded unchanged; B owns judgment. No operational
metadata is written here and this module implements no SSH transport.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import re
import shlex
from uuid import UUID

from core.cvss_validation import loads_strict, validate_json_value
from core.main import DiagnosisAggregator
from core.remote_result import parse_result_json
from core.storage import ReportStore


CHECK_IDS = frozenset({"SSH-02", "ACC-01", "ACC-02"})
STDOUT_LIMIT = 1024 * 1024
STDERR_LIMIT = 64 * 1024
LIMITS = {"connect_timeout_seconds": 10, "total_timeout_seconds": 60,
          "stdout_max_bytes": STDOUT_LIMIT, "stderr_max_bytes": STDERR_LIMIT,
          "max_retries": 0}


@dataclass(frozen=True)
class ApprovedProfile:
    """Caller-approved values, never derived from untrusted collector output.

    Constructing this object is not approval authentication. Host/addr describe
    the SSH-02 Match context, not necessarily the target management address.
    """
    target_id: str
    host: str
    addr: str
    os_id: str
    version_id: str
    report_os: str


class _Stop(Exception):
    def __init__(self, code):
        self.code = code


def _require(condition, code):
    if not condition:
        raise _Stop(code)


def _validate_profile(profile):
    _require(type(profile) is ApprovedProfile, "approved_profile_required")
    for field in ("target_id", "host", "addr", "os_id", "version_id", "report_os"):
        value = getattr(profile, field)
        _require(type(value) is str and bool(value) and len(value) <= 255,
                 "invalid_approved_profile")
        _require(re.fullmatch(r"[A-Za-z0-9_.:-]+", value) is not None,
                 "invalid_approved_profile")
    ipaddress.ip_address(profile.addr)
    _require(profile.report_os == profile.os_id + "-" + profile.version_id,
             "approved_os_mapping_mismatch")


def _observed_os(payload):
    record = payload.get("os_release")
    _require(type(record) is dict and record.get("state") == "ok"
             and type(record.get("text")) is str, "os_observation_unavailable")
    # A file record normally has no exit_code. Never coerce an explicit value.
    if "exit_code" in record:
        _require(type(record["exit_code"]) is int and record["exit_code"] == 0,
                 "os_observation_failed")
    for key in ("timeout", "truncated"):
        if key in record:
            _require(record[key] is False, "os_observation_failed")
    values = {}
    for line in record["text"].splitlines():
        key, separator, value = line.partition("=")
        if separator and key in ("ID", "VERSION_ID"):
            _require(key not in values, "ambiguous_os_observation")
            tokens = shlex.split(value, comments=True, posix=True)
            _require(len(tokens) == 1 and bool(tokens[0]), "invalid_os_observation")
            values[key] = tokens[0]
    _require(set(values) == {"ID", "VERSION_ID"}, "incomplete_os_observation")
    return values["ID"], values["VERSION_ID"]


def receive_b_collector_result(execution, *, profile, store,
                               judge_collector_output, collector_trust_error,
                               evidence_ref=None):
    """Inject judge(raw_stdout, trusted_context, *, result_version='1.2').

    B returns a check_id -> result mapping. D checks its exact keys and each
    embedded check_id before passing the three values to unchanged D APIs.

    A-like execution envelope: execution_id/target_id/operation/stdout/stderr/
    metadata. Operation is b_read_v1; metadata requires limits, exit_code,
    execution_succeeded/timeout/truncated, stdout_bytes/stderr_bytes. Extra
    metadata is ignored, not persisted or treated as verified. No FILE-01
    preflight attestation is repurposed as a B approval.

    Return a separate operational response. Success means receipt+roundtrip,
    never diagnosis pass. Failure records are an in-memory proposal; A owns
    durable execution_id--scan_id linkage and recovery. Do not automatically
    rerun judgment, save, load, or transport after any uncertain failure.
    """
    response = dict(execution_id=None, target_id=None, scan_id=None,
                    scanned_at=None, save_status="not_attempted",
                    load_status="not_attempted", report_verified=False,
                    integration_success=False, saved_path=None, report=None,
                    summary=None, failure=None)
    stage = "input"
    collector_failure = None
    try:
        _require(type(execution) is dict, "execution_object_required")
        execution_id = execution.get("execution_id")
        _require(type(execution_id) is str and str(UUID(execution_id)) == execution_id,
                 "invalid_execution_id")
        response["execution_id"] = execution_id
        _validate_profile(profile)
        response["target_id"] = profile.target_id
        _require(evidence_ref is None or (type(evidence_ref) is str and
                 re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", evidence_ref)),
                 "invalid_evidence_reference")
        _require(callable(judge_collector_output), "b_judge_required")
        _require(isinstance(collector_trust_error, type) and
                 issubclass(collector_trust_error, Exception) and
                 collector_trust_error is not Exception, "b_trust_error_type_required")
        _require(isinstance(store, ReportStore), "report_store_required")

        stage = "identity"
        _require(type(execution.get("target_id")) is str and
                 execution["target_id"] == profile.target_id, "target_mismatch")
        _require(execution.get("operation") == "b_read_v1", "operation_mismatch")
        stage = "metadata"
        meta = execution.get("metadata")
        _require(type(meta) is dict, "metadata_required")
        limits = meta.get("limits")
        _require(type(limits) is dict and all(type(limits.get(k)) is int
                 and limits[k] == v for k, v in LIMITS.items()), "limit_contract_mismatch")
        for key in ("execution_succeeded", "timeout", "truncated"):
            _require(type(meta.get(key)) is bool, "explicit_boolean_required")
        for key in ("stdout_bytes", "stderr_bytes"):
            _require(type(meta.get(key)) is int and meta[key] >= 0, "invalid_byte_count")
        stage = "transport"
        _require(not meta["timeout"], "timeout")
        _require(not meta["truncated"], "truncated")
        _require(meta["execution_succeeded"], "execution_failed")
        _require(type(meta.get("exit_code")) is int and meta["exit_code"] == 0,
                 "unconfirmed_or_nonzero_exit")
        stdout, stderr = execution.get("stdout"), execution.get("stderr")
        _require(type(stdout) is bytes and type(stderr) is bytes, "raw_bytes_required")
        _require(len(stdout) <= STDOUT_LIMIT and meta["stdout_bytes"] <= STDOUT_LIMIT,
                 "stdout_limit_exceeded")
        _require(len(stderr) <= STDERR_LIMIT and meta["stderr_bytes"] <= STDERR_LIMIT,
                 "stderr_limit_exceeded")
        _require(meta["stdout_bytes"] == len(stdout) and
                 meta["stderr_bytes"] == len(stderr), "byte_count_mismatch")
        _require(not stderr, "nonempty_stderr")
        stage = "decode"
        text = stdout.decode("utf-8", errors="strict")
        stage = "envelope"
        _require(len(text.splitlines()) == 1, "one_line_json_required")
        document = loads_strict(text)
        _require(type(document) is dict and set(document) ==
                 {"collector", "context_used", "payloads"}, "invalid_envelope")
        collector = document["collector"]
        _require(type(collector) is dict and set(collector) ==
                 {"name", "version", "elapsed_ms"}, "invalid_collector")
        _require(collector["name"] == "secureops-b-read" and
                 collector["version"] == "0.1-draft" and
                 type(collector["elapsed_ms"]) is int and collector["elapsed_ms"] >= 0,
                 "invalid_collector")
        payloads = document["payloads"]
        _require(type(payloads) is dict and set(payloads) == CHECK_IDS and
                 all(type(v) is dict for v in payloads.values()), "invalid_payload_set")
        stage = "context"
        context = {"host": profile.host, "addr": profile.addr}
        _require(type(document["context_used"]) is dict and
                 document["context_used"] == context, "context_mismatch")
        stage = "os"
        for check_id in ("ACC-01", "ACC-02"):
            _require(_observed_os(payloads[check_id]) ==
                     (profile.os_id, profile.version_id), "os_mismatch")
        stage = "judge"
        trusted_context = {"host": profile.host, "addr": profile.addr,
                           "os_id": profile.os_id, "os_version": profile.version_id}
        try:
            results = judge_collector_output(stdout, trusted_context, result_version="1.2")
        except collector_trust_error as error:
            # Preserve B's bounded reason codes, never the exception message.
            b_stage = getattr(error, "stage", None)
            b_reason = getattr(error, "reason", None)
            if (type(b_stage) is str and b_stage in ("decode", "structure", "context", "os")
                    and type(b_reason) is str and
                    re.fullmatch(r"[a-z][a-z0-9_]{0,63}", b_reason)):
                collector_failure = {"stage": b_stage, "reason": b_reason}
            raise _Stop("collector_trust_error") from None
        stage = "results"
        validate_json_value(results)
        _require(type(results) is dict and set(results) == CHECK_IDS, "invalid_result_set")
        _require(all(type(result) is dict and type(result.get("check_id")) is str
                     and result["check_id"] == check_id for check_id, result in results.items()),
                 "result_check_id_mismatch")
        items = [parse_result_json(json.dumps(r, ensure_ascii=False, allow_nan=False),
                 exit_code=0, execution_succeeded=True, schema_version="1.2")
                 for r in (results[k] for k in ("SSH-02", "ACC-01", "ACC-02"))]
        stage = "aggregate"
        aggregator = DiagnosisAggregator.from_results(
            account_results=items, system_results=[], target_id=profile.target_id,
            os=profile.report_os, schema_version="1.2")
        report = aggregator.get_report()
        response.update(scan_id=report["scan_id"], scanned_at=report["scanned_at"],
                        report=report, summary=aggregator.aggregate_results())
        stage = "save"
        response["save_status"] = "unconfirmed"
        path = store.save(deepcopy(report))
        response.update(save_status="success", saved_path=str(path))
        stage = "load"
        response["load_status"] = "attempted"
        loaded = store.load(profile.target_id, report["scan_id"])
        response["load_status"] = "success"
        stage = "verify"
        _require(loaded == report, "report_mismatch")
        response.update(report_verified=True, integration_success=True)
    except Exception as error:
        if stage == "load":
            response["load_status"] = "failed"
        code = error.code if isinstance(error, _Stop) else stage + "_failed"
        # Do not copy exception messages, stdout, stderr, context or local paths.
        response["failure"] = {
            "execution_id": response["execution_id"], "stage": stage, "code": code,
            "reason": "Receipt stopped; inspect restricted execution evidence.",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "evidence_ref": evidence_ref if type(evidence_ref) is str and
                re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", evidence_ref) else None,
        }
        if collector_failure is not None:
            response["failure"]["collector_trust"] = collector_failure
    return response
