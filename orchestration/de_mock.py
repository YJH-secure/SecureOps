"""MOCK-only D/E composition; existing diagnosis and E contracts are unchanged."""
from copy import deepcopy
import json

from core.storage import ReportStore
from remediation.engine import Remediator, build_plan
from remediation.history import ExecutionHistoryStore
from remediation.mock import MockBackend
from remediation.recheck import MockRecheckAdapter


def _response(target_id=None, before_scan_id=None):
    return {
        "target_id": target_id, "execution_id": None,
        "before_scan_id": before_scan_id, "after_scan_id": None,
        "outcome": None, "recheck_attempts": [], "e_result": None,
        "integration_success": False, "history_saved": False,
        "history_verified": False, "error_stage": None, "errors": [],
        "manual_recovery_required": False, "history_probe": None,
    }


def _error(response, stage, error):
    # Exception messages can contain credentials or paths: retain type only.
    response["error_stage"] = stage
    response["errors"].append({"stage": stage, "kind": type(error).__name__})


def _normal(value):
    return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))


def _verified_after(result):
    scan_id = result.get("after_scan_id")
    if not isinstance(scan_id, str) or not scan_id.strip():
        return False
    attempts = [
        a for a in result.get("recheck_attempts", [])
        if isinstance(a, dict) and a.get("phase") == "after"
    ]
    if len(attempts) != 1:
        return False
    attempt = attempts[0]
    return (
        attempt.get("execution_id") == result.get("execution_id")
        and attempt.get("target_id") == result.get("target_id")
        and attempt.get("check_id") == result.get("check_id")
        and attempt.get("scan_id") == scan_id
        and attempt.get("save_status") == "success"
        and attempt.get("load_status") == "success"
        and attempt.get("report_verified") is True
    )


def _probe_history(store, execution_id, expected):
    # Read-only probe, never retry E.run or history.save.
    try:
        loaded = store.load(execution_id)
        same = _normal(loaded) == expected
        return {"state": "present_equal" if same else "present_different"}
    except FileNotFoundError:
        return {"state": "not_found"}
    except Exception as error:
        return {"state": "unavailable", "kind": type(error).__name__}


def persist_mock_execution_history(result, *, history_store):
    """Persist one existing E result without executing or re-diagnosing anything.

    A duplicate ID is an explicit failure, even when its existing content matches.
    This is a manual-recovery aid, not an automatic retry/idempotency policy.
    """
    response = _response()
    try:
        if type(history_store) is not ExecutionHistoryStore:
            raise TypeError("exact E ExecutionHistoryStore required")
        if not isinstance(result, dict):
            raise TypeError("E result object required")
        expected = _normal(result)
        execution_id = result["execution_id"]
        if not isinstance(execution_id, str) or not execution_id.strip():
            raise ValueError("execution_id required")
        response.update(
            target_id=result["target_id"], execution_id=execution_id,
            before_scan_id=result["before_scan_id"],
            after_scan_id=result.get("after_scan_id"), outcome=result["outcome"],
            recheck_attempts=deepcopy(result.get("recheck_attempts", [])),
            e_result=deepcopy(result),
        )
    except Exception as error:
        _error(response, "history_input", error)
        return response

    try:
        history_store.save(result)
    except Exception as error:
        response["history_saved"] = None
        response["manual_recovery_required"] = True
        _error(response, "history_conflict" if isinstance(error, FileExistsError)
               else "history_save", error)
        response["history_probe"] = _probe_history(history_store, execution_id, expected)
        return response

    response["history_saved"] = True
    try:
        loaded = history_store.load(execution_id)
    except Exception as error:
        response["manual_recovery_required"] = True
        _error(response, "history_load", error)
        return response
    try:
        if _normal(loaded) != expected:
            raise ValueError("execution history mismatch")
    except Exception as error:
        response["manual_recovery_required"] = True
        _error(response, "history_verify", error)
        return response
    response["history_verified"] = True
    response["history_probe"] = {"state": "present_equal"}
    if result.get("outcome") == "failed":
        # A failed operation is never retried automatically, even if its audit
        # record was stored successfully. Keep its ID for manual review.
        response["manual_recovery_required"] = True
        stage = result.get("failed_stage")
        if stage not in {"approval", "preflight", "backup", "apply", "validate", "recheck"}:
            stage = "run"
        response["error_stage"] = "e_" + stage
        response["errors"].append({"stage": "e_" + stage, "kind": "EOutcomeFailed"})
    if result.get("outcome") == "success":
        response["integration_success"] = _verified_after(result)
        if not response["integration_success"]:
            response["manual_recovery_required"] = True
            _error(response, "recheck_verification", ValueError())
    return response


def execute_mock_remediation(
    *, report_store, history_store, remediator, target_id, before_scan_id,
    check_id, approval=None, dry_run=True, backend=None, recheck_adapter=None,
):
    """Load before, build a plan, run E exactly once, then persist its result.

    No live backend, legacy callback, generic post-rollback opt-in, or automatic
    retry is exposed. Q09 keeps the generic False option below; the pinned E
    FILE-01 finish policy independently owns post_restore/post_rollback checks.
    The injected adapter alone owns re-diagnosis and D persistence.
    """
    response = _response(target_id, before_scan_id)
    try:
        if type(report_store) is not ReportStore:
            raise TypeError("exact D ReportStore required")
        if type(history_store) is not ExecutionHistoryStore:
            raise TypeError("exact E history store required")
        if type(remediator) is not Remediator:
            raise TypeError("exact E Remediator required")
        if type(dry_run) is not bool:
            raise TypeError("dry_run must be boolean")
    except Exception as error:
        _error(response, "configuration", error)
        return response

    try:
        before = report_store.load(target_id, before_scan_id)
    except Exception as error:
        _error(response, "before_load", error)
        return response
    try:
        if before.get("schema_version") != "1.2":
            raise ValueError("this MOCK composition profile requires v1.2")
        plan = build_plan(before, check_id)
    except Exception as error:
        _error(response, "plan", error)
        return response
    try:
        if recheck_adapter is not None:
            if (type(recheck_adapter) is not MockRecheckAdapter
                    or recheck_adapter.store is not report_store):
                raise TypeError("exact adapter bound to the same D store required")
        if not dry_run and plan.skip_reason is None:
            if type(backend) is not MockBackend:
                raise TypeError("live remediation is disabled")
            if type(recheck_adapter) is not MockRecheckAdapter:
                raise TypeError("v1.2 MOCK adapter required")
    except Exception as error:
        _error(response, "configuration", error)
        return response
    try:
        result = remediator.run(
            before, plan, backend=backend, approval=approval, dry_run=dry_run,
            recheck_adapter=recheck_adapter, post_rollback_recheck=False,
        )
    except Exception as error:
        # E might already have acted: never invent a new ID or automatically run again.
        response["manual_recovery_required"] = True
        _error(response, "e_run", error)
        return response
    try:
        if (
            result["target_id"] != target_id
            or result["before_scan_id"] != before_scan_id
            or result["check_id"] != check_id
            or result["plan_id"] != plan.plan_id
        ):
            raise ValueError("E result binding mismatch")
    except Exception as error:
        response["e_result"] = deepcopy(result)
        response["manual_recovery_required"] = True
        _error(response, "e_result_binding", error)
        return response
    return persist_mock_execution_history(result, history_store=history_store)
