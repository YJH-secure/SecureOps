"""Receipt-only A/B/D composition; no SSH execution or metadata file writes.

Dependencies are the separately frozen A v2, B collector_entry and D adapter.
The caller has already executed A. This module neither retries that execution
nor calls B directly: the unchanged D adapter owns the single B invocation.
"""
from copy import deepcopy
import re
from uuid import UUID

from integration.a_ssh_transport import b_read_stop_reason, b_read_trusted_context
from integration.bd_collector_adapter import ApprovedProfile, receive_b_collector_result
from collector_entry import CollectorTrustError, judge_collector_output


def _identity(execution):
    execution_id = target_id = None
    if type(execution) is dict:
        value = execution.get("execution_id")
        try:
            if type(value) is str and str(UUID(value)) == value:
                execution_id = value
        except ValueError:
            pass
        value = execution.get("target_id")
        if type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,255}", value):
            target_id = value
    return execution_id, target_id


def _stop(response, layer, stage, code):
    response.update(failure_layer=layer, failure={"stage": stage, "code": code})
    return response


def diagnose_abd_execution(execution, *, profile, store, evidence_ref=None):
    """Apply A's gate, bind approved context, delegate once to the D adapter.

    Return a separate in-memory operational response, not diagnosis JSON.
    id_link is only extracted linkage; no d_link.json or other writer exists.
    integration_success means verified report persistence, never diagnosis pass.
    The caller must supply a trusted ApprovedProfile and private ReportStore.
    """
    execution_id, target_id = _identity(execution)
    response = {"execution_id": execution_id, "target_id": target_id,
                "scan_id": None, "A_stop_reason": None, "failure_layer": None,
                "failure": None, "D_response": None, "integration_success": False,
                "id_link": {"execution_id": execution_id, "target_id": target_id, "scan_id": None}}
    try:
        reason = b_read_stop_reason(execution)
    except Exception:
        return _stop(response, "A", "A_gate", "gate_exception")
    if reason is not None:
        # Only fixed A reason codes are copied, never exception/output text.
        code = reason if type(reason) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason) else "invalid_gate_reason"
        response["A_stop_reason"] = code
        return _stop(response, "A", "A_gate", code)

    try:
        context = b_read_trusted_context(execution["target_id"])
        if type(profile) is not ApprovedProfile:
            raise ValueError("approved profile required")
        proposed = {"host": profile.host, "addr": profile.addr,
                    "os_id": profile.os_id, "os_version": profile.version_id}
        if profile.target_id != execution["target_id"] or proposed != context:
            raise ValueError("approved profile and A context differ")
    except Exception:
        return _stop(response, "D", "profile", "approved_A_profile_mismatch")

    try:
        diagnosis = receive_b_collector_result(
            execution, profile=profile, store=store,
            judge_collector_output=judge_collector_output,
            collector_trust_error=CollectorTrustError, evidence_ref=evidence_ref)
        if type(diagnosis) is not dict:
            raise TypeError("D response required")
    except Exception:
        # A report may already have been published. Never infer absence/retry.
        return _stop(response, "D", "D_response", "response_unavailable")

    response["D_response"] = diagnosis
    response["scan_id"] = diagnosis.get("scan_id")
    response["id_link"]["scan_id"] = response["scan_id"]
    success = (diagnosis.get("integration_success") is True
               and diagnosis.get("report_verified") is True
               and diagnosis.get("save_status") == "success"
               and diagnosis.get("load_status") == "success"
               and diagnosis.get("failure") is None)
    response["integration_success"] = success
    if not success:
        failure = diagnosis.get("failure")
        response["failure_layer"] = "B" if type(failure) is dict and failure.get("code") == "collector_trust_error" else "D"
        response["failure"] = deepcopy(failure) if type(failure) is dict else {
            "stage": "D_response", "code": "unverified_response"}
    return response
