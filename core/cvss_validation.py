"""Runtime JSON v1.2 contract validation, separate from the v1.1 validator.

Mirrors the adopted schema and adds computed score/rating, uniqueness,
timestamp semantics, strict JSON types and decimal-tenth checks.
"""

from decimal import Decimal
import json
import math

from core.cvss import base_score, rating


STATUSES = {"pass", "vulnerable", "error", "not_applicable", "needs_review"}


def validate_json_value(value):
    """JSON-native values only. Reject cycles, nonfinite numbers and Python coercions."""
    active = set()

    def visit(item):
        if type(item) in (dict, list):
            if id(item) in active:
                raise ValueError("Circular JSON value")
            active.add(id(item))
            if type(item) is dict:
                if any(type(key) is not str for key in item):
                    raise TypeError("JSON object keys must be strings")
                children = item.values()
            else:
                children = item
            for child in children:
                visit(child)
            active.remove(id(item))
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("Nonfinite JSON number")
        elif item is not None and type(item) not in (str, bool, int):
            raise TypeError("Non-JSON value")
    try:
        visit(value)
    except RecursionError:
        raise ValueError("JSON nesting is too deep") from None


def loads_strict(text):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj

    def reject(_):
        raise ValueError("Nonstandard JSON number")

    try:
        value = json.loads(text, object_pairs_hook=unique, parse_constant=reject)
    except RecursionError:
        raise ValueError("JSON nesting is too deep") from None
    validate_json_value(value)
    return value


def validate_cvss(cvss, status, fields):
    if not isinstance(cvss, dict):
        raise TypeError("cvss must be an object")
    required = {"assessment_status", "version", "vector", "base_score", "rating", "source", "rationale"}
    if set(cvss) != required:
        raise ValueError("cvss requires exactly the seven v1.2 fields")
    fields(cvss, {"assessment_status": str, "rationale": str}, {}, "cvss")
    assessment = cvss["assessment_status"]
    if assessment not in {"scored", "pending", "not_applicable"}:
        raise ValueError("Invalid CVSS assessment_status")
    if status != "vulnerable" and assessment != "not_applicable":
        raise ValueError("Only vulnerable results may be scored or pending")
    source = cvss["source"]
    if source is not None and not isinstance(source, str):
        raise TypeError("CVSS source must be string or null")
    if not cvss["rationale"].strip():
        raise ValueError("CVSS rationale must include a reason")
    if assessment != "scored":
        if any(cvss[key] is not None for key in ("version", "vector", "base_score", "rating")):
            raise ValueError("Unscored CVSS values must remain null")
        return
    if cvss["version"] != "3.1":
        raise ValueError("Only CVSS version 3.1 is supported")
    if not source or not source.strip():
        raise ValueError("Scored CVSS requires a source")
    score = cvss["base_score"]
    if type(score) not in (int, float):
        raise TypeError("CVSS base_score must be numeric, never bool or null")
    if not 0 <= score <= 10 or not math.isfinite(score):
        raise ValueError("CVSS base_score outside 0..10")
    # JSON numbers 9 and 9.0 are equivalent; precision is numeric, not lexical.
    decimal = Decimal(str(score))
    if decimal * 10 != (decimal * 10).to_integral_value():
        raise ValueError("CVSS base_score must be in decimal tenths")
    calculated = base_score(cvss["vector"])
    if score != calculated:
        raise ValueError("CVSS vector and base_score disagree")
    if cvss["rating"] != rating(calculated):
        raise ValueError("CVSS base_score and rating disagree")


def validate_report(data):
    # Local import avoids coupling the unchanged v1.1 validation body to this module.
    from core.main import DiagnosisAggregator
    fields = DiagnosisAggregator._validate_fields
    timestamp = DiagnosisAggregator._validate_timestamp
    validate_json_value(data)
    fields(data, {"schema_version": str, "scan_id": str, "target_id": str,
                  "os": str, "scanned_at": str, "results": list},
           {"ip_address": str}, "report", reject_extra=True)
    if data["schema_version"] != "1.2":
        raise ValueError("Expected JSON v1.2")
    timestamp(data["scanned_at"], "scanned_at")
    if not data["results"]:
        raise ValueError("results must not be empty")
    seen = set()
    for index, item in enumerate(data["results"]):
        location = f"results[{index}]"
        fields(item, {"check_id": str, "status": str, "evidence": str,
                      "recommendation": str, "cvss": dict},
               {"category": str, "title": str, "checked_at": str, "details": dict},
               location, reject_extra=True)
        if item["status"] not in STATUSES:
            raise ValueError("Invalid diagnosis status")
        if item["check_id"] in seen:
            raise ValueError("Duplicate check_id")
        seen.add(item["check_id"])
        if "checked_at" in item:
            timestamp(item["checked_at"], location + ".checked_at")
        validate_cvss(item["cvss"], item["status"], fields)
