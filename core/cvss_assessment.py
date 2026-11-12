"""Explicit D-internal assessment boundary; not a B/C or SSH transport contract.

The caller supplies applicability and a human-reviewed sufficiency decision.
Nonempty prose alone cannot prove that a CVSS metric is correct. This helper
never infers a vector, CVE, applicability or score from severity/check_id.
The adopted JSON v1.2 policy/schema are unchanged.
"""

from core.cvss import METRICS, base_score, parse_vector, rating
from core.cvss_validation import STATUSES


def assess_cvss(*, status, cvss_applicable, rationale, source=None,
                vector=None, metric_evidence=None, evidence_sufficient=False):
    """Build a v1.2 cvss object without mutating diagnosis or evidence inputs.

    cvss_applicable is an explicit caller classification. evidence_sufficient
    defaults to False: presence of a vector/evidence is not approval to score.
    Missing prerequisites produce pending, not a guessed or zero score.
    Supplied malformed values are errors, never silently repaired.
    """
    if not isinstance(status, str) or status not in STATUSES:
        raise ValueError("Invalid diagnosis status")
    if type(cvss_applicable) is not bool or type(evidence_sufficient) is not bool:
        raise TypeError("Applicability and evidence sufficiency must be explicit bool values")
    if not isinstance(rationale, str) or not rationale.strip():
        raise ValueError("An explicit assessment reason is required")
    if source is not None and (not isinstance(source, str) or not source.strip()):
        raise ValueError("Supplied source must be a nonempty string")
    if vector is not None:
        parse_vector(vector)
    if metric_evidence is None:
        metric_evidence = {}
    if not isinstance(metric_evidence, dict):
        raise TypeError("metric_evidence must be a mapping")
    if set(metric_evidence) - METRICS.keys():
        raise ValueError("Unknown evidence metric")
    for value in metric_evidence.values():
        if value is not None and not isinstance(value, str):
            raise TypeError("Each supplied metric reason must be text or None")

    result = {"assessment_status": "not_applicable", "version": None,
              "vector": None, "base_score": None, "rating": None,
              "source": source, "rationale": rationale}
    if status != "vulnerable" or not cvss_applicable:
        if cvss_applicable and status != "vulnerable":
            raise ValueError("Only vulnerable diagnoses may be CVSS-applicable")
        if vector is not None or metric_evidence or evidence_sufficient:
            raise ValueError("Nonapplicable assessments must not carry scoring inputs")
        return result

    missing = []
    if vector is None:
        missing.append("vector")
    if source is None:
        missing.append("source")
    incomplete = [name for name in METRICS if not (metric_evidence.get(name) or "").strip()]
    if incomplete:
        missing.append("metric evidence: " + ", ".join(incomplete))
    if not evidence_sufficient:
        missing.append("explicit evidence sufficiency review")
    if missing:
        result.update(assessment_status="pending",
                      rationale=rationale + "\nPending prerequisites: " + "; ".join(missing))
        return result

    score = base_score(vector)
    result.update(assessment_status="scored", version="3.1", vector=vector,
                  base_score=score, rating=rating(score),
                  rationale=rationale + "\n" + "\n".join(
                      f"{name}: {metric_evidence[name]}" for name in METRICS))
    return result
