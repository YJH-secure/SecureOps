"""FIRST CVSS v3.1 Base only; SecureOps canonical metric order.

Formula/weights: https://www.first.org/cvss/v3-1/specification-document
Sections 7.1, 7.4 and Appendix A. No policy-priority/severity conversion.
"""

import math


METRICS = {"AV": "NALP", "AC": "LH", "PR": "NLH", "UI": "NR",
           "S": "UC", "C": "NLH", "I": "NLH", "A": "NLH"}
RATINGS = ("none", "low", "medium", "high", "critical")


def parse_vector(vector: str) -> dict:
    """Reject non-Base metrics and noncanonical order rather than repairing input."""
    if not isinstance(vector, str):
        raise TypeError("CVSS vector must be a string")
    parts = vector.split("/")
    if len(parts) != 9 or parts[0] != "CVSS:3.1":
        raise ValueError("Expected CVSS:3.1 and eight Base metrics")
    result = {}
    for expected, part in zip(METRICS, parts[1:]):
        pair = part.split(":")
        if len(pair) != 2 or pair[0] != expected or pair[1] not in METRICS[expected]:
            raise ValueError("Invalid, duplicate, missing or noncanonical Base metric")
        if len(pair[1]) != 1:
            raise ValueError("Invalid Base metric value")
        result[pair[0]] = pair[1]
    return result


def roundup(value: float) -> float:
    """FIRST Appendix A: nearest integer at 1e5, then integer tenth ceiling."""
    if type(value) not in (int, float) or not 0 <= value <= 10 or not math.isfinite(value):
        raise ValueError("Roundup expects a finite number from 0 to 10")
    scaled = math.floor(value * 100000 + 0.5)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (scaled // 10000 + 1) / 10.0


def base_score(vector: str) -> float:
    metrics = parse_vector(vector)
    av = {"N": .85, "A": .62, "L": .55, "P": .2}[metrics["AV"]]
    ac = {"L": .77, "H": .44}[metrics["AC"]]
    changed = metrics["S"] == "C"
    pr = {"N": .85, "L": .68 if changed else .62,
          "H": .5 if changed else .27}[metrics["PR"]]
    ui = {"N": .85, "R": .62}[metrics["UI"]]
    impact_values = {"N": 0, "L": .22, "H": .56}
    c, i, a = (impact_values[metrics[key]] for key in ("C", "I", "A"))
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
              if changed else 6.42 * iss)
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    return roundup(min((1.08 if changed else 1) * (impact + exploitability), 10))


def rating(score: float) -> str:
    if type(score) not in (int, float) or not 0 <= score <= 10 or not math.isfinite(score):
        raise ValueError("CVSS score must be a finite number from 0 to 10")
    if score == 0:
        return "none"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"
