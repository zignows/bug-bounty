"""CVSS v3.1 base score — computed deterministically, never guessed.

Severity is *calculated* from the vector per the official FIRST.org v3.1
equations (constants, impact/exploitability, and the exact Roundup
function), so a finding's score can't be an LLM's opinion. Base metrics
only; temporal/environmental metrics, if present in a vector, are ignored.

Reference: FIRST CVSS v3.1 Specification, section 7 (metric values) and
section 8.1 (base equations), including the Appendix Roundup definition.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_ALLOWED = {
    "AV": set(_AV), "AC": set(_AC), "PR": {"N", "L", "H"},
    "UI": set(_UI), "S": {"U", "C"},
    "C": set(_CIA), "I": set(_CIA), "A": set(_CIA),
}


class CvssError(ValueError):
    pass


@dataclass(frozen=True)
class CvssResult:
    base_score: float
    severity: str
    vector: str


def roundup(value: float) -> float:
    """The official CVSS v3.1 Roundup: smallest one-decimal number >= value,
    computed in a float-safe way (spec Appendix A)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def severity_rating(score: float) -> str:
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into its base metrics.

    Accepts an optional 'CVSS:3.1/' prefix. Extra (temporal/environmental)
    metrics are ignored. Raises CvssError on a missing or invalid base
    metric.
    """
    tokens = [t for t in vector.strip().split("/") if t]
    metrics: dict[str, str] = {}
    for tok in tokens:
        if ":" not in tok:
            raise CvssError(f"malformed token: {tok!r}")
        key, _, val = tok.partition(":")
        key, val = key.strip().upper(), val.strip().upper()
        if key == "CVSS":
            if val not in ("3.1", "3.0"):
                raise CvssError(f"unsupported CVSS version: {val!r}")
            continue
        metrics[key] = val
    out: dict[str, str] = {}
    for m in _BASE_METRICS:
        if m not in metrics:
            raise CvssError(f"missing base metric {m}")
        if metrics[m] not in _ALLOWED[m]:
            raise CvssError(f"invalid value for {m}: {metrics[m]!r}")
        out[m] = metrics[m]
    return out


def base_score_from_metrics(m: dict[str, str]) -> float:
    scope_changed = m["S"] == "C"
    pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED

    iss = 1 - ((1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]]))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    exploitability = (
        8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr_table[m["PR"]] * _UI[m["UI"]]
    )

    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def score_vector(vector: str) -> CvssResult:
    metrics = parse_vector(vector)
    score = base_score_from_metrics(metrics)
    return CvssResult(base_score=score, severity=severity_rating(score), vector=vector)
