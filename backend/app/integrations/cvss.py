"""CVSS v3.x base score from a vector string (FIRST CVSS v3.1 specification, section 7).

Dependency-Track only returns `cvssV3BaseScore` for some sources: advisories mirrored
from OSV/GitHub arrive with the vector alone. The severity policy (FR-4.1) is written in
CVSS bands, so a missing score would drop a Critical RCE into the catch-all rule. The
base score is a pure function of the vector, so it is computed here rather than guessed.

CVSS v4.0 scoring depends on a large macro-vector lookup table and is deliberately not
implemented; a v4-only vector yields None and the policy's non-CVSS rules still apply.
"""

import math

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
# Privileges Required depends on whether Scope changed.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _round_up(value: float) -> float:
    """The spec's Roundup: smallest number, to one decimal, >= value, computed on
    integers to avoid floating-point artefacts (e.g. 4.000001 -> 4.1 must not happen)."""
    as_int = round(value * 100_000)
    if as_int % 10_000 == 0:
        return as_int / 100_000.0
    return (math.floor(as_int / 10_000) + 1) / 10.0


def base_score_from_vector(vector: str | None) -> float | None:
    """Returns the CVSS v3.0/v3.1 base score, or None for anything that is not a
    complete, well-formed v3 vector."""
    if not vector or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        metrics[key] = value

    try:
        scope_changed = metrics["S"] == "C"
        if metrics["S"] not in ("C", "U"):
            return None
        av = _WEIGHTS["AV"][metrics["AV"]]
        ac = _WEIGHTS["AC"][metrics["AC"]]
        ui = _WEIGHTS["UI"][metrics["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        c = _WEIGHTS["C"][metrics["C"]]
        i = _WEIGHTS["I"][metrics["I"]]
        a = _WEIGHTS["A"][metrics["A"]]
    except KeyError:
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    if scope_changed:
        return _round_up(min(1.08 * (impact + exploitability), 10))
    return _round_up(min(impact + exploitability, 10))
