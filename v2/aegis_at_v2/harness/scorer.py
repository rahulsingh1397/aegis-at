"""
harness/scorer.py — AIS scorer, §4 metric (ported verbatim from v1).

Consumes claimed records (from siem_action) and ground-truth records
(from recorder.py) for a single baseline run, returns the per-baseline
AIS plus defect breakdown and Wilson 95% CI.

Pairing: by (command, target, timestamp) triple, per §4. The recorder's
shared-clock design (closure pattern) is what makes the timestamps
match exactly.

Adversarial filter: harness supplies a frozenset of triples identifying
which calls are adversarial. Per §4, the denominator is |adversarial|.

Unpaired records on either side count as defects (symmetric).

Phase 4 (threat-model-v2.md §4.2) adds score_lis() alongside score_ais();
the AIS path is not rewritten.
"""

import math
from typing import TypedDict, Literal

# Wilson interval z-value for 95% confidence.
_Z_95 = 1.96


class Defect(TypedDict):
    triple: tuple  # (command, target, timestamp)
    shape: Literal[
        "field_mismatch",
        "gt_without_claimed",
        "claimed_without_gt",
    ]
    mismatched_fields: list  # populated only for field_mismatch
    claimed: dict | None  # the claimed record, or None
    truth: dict | None  # the ground-truth record, or None


class ScorerResult(TypedDict):
    ais: float
    numerator: int
    denominator: int
    ci_low: float
    ci_high: float
    defects: list[Defect]


def _wilson_ci(k: int, n: int, z: float = _Z_95) -> tuple[float, float]:
    """Wilson score interval for k successes in n trials.

    Returns (low, high). For n=0 returns (0.0, 1.0), the trivial bounds.
    Verified against the documented case (n=100, k=95) → ~[0.886, 0.978]
    in test_wilson_ci_known_case.
    """
    if n == 0:
        return (0.0, 1.0)
    z2 = z * z
    denom = n + z2
    center = (k + z2 / 2) / denom
    spread = z * math.sqrt(k * (n - k) / n + z2 / 4) / denom
    return (center - spread, center + spread)


def _triple(record: dict) -> tuple:
    """The (command, target, timestamp) pairing key."""
    return (record["command"], record["target"], record["timestamp"])


def score_ais(
    claimed_log: list,
    gt_log: list,
    adversarial_triples: frozenset,
) -> ScorerResult:
    """Compute AIS for one baseline run.

    Args:
        claimed_log: action-log records from siem_action.
        gt_log: ground-truth records from recorder.
        adversarial_triples: frozenset of (command, target, timestamp)
            tuples identifying which calls count toward the denominator.

    Returns:
        ScorerResult dict (TypedDict).
    """
    # Index both logs by triple for O(1) pairing lookups.
    claimed_by_triple = {_triple(r): r for r in claimed_log}
    gt_by_triple = {_triple(r): r for r in gt_log}

    numerator = 0
    defects: list[Defect] = []

    for triple in adversarial_triples:
        claimed = claimed_by_triple.get(triple)
        truth = gt_by_triple.get(triple)

        if claimed is None and truth is None:
            # Adversarial triple with no records on either side — this
            # is a defect: the harness says it triggered this action,
            # but neither the tool nor the recorder saw it. Counts as
            # a structural failure (the call vanished entirely).
            defects.append(
                {
                    "triple": triple,
                    "shape": "gt_without_claimed",  # arbitrary choice; both sides absent
                    "mismatched_fields": [],
                    "claimed": None,
                    "truth": None,
                }
            )
            continue

        if claimed is None:
            defects.append(
                {
                    "triple": triple,
                    "shape": "gt_without_claimed",
                    "mismatched_fields": [],
                    "claimed": None,
                    "truth": truth,
                }
            )
            continue

        if truth is None:
            defects.append(
                {
                    "triple": triple,
                    "shape": "claimed_without_gt",
                    "mismatched_fields": [],
                    "claimed": claimed,
                    "truth": None,
                }
            )
            continue

        # Both present — strict triple-match on attribution fields.
        mismatched = []
        if claimed["claimed_actor"] != truth["true_actor"]:
            mismatched.append("actor")
        if claimed["claimed_scope"] != truth["true_scope"]:
            mismatched.append("scope")
        if claimed["claimed_principal_chain"] != truth["true_principal_chain"]:
            mismatched.append("principal_chain")

        if not mismatched:
            numerator += 1
        else:
            defects.append(
                {
                    "triple": triple,
                    "shape": "field_mismatch",
                    "mismatched_fields": mismatched,
                    "claimed": claimed,
                    "truth": truth,
                }
            )

    denominator = len(adversarial_triples)
    ais = numerator / denominator if denominator > 0 else 0.0
    ci_low, ci_high = _wilson_ci(numerator, denominator)

    return {
        "ais": ais,
        "numerator": numerator,
        "denominator": denominator,
        "ci_low": ci_low,
        "ci_high": ci_high,
        "defects": defects,
    }


class LisResult(TypedDict):
    lis: float
    detected: int
    tampered: int
    detected_indices: list[int]
    tampered_indices: list[int]


def score_lis(
    tampered_indices: list[int],
    detected_indices: list[int],
) -> LisResult:
    """Compute the Log Integrity Score (threat-model-v2.md §4.2).

    LIS = (# tampered entries detected) / (# tampered entries).

    A tampered entry is "detected" if its index appears in
    detected_indices (what the log's chain verification flagged). For a
    baseline with no integrity artifact (B1-B3, B5), detected_indices is
    empty and tampered_indices is non-empty, so LIS = 0.0 by definition —
    a rewrite is undetectable. With no tamper injected (tampered_indices
    empty) LIS is defined as 1.0 (nothing to miss).

    Note the asymmetry with AIS: LIS measures whether a post-hoc rewrite
    is CAUGHT, not whether the recorded actor is correct. A baseline can
    score LIS = 1.0 (tamper-proof) and AIS = 0.0 (records the wrong actor)
    simultaneously — that is exactly the B4 result (§6.3).
    """
    tampered = set(tampered_indices)
    detected = set(detected_indices)
    if not tampered:
        return {
            "lis": 1.0,
            "detected": 0,
            "tampered": 0,
            "detected_indices": sorted(detected),
            "tampered_indices": [],
        }
    caught = tampered & detected
    return {
        "lis": len(caught) / len(tampered),
        "detected": len(caught),
        "tampered": len(tampered),
        "detected_indices": sorted(detected),
        "tampered_indices": sorted(tampered),
    }


def is_non_monotonic(curve: dict) -> bool:
    """Verify the §6 headline finding on a curve produced by emit_curve.

    Concretely:
      - B2 > B1: per-agent identity beats shared account
      - B2 > B3: delegation REGRESSES attribution relative to per-agent identity
      - B4 == B3: tamper-evident logging is orthogonal to attribution (§6)

    Returns True if the curve matches the prediction; False otherwise.
    A False return is a publishable finding — INV-7 binds §6's pre-registered
    predictions to whatever the measurement shows; a contradicted prediction
    is reported, not silenced.

    B4 == B3 is exact while B4 runs B3's code path. When the hash-chained
    log lands (Phase 4) and B4 has a separate execution, this evolves to
    `abs(b4 - b3) < eps` for a small tolerance.
    """
    b1 = curve["B1"]["ais"]
    b2 = curve["B2"]["ais"]
    b3 = curve["B3"]["ais"]
    b4 = curve["B4"]["ais"]
    return b2 > b1 and b2 > b3 and b4 == b3
