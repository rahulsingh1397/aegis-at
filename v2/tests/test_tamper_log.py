"""
Phase 4 tests — hash-chained log + LIS (threat-model-v2.md §4.2, §6).

WHY these tests exist: v1 shipped Baseline 4 as an attribution-only stub
and explicitly named two unverified claims as future work — (1) a real
hash-chained log detects post-hoc tampering (§6.2), and (2) doing so does
NOT recover attribution, because the wrong actor is committed upstream at
minting (§6.3). These tests turn both into measured facts, and pin the
asymmetry that is the B4 result: LIS = 1.0 AND AIS = 0.0 at the same
baseline. A test that showed only one half would miss the point.
"""

import pytest

from aegis_at_v2.harness import sweep
from aegis_at_v2.harness.scorer import score_lis
from aegis_at_v2.harness.tamper_log import TamperEvidentLog, GENESIS_HASH

_FIXED = 1_700_000_000.0


def _fixed_now():
    return _FIXED


def _entries(n: int) -> list[dict]:
    return [
        {
            "claimed_actor": "agent:enrich",
            "claimed_scope": "siem:write",
            "command": "isolate_host",
            "target": f"host-{i}",
            "timestamp": _FIXED + i,
        }
        for i in range(n)
    ]


# --- TamperEvidentLog unit (threat-model-v2.md §6.1) -----------------------


def test_intact_chain_verifies_clean():
    """An unmodified chain reports no broken entries."""
    log = TamperEvidentLog()
    for e in _entries(5):
        log.append(e)
    assert log.verify(head_signature=log.sign_head()) == []


def test_empty_log_head_is_genesis():
    """An empty log's head is the fixed genesis seed (deterministic)."""
    assert TamperEvidentLog().head == GENESIS_HASH


def test_in_place_edit_is_detected_at_its_site():
    """threat-model-v2.md §6.2: rewriting a committed entry breaks the
    chain link at that entry's index."""
    log = TamperEvidentLog()
    for e in _entries(5):
        log.append(e)
    log.entries[2] = {**log.entries[2], "claimed_actor": "agent:enrich-rewritten"}
    assert 2 in log.verify()


def test_head_signature_tamper_is_detected():
    """threat-model-v2.md §6.1: a head signature that no longer attests the
    chain flags the log even if (hypothetically) links looked intact. Here
    we verify with a signature over a DIFFERENT chain's head."""
    log = TamperEvidentLog()
    for e in _entries(3):
        log.append(e)
    other = TamperEvidentLog()
    other.append(_entries(1)[0])
    wrong_sig = other.sign_head()
    assert log.verify(head_signature=wrong_sig) != []


def test_logger_key_is_internal():
    """§6.1: the logger key lives inside the log object (parent harness);
    only its PUBLIC key is exposed for verification."""
    log = TamperEvidentLog()
    assert hasattr(log, "public_key")
    assert not hasattr(log, "_logger_key_pem")  # no private export surface


# --- score_lis (threat-model-v2.md §4.2) -----------------------------------


def test_score_lis_all_detected():
    assert score_lis([0, 1, 2], [0, 1, 2])["lis"] == 1.0


def test_score_lis_none_detected():
    assert score_lis([0, 1, 2], [])["lis"] == 0.0


def test_score_lis_no_tamper_is_one():
    """No tamper injected → nothing to miss → LIS = 1.0 by definition."""
    assert score_lis([], [])["lis"] == 1.0


def test_score_lis_partial():
    assert score_lis([0, 1, 2, 3], [0, 2])["lis"] == 0.5


# --- LIS curve across baselines (threat-model-v2.md §6.2) ------------------

_LIS_CURVE = {"B1": 0.0, "B2": 0.0, "B3": 0.0, "B4": 1.0, "B5": 0.0}


@pytest.mark.parametrize("baseline,expected", sorted(_LIS_CURVE.items()))
def test_lis_curve(baseline, expected):
    """threat-model-v2.md §6.2: only the hash-chained baseline (B4) detects
    a post-hoc rewrite; every other baseline has no integrity artifact."""
    result = sweep.measure_lis(baseline, _entries(5))
    assert result["lis"] == expected, (baseline, result)


def test_b4_detects_multiple_tampers():
    """§6.2: B4 catches every rewritten entry, not just the first."""
    result = sweep.measure_lis("B4", _entries(6), tamper_indices=[1, 3, 5])
    assert result["lis"] == 1.0
    assert result["detected"] == 3


def test_emit_lis_curve_matches_prediction():
    """threat-model-v2.md §6.2: the full LIS curve matches the pre-reg."""
    curve = sweep.emit_lis_curve()
    assert {b: curve[b]["lis"] for b in _LIS_CURVE} == _LIS_CURVE


# --- The asymmetry that IS the B4 result (threat-model-v2.md §6.3) ---------


def test_b4_lis_one_but_ais_zero():
    """threat-model-v2.md §6.3 — the load-bearing test. B4 with the REAL
    hash chain detects tampering (LIS = 1.0) yet attribution is still wrong
    (AIS = 0.0): the wrong actor was committed upstream at minting, before
    the log saw the entry. Tamper-evidence protects a wrong answer from
    being altered; it does not make the answer right."""
    run_out = sweep.run("B4", now_fn=_fixed_now)
    ais = run_out["result"]["ais"]

    lis = sweep.measure_lis("B4", run_out["claimed"])["lis"]

    assert ais == 0.0, "B4 attribution must stay wrong (§6.3)"
    assert lis == 1.0, "B4 must detect tampering with the real chain (§6.2)"


def test_b4_ais_unchanged_from_b3():
    """§6.3: adding the real log does not change B4's attribution relative
    to B3 — both record the requester (Enrich), not the executor."""
    assert sweep.run("B3", now_fn=_fixed_now)["result"]["ais"] == 0.0
    assert sweep.run("B4", now_fn=_fixed_now)["result"]["ais"] == 0.0
