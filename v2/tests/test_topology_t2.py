"""
Phase 5 tests — 3-agent topology T2 (threat-model-v2.md §7).

WHY these tests exist: v1's central conceded limitation (§8.1) was n=1
topology. v2 adds T2 (Enrich -> Investigator -> Contain) to move the
generalization claim from "structural argument" to "shown in 2 topologies."
The locked prediction (§7.2) is that the curve SHAPE is identical to T1 —
the gap does NOT heal with chain depth — and that at B3/B4 the claimed
actor is the DEEPEST requester (Investigator), not the executor (Contain).
A test that merely checked "T2 AIS = 0 at B3" could pass for the wrong
reason; these pin the actor and chain depth too.
"""

import pytest

from aegis_at_v2.harness import sweep
from aegis_at_v2.harness.scorer import is_non_monotonic
from aegis_at_v2.topologies import (
    get_topology,
    all_topologies,
    TOPOLOGY_NAMES,
    TWO_AGENT,
    THREE_AGENT,
)

_FIXED = 1_700_000_000.0


def _fixed_now():
    return _FIXED


# Pre-registered curve, identical for every topology (threat-model-v2.md §7.2).
_PREDICTED = {"B1": 0.0, "B2": 1.0, "B3": 0.0, "B4": 0.0, "B5": 1.0}


# --- the topology registry (the data that drives chain depth) -------------


def test_registry_resolves_t1_and_t2():
    """§7: both topologies are registered and resolvable by name."""
    assert TOPOLOGY_NAMES == ("T1", "T2")
    assert get_topology("T1") is TWO_AGENT
    assert get_topology("T2") is THREE_AGENT


def test_unknown_topology_fails_loud():
    """Rule 12: an unknown topology is an error, not a silent default."""
    with pytest.raises(ValueError):
        get_topology("T9")


def test_topology_declared_depth_matches_prediction():
    """§7.2: T1 is one re-delegation hop, T2 is two; the claimed actor is
    the deepest requester, never the executor. This is checked from the
    DECLARATION (no minting) as an independent source of truth for the
    chain the sweep should build."""
    assert TWO_AGENT.redelegation_chain == ("agent:enrich",)
    assert TWO_AGENT.claimed_actor == "agent:enrich"
    assert TWO_AGENT.expected_claimed_chain == ["agent:enrich", "human:analyst"]

    assert THREE_AGENT.redelegation_chain == ("agent:enrich", "agent:investigator")
    assert THREE_AGENT.claimed_actor == "agent:investigator"
    assert THREE_AGENT.expected_claimed_chain == [
        "agent:investigator",
        "agent:enrich",
        "human:analyst",
    ]
    # The executor is never a requester in the chain.
    for topo in all_topologies():
        assert "agent:contain" not in topo.redelegation_chain


# --- the T2 curve (the §7.2 prediction) -----------------------------------


@pytest.mark.parametrize("baseline,expected", sorted(_PREDICTED.items()))
def test_t2_curve_matches_prediction(baseline, expected):
    """§7.2: the full B1-B5 sweep on T2 yields the same curve as T1
    (B1=0, B2=1.0, B3=0, B4=0, B5=1.0). The gap does not heal with depth;
    B5 still recovers attribution."""
    out = sweep.run(baseline, now_fn=_fixed_now, topology="T2")
    assert out["topology"] == "T2"
    assert out["result"]["ais"] == expected, (
        f"T2 {baseline}: AIS={out['result']['ais']}, predicted {expected} "
        "(threat-model-v2.md §7.2)"
    )


def test_t2_curve_is_non_monotonic():
    """§7.2: the v1 headline shape (B2>B1, B2>B3, B4≈B3) holds on T2."""
    curve = {b: sweep.run(b, now_fn=_fixed_now, topology="T2")["result"] for b in _PREDICTED}
    assert is_non_monotonic(curve)


def test_t2_b3_claimed_actor_is_deepest_requester_not_executor():
    """§7.2 (the load-bearing check): on T2 the B3 defect names the DEEPEST
    requester (Investigator) as claimed actor while the true actor is the
    executor (Contain), and the claimed chain has grown to 3 hops. This is
    what distinguishes 'gap persists at depth 2' from 'AIS=0 by accident'."""
    out = sweep.run("B3", now_fn=_fixed_now, topology="T2")
    defects = out["result"]["defects"]
    assert len(defects) == 1
    d = defects[0]
    assert d["shape"] == "field_mismatch"
    assert d["mismatched_fields"] == ["actor", "principal_chain"]
    assert d["claimed"]["claimed_actor"] == "agent:investigator"
    assert d["truth"]["true_actor"] == "agent:contain"
    # Claimed chain grew a hop vs T1; true chain stays the executor's 2-hop.
    assert d["claimed"]["claimed_principal_chain"] == [
        "agent:investigator",
        "agent:enrich",
        "human:analyst",
    ]
    assert d["truth"]["true_principal_chain"] == ["agent:contain", "human:analyst"]


def test_t1_vs_t2_b3_differ_only_in_claimed_depth():
    """§7.2: T1 and T2 differ ONLY in the B3 claimed actor/chain depth —
    same true actor, same scope, same shape. Confirms the topology axis is
    the chain, nothing else (INV-6)."""
    t1 = sweep.run("B3", now_fn=_fixed_now, topology="T1")["result"]["defects"][0]
    t2 = sweep.run("B3", now_fn=_fixed_now, topology="T2")["result"]["defects"][0]
    assert t1["claimed"]["claimed_actor"] == "agent:enrich"
    assert t2["claimed"]["claimed_actor"] == "agent:investigator"
    # ground truth is identical across topologies (executor unchanged)
    assert t1["truth"]["true_actor"] == t2["truth"]["true_actor"] == "agent:contain"
    assert (
        t1["claimed"]["claimed_scope"]
        == t2["claimed"]["claimed_scope"]
        == "siem:write"
    )


# --- regression: T1 must still match v1 (§7.3 / §3.1) ---------------------


@pytest.mark.parametrize("baseline,expected", sorted(_PREDICTED.items()))
def test_t1_regression_unchanged(baseline, expected):
    """§7.3: adding T2 must not perturb T1. T1's curve still reproduces the
    v1 result (plus B5=1.0)."""
    out = sweep.run(baseline, now_fn=_fixed_now, topology="T1")
    assert out["result"]["ais"] == expected


def test_emit_curves_covers_both_topologies():
    """§7.2: emit_curves() returns one curve per topology, both matching
    the prediction. (determinism check off for speed; covered elsewhere.)"""
    curves = sweep.emit_curves(with_determinism_check=False)
    assert set(curves) == {"T1", "T2"}
    for name, curve in curves.items():
        for baseline, expected in _PREDICTED.items():
            assert curve[baseline]["ais"] == expected, f"{name} {baseline}"


def test_t2_is_deterministic():
    """§7 relies on T2 being as deterministic as T1 (the stochastic sweep
    builds on it). B3 chosen: it has the most moving parts (2-hop mint)."""
    assert sweep.verify_deterministic("B3", k=2, topology="T2")
