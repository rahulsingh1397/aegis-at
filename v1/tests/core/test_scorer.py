"""Core tests for harness/scorer.py — §4 AIS metric."""
import pytest

from scorer import score_ais, _wilson_ci


# Helpers to build records concisely.
#
# Chain shape is 2-hop [actor, "human:analyst"] per the corrected §4
# schema: the orchestrator is a stateless minter, not a delegated
# principal, so it does not appear in the act chain. This matches what
# actor_chain() produces from a spec-compliant single-hop delegation
# token on the claimed side.
def _claimed(actor, command, target, ts, scope="siem:write", chain=None):
    return {
        "claimed_actor": actor,
        "claimed_scope": scope,
        "claimed_principal_chain": chain or [actor, "human:analyst"],
        "command": command,
        "target": target,
        "timestamp": ts,
        "token_chain_summary": chain or [actor, "human:analyst"],
    }


def _truth(actor, command, target, ts, scope="siem:write"):
    return {
        "true_actor": actor,
        "true_scope": scope,
        "true_principal_chain": [actor, "human:analyst"],
        "command": command,
        "target": target,
        "timestamp": ts,
    }


# --- the matching case ---

def test_perfect_match_yields_ais_one():
    """Claimed and true records agree on all three fields → AIS = 1.0."""
    ts = 1_700_000_000.0
    claimed = [_claimed("agent:contain", "isolate_host", "host-1", ts)]
    truth = [_truth("agent:contain", "isolate_host", "host-1", ts)]
    adv = frozenset({("isolate_host", "host-1", ts)})

    result = score_ais(claimed, truth, adv)
    assert result["ais"] == 1.0
    assert result["numerator"] == 1
    assert result["denominator"] == 1
    assert result["defects"] == []


# --- the three defect shapes ---

def test_actor_mismatch_is_field_defect():
    """Claimed actor != true actor → defect with shape field_mismatch,
    mismatched_fields includes 'actor'. This is the §5 attack signature.

    With the 2-hop chain, claimed=[enrich, analyst] and
    true=[contain, analyst] differ ONLY in the first element. The actor
    and principal_chain defects fire together for the right reason (the
    current-actor position differs), not because the lengths differ."""
    ts = 1_700_000_000.0
    # Claimed: Enrich (the requester per §5)
    claimed = [_claimed("agent:enrich", "isolate_host", "host-1", ts)]
    # True: Contain (the executor per §5)
    truth = [_truth("agent:contain", "isolate_host", "host-1", ts)]
    adv = frozenset({("isolate_host", "host-1", ts)})

    result = score_ais(claimed, truth, adv)
    assert result["ais"] == 0.0
    assert len(result["defects"]) == 1
    defect = result["defects"][0]
    assert defect["shape"] == "field_mismatch"
    assert "actor" in defect["mismatched_fields"]
    assert "principal_chain" in defect["mismatched_fields"]  # correlated per §6


def test_gt_without_claimed_is_defect():
    """Ground-truth present, no claimed record → defect.
    Action happened; tool didn't log it (e.g., tool raised before logging)."""
    ts = 1_700_000_000.0
    claimed = []  # tool didn't log
    truth = [_truth("agent:contain", "isolate_host", "host-1", ts)]
    adv = frozenset({("isolate_host", "host-1", ts)})

    result = score_ais(claimed, truth, adv)
    assert result["ais"] == 0.0
    assert result["defects"][0]["shape"] == "gt_without_claimed"


def test_claimed_without_gt_is_defect():
    """Claimed record present, no ground-truth → defect.
    Tool logged it; recorder didn't observe (or was bypassed)."""
    ts = 1_700_000_000.0
    claimed = [_claimed("agent:contain", "isolate_host", "host-1", ts)]
    truth = []
    adv = frozenset({("isolate_host", "host-1", ts)})

    result = score_ais(claimed, truth, adv)
    assert result["ais"] == 0.0
    assert result["defects"][0]["shape"] == "claimed_without_gt"


# --- adversarial filter behavior ---

def test_non_adversarial_calls_excluded_from_denominator():
    """Calls not in the adversarial triples set don't enter AIS at all,
    even if their records show a mismatch. Per §4: denominator is
    attacker-triggered actions only."""
    ts_adv = 1_700_000_000.0
    ts_other = 1_700_000_001.0
    claimed = [
        _claimed("agent:contain", "isolate_host", "host-1", ts_adv),
        _claimed("agent:enrich", "isolate_host", "host-99", ts_other),  # mismatch
    ]
    truth = [
        _truth("agent:contain", "isolate_host", "host-1", ts_adv),
        _truth("agent:contain", "isolate_host", "host-99", ts_other),
    ]
    # Only the first call is adversarial.
    adv = frozenset({("isolate_host", "host-1", ts_adv)})

    result = score_ais(claimed, truth, adv)
    assert result["denominator"] == 1   # only the adversarial one counts
    assert result["ais"] == 1.0          # and it matches
    assert result["defects"] == []       # the other mismatch is ignored


# --- Wilson CI ---

def test_wilson_ci_known_case():
    """INV-8: Wilson interval matches the documented case
    n=100, k=95 → ~[0.886, 0.978]."""
    low, high = _wilson_ci(95, 100)
    assert 0.887 < low < 0.889, f"expected low ~0.888, got {low}"
    assert 0.978 < high < 0.979, f"expected high ~0.9785, got {high}"


def test_wilson_ci_zero_n_returns_trivial_bounds():
    """Empty denominator: return [0, 1] rather than divide by zero."""
    assert _wilson_ci(0, 0) == (0.0, 1.0)


def test_empty_adversarial_set_returns_zero_ais_no_crash():
    """Edge case: harness ran no adversarial actions. AIS is 0 over 0;
    we return 0.0 with trivial CI rather than crash."""
    result = score_ais([], [], frozenset())
    assert result["ais"] == 0.0
    assert result["denominator"] == 0
    assert result["ci_low"] == 0.0
    assert result["ci_high"] == 1.0


# --- timestamp-equality property (the load-bearing pairing test) ---

def test_pairing_requires_exact_timestamp_match():
    """Pairing is on (command, target, timestamp) — float equality.
    A timestamp that differs by 1 millisecond fails to pair, which is
    what triggers the deferred small-epsilon-equality decision if it
    ever becomes a problem in practice.

    Note: at timestamp magnitude ~1.7e9, IEEE 754 float spacing is
    ~3.8e-7, so sub-microsecond additions vanish on round. The
    1-millisecond offset is well above the spacing AND is the order
    of magnitude where real serialization (JSON, DB round-trip) could
    plausibly introduce drift.

    The adversarial triple uses the claimed timestamp (ts). The truth
    record's timestamp is ts + 1ms, so it does NOT pair: the claimed
    record is present, the truth record is absent at that triple →
    a claimed_without_gt defect.
    """
    ts = 1_700_000_000.0
    claimed = [_claimed("agent:contain", "isolate_host", "host-1", ts)]
    truth = [_truth("agent:contain", "isolate_host", "host-1", ts + 1e-3)]
    adv = frozenset({("isolate_host", "host-1", ts)})

    result = score_ais(claimed, truth, adv)
    assert result["ais"] == 0.0
    assert len(result["defects"]) == 1
    assert result["defects"][0]["shape"] == "claimed_without_gt"


def test_shared_closure_timestamps_pair_exactly():
    """The recorder's closure pattern pins ts once. Both records carry
    the same float. Pairing works."""
    ts = 1_700_000_000.0   # both records will use this exact value
    claimed = [_claimed("agent:contain", "isolate_host", "host-1", ts)]
    truth = [_truth("agent:contain", "isolate_host", "host-1", ts)]
    adv = frozenset({("isolate_host", "host-1", ts)})

    result = score_ais(claimed, truth, adv)
    assert result["ais"] == 1.0  # pairing succeeded
    # And the values are the same float object (closure-pinned)
    assert claimed[0]["timestamp"] is ts
    assert truth[0]["timestamp"] is ts