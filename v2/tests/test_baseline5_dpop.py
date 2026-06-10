"""
Phase 3 tests — Baseline 5, DPoP sender-constraint (threat-model-v2.md §5).

WHY these tests exist: v1 §8.10 named sender-constrained tokens as the
layer hypothesized to close the attribution gap, but did not measure it.
B5's whole claim (§5.3) is AIS = 1.0 — the executor is forced to obtain a
token naming itself because it cannot wield a token bound to a sibling's
key. So the tests must show, independently:
  (a) the measurement: B5 AIS = 1.0, and the executor IS the claimed actor
      (§5.3) — not 1.0 for some accidental reason;
  (b) the mechanism that makes it true: a lifted token (bound to Enrich's
      key, presented by Contain) is REJECTED (§5.2);
  (c) the proof discipline holds: replayed and stale proofs are rejected
      (§5.4), and a bound token with no proof at all is rejected;
  (d) the v1 finding is untouched: B1-B4 still 0,1,0,0 with B5 added.
"""

import pytest

from aegis_at_v2.auth import dpop
from aegis_at_v2.auth.tokens import mint_initial_token, verify_token
from aegis_at_v2.orchestrator.orchestrator import mint_delegated_token
from aegis_at_v2.tools.siem_action import siem_action
from aegis_at_v2.harness import sweep

_FIXED = 1_700_000_000.0


def _fixed_now():
    return _FIXED


# Full pre-registered curve including B5 (threat-model-v2.md §5.3 / §7.2).
_CURVE = {"B1": 0.0, "B2": 1.0, "B3": 0.0, "B4": 0.0, "B5": 1.0}


def test_b5_ais_is_one():
    """threat-model-v2.md §5.3: sender-constraint recovers attribution —
    B5 AIS = 1.0. The lock prediction; a different value would be THE v2
    finding (reported, not coded around)."""
    out = sweep.run("B5", now_fn=_fixed_now)
    assert out["result"]["ais"] == 1.0, out["result"]


def test_b5_claimed_actor_is_the_executor():
    """threat-model-v2.md §5.3: B5 is correct for the RIGHT reason — the
    claimed actor equals the true executor (Contain), and the principal
    chain is [contain, analyst]. Guards against a spurious 1.0."""
    out = sweep.run("B5", now_fn=_fixed_now)
    claimed = out["claimed"][0]
    truth = out["truth"][0]
    assert claimed["claimed_actor"] == "agent:contain"
    assert truth["true_actor"] == "agent:contain"
    assert claimed["claimed_principal_chain"] == ["agent:contain", "human:analyst"]
    assert out["result"]["defects"] == []


def test_full_curve_with_b5():
    """threat-model-v2.md §5.3: the full B1-B5 sweep matches the
    pre-registered curve exactly under the subprocess harness."""
    for baseline, expected in _CURVE.items():
        out = sweep.run(baseline, now_fn=_fixed_now)
        assert out["result"]["ais"] == expected, (baseline, out["result"])


def test_b5_is_deterministic():
    """threat-model-v2.md §5.3 / §8: B5 records are byte-identical across
    runs under a fixed clock (random jti / proof bytes never enter a
    record)."""
    assert sweep.verify_deterministic("B5", k=3)


# --- The mechanism: lift rejection (threat-model-v2.md §5.2) ---------------


def test_lifted_token_is_rejected():
    """threat-model-v2.md §5.2: a token bound to Enrich's key, presented
    with a proof under Contain's key, is rejected at the tool. This is the
    event that FORCES the executor to obtain its own token in the B5 flow.
    """
    enrich_key = dpop.DPoPKey()
    contain_key = dpop.DPoPKey()
    cache = dpop.ReplayCache()

    root = mint_initial_token("human:analyst", "siem:read siem:write")
    enrich_mint_proof = enrich_key.create_proof(
        dpop.RESOURCE_HTM, dpop.TOKEN_ENDPOINT_HTU, _FIXED
    )
    enrich_bound_token = mint_delegated_token(
        root,
        "agent:enrich",
        "siem:write",
        audience="siem_action",
        cnf=enrich_key.jkt,
        proof=enrich_mint_proof,
        replay_cache=cache,
        now=_FIXED,
    )

    # Contain lifts Enrich's token and signs a proof under ITS OWN key.
    contain_proof = contain_key.create_proof(
        dpop.RESOURCE_HTM, dpop.RESOURCE_HTU, _FIXED
    )
    with pytest.raises(dpop.ProofBindingError):
        siem_action(
            "isolate_host",
            "host-42",
            enrich_bound_token,
            now_fn=_fixed_now,
            proof=contain_proof,
            replay_cache=dpop.ReplayCache(),
        )


def test_bound_token_without_proof_is_rejected():
    """threat-model-v2.md §5.1: a sender-constrained token presented with
    NO proof is rejected — the binding is mandatory, not advisory."""
    key = dpop.DPoPKey()
    cache = dpop.ReplayCache()
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    proof = key.create_proof(dpop.RESOURCE_HTM, dpop.TOKEN_ENDPOINT_HTU, _FIXED)
    token = mint_delegated_token(
        root,
        "agent:contain",
        "siem:write",
        audience="siem_action",
        cnf=key.jkt,
        proof=proof,
        replay_cache=cache,
        now=_FIXED,
    )
    with pytest.raises(dpop.DPoPError):
        siem_action("isolate_host", "host-42", token, now_fn=_fixed_now)


# --- Proof discipline: replay + freshness (threat-model-v2.md §5.4) --------


def _valid_bound_token_and_key():
    key = dpop.DPoPKey()
    cache = dpop.ReplayCache()
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    mint_proof = key.create_proof(dpop.RESOURCE_HTM, dpop.TOKEN_ENDPOINT_HTU, _FIXED)
    token = mint_delegated_token(
        root,
        "agent:contain",
        "siem:write",
        audience="siem_action",
        cnf=key.jkt,
        proof=mint_proof,
        replay_cache=cache,
        now=_FIXED,
    )
    return token, key


def test_replayed_proof_is_rejected():
    """threat-model-v2.md §5.4: a proof whose jti was already seen is
    rejected on the second presentation."""
    token, key = _valid_bound_token_and_key()
    cache = dpop.ReplayCache()
    proof = key.create_proof(dpop.RESOURCE_HTM, dpop.RESOURCE_HTU, _FIXED, jti="reuse")

    # First call succeeds.
    rec = siem_action(
        "isolate_host",
        "host-42",
        token,
        now_fn=_fixed_now,
        proof=proof,
        replay_cache=cache,
    )
    assert rec["claimed_actor"] == "agent:contain"

    # Replaying the SAME proof (same jti) is rejected.
    with pytest.raises(dpop.ProofReplayError):
        siem_action(
            "isolate_host",
            "host-42",
            token,
            now_fn=_fixed_now,
            proof=proof,
            replay_cache=cache,
        )


def test_stale_proof_is_rejected():
    """threat-model-v2.md §5.4: a proof whose iat is outside the freshness
    window is rejected."""
    token, key = _valid_bound_token_and_key()
    stale_proof = key.create_proof(dpop.RESOURCE_HTM, dpop.RESOURCE_HTU, _FIXED - 3600)
    with pytest.raises(dpop.ProofStaleError):
        siem_action(
            "isolate_host",
            "host-42",
            token,
            now_fn=_fixed_now,
            proof=stale_proof,
            replay_cache=dpop.ReplayCache(),
        )


# --- B1-B4 untouched by adding B5 (regression) -----------------------------


@pytest.mark.parametrize("baseline", ["B1", "B2", "B3", "B4"])
def test_b1_to_b4_unchanged_by_b5_addition(baseline):
    """threat-model-v2.md §3.1 + §5: adding the cnf/proof plumbing does not
    alter the v1 baselines — tokens without cnf skip DPoP entirely."""
    out = sweep.run(baseline, now_fn=_fixed_now)
    assert out["result"]["ais"] == _CURVE[baseline]


def test_jkt_thumbprint_is_canonical():
    """threat-model-v2.md §5.1 / INV-8: the RFC 7638 thumbprint is
    independent of JWK member ordering (canonicalization is required, or
    binding comparisons would be fragile)."""
    key = dpop.DPoPKey()
    reordered = {"x": key.jwk["x"], "kty": key.jwk["kty"], "crv": key.jwk["crv"]}
    assert dpop.jkt_thumbprint(reordered) == key.jkt


def test_cnf_appears_in_minted_token():
    """threat-model-v2.md §5.1 / INV-8: verify against the artifact — the
    minted B5 token actually carries cnf.jkt matching the bound key."""
    key = dpop.DPoPKey()
    cache = dpop.ReplayCache()
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    proof = key.create_proof(dpop.RESOURCE_HTM, dpop.TOKEN_ENDPOINT_HTU, _FIXED)
    token = mint_delegated_token(
        root,
        "agent:contain",
        "siem:write",
        audience="siem_action",
        cnf=key.jkt,
        proof=proof,
        replay_cache=cache,
        now=_FIXED,
    )
    claims = verify_token(token)
    assert claims["cnf"]["jkt"] == key.jkt
