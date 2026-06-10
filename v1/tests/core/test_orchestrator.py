"""Core tests for orchestrator/orchestrator.py — §2 Boundary 2 validator/minter."""

import pytest
import jwt as pyjwt

from tokens import mint_initial_token, exchange_token, verify_token
from orchestrator import mint_delegated_token


def _decode(token: str) -> dict:
    """Decode a token WITHOUT signature verification — for inspecting
    structural fields in tests that don't need crypto verification."""
    return pyjwt.decode(token, options={"verify_signature": False})


# ---- fixtures ----


@pytest.fixture
def analyst_root():
    """Root token: analyst principal, broad scope, no act claim."""
    return mint_initial_token("human:analyst", "siem:read siem:write")


@pytest.fixture
def enrich_token(analyst_root):
    """Enrich's delegation token: act.sub = enrich, sub = analyst.
    Scope narrowed to siem:read (Enrich is the read-only sibling)."""
    return exchange_token(analyst_root, "agent:enrich", "siem:read")


# ---- happy path ----


def test_happy_path(enrich_token):
    """Valid token + human principal + narrowed scope → minted token
    has correct sub, scope, and current actor."""
    tok = mint_delegated_token(
        enrich_token, "agent:enrich", "siem:read", audience="siem_action"
    )
    claims = verify_token(tok)
    assert claims["sub"] == "human:analyst"
    assert claims["scope"] == "siem:read"
    assert claims["act"]["sub"] == "agent:enrich"


# ---- validation failures (one per check) ----


def test_forged_token_raises():
    """Cryptographically invalid token raises InvalidTokenError
    (Check 1, delegated to verify_token via PyJWT)."""
    forged = pyjwt.encode(
        {"sub": "human:analyst", "scope": "siem:write"},
        "wrong-secret",
        algorithm="HS256",
    )
    with pytest.raises(pyjwt.InvalidTokenError):
        mint_delegated_token(
            forged, "agent:enrich", "siem:read", audience="siem_action"
        )


def test_non_human_principal_raises():
    """Token whose sub does not start with 'human:' raises ValueError
    (Check 2, the orchestrator's only original logic)."""
    # Root token whose principal is an agent, not a human.
    agent_root = mint_initial_token("agent:rogue", "siem:read")
    with pytest.raises(ValueError, match="human principal"):
        mint_delegated_token(
            agent_root, "agent:enrich", "siem:read", audience="siem_action"
        )


def test_scope_expansion_raises(enrich_token):
    """Requesting wider scope than enrich_token carries raises ValueError
    (Check 3, delegated to exchange_token's scope-narrowing rule).

    enrich_token has scope='siem:read'; requesting siem:write attempts
    to widen, which exchange_token blocks."""
    with pytest.raises(ValueError, match="scope escalation"):
        mint_delegated_token(
            enrich_token, "agent:enrich", "siem:write", audience="siem_action"
        )


# ---- structural correctness ----


def test_act_chain_omits_orchestrator(enrich_token):
    """The minted token nests the new actor per RFC 8693 §4.1, and the
    orchestrator does NOT appear in the chain — it is a stateless minter,
    not a delegated principal (threat-model.md §5).

    enrich_token's chain is [enrich, analyst]. Minting with
    new_actor='agent:enrich' produces [enrich, enrich, analyst] —
    the new actor on top of the prior chain. No orchestrator hop
    anywhere."""
    tok = mint_delegated_token(
        enrich_token, "agent:enrich", "siem:read", audience="siem_action"
    )
    claims = verify_token(tok)
    # sub: root principal, unchanged.
    assert claims["sub"] == "human:analyst"
    # act.sub: new current actor.
    assert claims["act"]["sub"] == "agent:enrich"
    # act.act.sub: prior actor (from enrich_token's own act claim).
    assert claims["act"]["act"]["sub"] == "agent:enrich"
    # No deeper nesting — prior token was one-hop.
    assert "act" not in claims["act"]["act"]
    # The orchestrator appears NOWHERE in the token.
    assert "orchestrator" not in str(claims)


# ---- non-interference (INV-5 safeguard, Rule 12) ----


def test_non_interference(enrich_token):
    """Same parameters → structurally identical tokens (iat/exp may
    differ since exchange_token uses wall-clock time). If anyone later
    adds alert-based routing or any dependency outside the four
    parameters, this test fails loud."""
    tok1 = mint_delegated_token(
        enrich_token, "agent:enrich", "siem:read", audience="siem_action"
    )
    tok2 = mint_delegated_token(
        enrich_token, "agent:enrich", "siem:read", audience="siem_action"
    )
    c1, c2 = _decode(tok1), _decode(tok2)
    # Structural fields must be identical across calls.
    assert c1["sub"] == c2["sub"]
    assert c1["scope"] == c2["scope"]
    assert c1["act"] == c2["act"]
    # iat and exp are expected to differ (wall-clock timestamps) — no assertion.
