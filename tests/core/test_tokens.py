"""Core tests for auth/tokens.py — INV-1 and INV-2"""
from tokens import mint_initial_token, exchange_token, actor_chain, verify_token

def test_three_hop_chain_current_actor_first():
    """
    After root → orchestrator → enrich, the chain's first element
    must be the CURRENT actor (enrich), per RFC 8693 §4.1 (INV‑2).
    """
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    orch = exchange_token(root, "agent:orchestrator")
    enrich = exchange_token(orch, "agent:enrich")
    chain = actor_chain(verify_token(enrich))

    assert chain[0] == "agent:enrich", f"expected enrich first, got {chain}"
    assert chain[-1] == "human:analyst", f"expected root last, got {chain}"

def test_token_shape_inv1():
    """
    The token must have sub = principal, act.sub = current actor,
    and the executor (Contain) NEVER appears unless explicitly added.
    """
    root = mint_initial_token("human:analyst", "siem:read siem:write")
    orch = exchange_token(root, "agent:orchestrator")
    claims = verify_token(orch)

    assert claims["sub"] == "human:analyst"
    assert claims["act"]["sub"] == "agent:orchestrator"
    assert "contain" not in str(claims)