"""Core tests for tools/siem_action.py — §2 Boundary 3 verification."""
import pytest

from tokens import mint_initial_token, exchange_token, verify_token
from siem_action import (
    check_scope,
    check_chain_integrity,
    resolve_identity,
    ScopeViolationError,
    ChainIntegrityError,
)


# --- scope-gate tests (INV check 4 of 5) ---

def test_write_token_accepted_for_write_command():
    """siem:write token must be accepted for isolate_host (the attack action)."""
    check_scope({"scope": "siem:write"}, "isolate_host")


def test_read_token_rejected_for_write_command():
    """siem:read token must be rejected for isolate_host. This gate is what
    stops Enrich (read-scoped) from directly executing containment."""
    with pytest.raises(ScopeViolationError):
        check_scope({"scope": "siem:read"}, "isolate_host")


def test_multi_scope_token_satisfies_either_command():
    """RFC 6749 §3.3: scope is multi-valued. A token with both scopes
    must satisfy both commands."""
    claims = {"scope": "siem:read siem:write"}
    check_scope(claims, "keyword_search")
    check_scope(claims, "isolate_host")


def test_unknown_command_surfaces_policy_error():
    """check_scope must not swallow scope_map's ValueError. Unknown commands
    are a policy error, not a scope error — the distinction aids debugging."""
    with pytest.raises(ValueError, match="unknown command"):
        check_scope({"scope": "siem:write"}, "delete_everything")


# ------------------------------------------------------------------
# Chain integrity tests — check_chain_integrity
# ------------------------------------------------------------------
from siem_action import check_chain_integrity, ChainIntegrityError

def test_well_formed_chain_passes():
    """A delegation chain with sub and one act node must pass."""
    claims = {
        "sub": "human:analyst",
        "act": {"sub": "agent:enrich"}
    }
    check_chain_integrity(claims)  # no raise


def test_root_token_with_no_act_passes():
    """A root token with sub and no act claim is structurally valid.
    (Baseline 2 tokens have this shape.)"""
    claims = {"sub": "human:analyst"}
    check_chain_integrity(claims)  # no raise


def test_missing_sub_raises():
    """Every token must have a principal (sub)."""
    with pytest.raises(ChainIntegrityError, match="missing 'sub'"):
        check_chain_integrity({"act": {"sub": "agent:enrich"}})


def test_act_node_missing_sub_raises():
    """Every act node in the chain must have a sub field."""
    claims = {
        "sub": "human:analyst",
        "act": {"not_sub": "something"}
    }
    with pytest.raises(ChainIntegrityError, match="missing 'sub'"):
        check_chain_integrity(claims)


# ------------------------------------------------------------------
# Identity resolution tests — resolve_identity
# ------------------------------------------------------------------
from siem_action import resolve_identity

def test_resolve_identity_returns_current_actor():
    """resolve_identity must return the top-level act.sub (current actor),
    per INV-2 and RFC 8693 §4.1."""
    claims = {
        "sub": "human:analyst",
        "act": {"sub": "agent:enrich", "act": {"sub": "agent:orchestrator"}}
    }
    assert resolve_identity(claims) == "agent:enrich"


def test_resolve_identity_root_token_returns_principal():
    """For a root token with no act claim, identity is the principal (sub).
    This is the Baseline 2 path — per-agent identity without delegation."""
    claims = {"sub": "human:analyst"}
    assert resolve_identity(claims) == "human:analyst"


def test_resolve_identity_never_returns_root_for_delegated_token():
    """The innermost (deepest) subject is the root principal, and identity
    resolution MUST NOT return it when an act claim exists. This is the
    error we almost shipped — current actor, not root."""
    claims = {
        "sub": "human:analyst",            # root
        "act": {
            "sub": "agent:enrich",          # current actor
            "act": {"sub": "agent:orchestrator"}  # prior actor
        }
    }
    # If resolve_identity incorrectly returned the root, this would fail
    assert resolve_identity(claims) != "human:analyst"
    assert resolve_identity(claims) == "agent:enrich"

# --- siem_action() entry-point tests ---


def _fake_clock():
    return 1_700_000_000.0


def test_entry_point_happy_path_records_current_actor():
    """Valid token + valid command produces a record whose claimed_actor
    is the current actor (INV-2), not the principal."""
    from siem_action import siem_action

    root = mint_initial_token("human:analyst", "siem:read siem:write")
    orch = exchange_token(root, "agent:orchestrator")
    enrich = exchange_token(orch, "agent:enrich", "siem:read")

    record = siem_action(
        command="keyword_search",
        target="src_ip=1.2.3.4",
        token=enrich,
        now_fn=_fake_clock,
    )

    assert record["claimed_actor"] == "agent:enrich"
    assert record["claimed_scope"] == "siem:read"
    assert record["claimed_principal_chain"][0] == "agent:enrich"
    assert record["claimed_principal_chain"][-1] == "human:analyst"
    assert record["command"] == "keyword_search"
    assert record["target"] == "src_ip=1.2.3.4"
    assert record["timestamp"] == 1_700_000_000.0
    assert record["token_chain_summary"] == record["claimed_principal_chain"]


def test_entry_point_scope_violation_raises():
    """Read token attempting an action command must raise — no record returned."""
    from siem_action import siem_action

    root = mint_initial_token("human:analyst", "siem:read")
    enrich = exchange_token(root, "agent:enrich")

    with pytest.raises(ScopeViolationError):
        siem_action("isolate_host", "host-01", enrich)


def test_entry_point_expired_token_raises():
    """Expired token rejected via PyJWT, not by a duplicated tool check."""
    import jwt as pyjwt
    import time as _time
    from tokens import PRIVATE_PEM
    from siem_action import siem_action

    expired = pyjwt.encode(
        {"sub": "human:analyst", "scope": "siem:write", "exp": _time.time() - 60},
        PRIVATE_PEM,
        algorithm="RS256",
    )
    with pytest.raises(pyjwt.ExpiredSignatureError):
        siem_action("isolate_host", "host-01", expired)


def test_entry_point_unknown_command_raises():
    """Unknown command surfaces ValueError from scope_map, unchanged."""
    from siem_action import siem_action

    root = mint_initial_token("human:analyst", "siem:write")
    with pytest.raises(ValueError, match="unknown command"):
        siem_action("delete_everything", "host-01", root)