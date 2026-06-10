"""
tools/siem_action.py — scope-gated SOAR tool, §2 Boundary 3 (ported from v1).

v2 port note: identical to v1/aegis-at/tools/siem_action.py except the
imports are package-absolute (required for spawn-based subprocesses to
re-import consistently). Phase 3 (threat-model-v2.md §5) adds DPoP proof
verification; it does not rewrite this module.

Boundary 3 checks (in order):
  1. Signature + expiry  — verify_token (PyJWT)
  2. Chain integrity     — check_chain_integrity()
  3. Scope gate          — check_scope()
  4. Identity resolution — resolve_identity(), INV-2

RFC 8693 §4.1: current actor = outermost act.sub.
"""

import time
from typing import Callable

from aegis_at_v2.auth import dpop
from aegis_at_v2.policy.scope_map import scope_for_command
from aegis_at_v2.auth.tokens import actor_chain, verify_token


class ScopeViolationError(Exception):
    """Token scope does not cover the requested command."""


class ChainIntegrityError(Exception):
    """act chain is malformed or missing the principal."""


def check_scope(claims: dict, command: str) -> None:
    """Raise ScopeViolationError if the token's scope doesn't cover command.

    Uses set-containment (RFC 6749 §3.3: scopes are space-separated).
    Propagates ValueError from scope_map unchanged — unknown commands are
    a policy error, not a scope error.
    """
    required = scope_for_command(command)
    if required not in set(claims.get("scope", "").split()):
        raise ScopeViolationError(
            f"command {command!r} requires {required!r}; "
            f"token carries {sorted(claims.get('scope', '').split())}"
        )


def check_chain_integrity(claims: dict) -> None:
    """Raise ChainIntegrityError if the act chain is structurally unsound.

    Checks structure only — cryptographic validity is PyJWT's job.
    """
    if "sub" not in claims:
        raise ChainIntegrityError("missing 'sub' claim")
    node = claims.get("act")
    depth = 0
    while node is not None:
        if "sub" not in node:
            raise ChainIntegrityError(f"act node at depth {depth} missing 'sub'")
        node = node.get("act")
        depth += 1


def resolve_identity(claims: dict) -> str:
    """Return the current actor: chain[0] per RFC 8693 §4.1 (INV-2).
    For a root token with no act claim, chain[0] is the principal —
    this is the Baseline 2 case where executor = authenticator.
    """
    return actor_chain(claims)[0]


def siem_action(
    command: str,
    target: str,
    token: str,
    now_fn: Callable[[], float] = time.time,
    *,
    proof: str | None = None,
    replay_cache: "dpop.ReplayCache | None" = None,
    proof_window_s: int = dpop.DEFAULT_PROOF_WINDOW_S,
) -> dict:
    """Run Boundary 3 verification, return a Boundary 4 action-log record.

    Composes the three verification functions (chain, scope, identity)
    after PyJWT does signature + expiry via verify_token. Stateless:
    returns the record; caller accumulates the log.

    Raises whichever check fails first; record only returned if all pass.

    Credential-aware (Baselines 1-2): a non-JWT per-agent credential
    (dict with format="apikey") carries no delegation chain. Identity is
    the authenticating agent; claimed_principal_chain is None. JWTs
    (Baselines 3-4) take the act-claim path below. Discrimination is on
    credential STRUCTURE only (threat-model.md §6); INV-2 holds for JWTs.

    DPoP (Baseline 5, threat-model-v2.md §5.1): if the verified token
    carries a `cnf.jkt` claim, the tool REQUIRES a DPoP `proof` and a
    `replay_cache`, and verifies that the proof proves possession of the
    bound key (and is fresh and not replayed) BEFORE resolving identity.
    This is the check that rejects a lifted token: an agent presenting a
    token bound to another agent's key cannot produce the matching proof.
    Tokens without `cnf` (B1-B4) skip this entirely — proof is ignored.
    """
    if isinstance(token, dict) and token.get("format") == "apikey":
        check_scope({"scope": token["scope"]}, command)  # scope gate only
        return {
            "claimed_actor": token["agent"],
            "claimed_scope": token["scope"],
            "claimed_principal_chain": None,  # no chain pre-delegation
            "command": command,
            "target": target,
            "timestamp": now_fn(),
            "token_chain_summary": None,
        }

    claims = verify_token(token)  # checks 1-2
    check_chain_integrity(claims)  # check 3
    check_scope(claims, command)  # check 4

    # Baseline 5: sender-constraint. A bound token may only be wielded by
    # the holder of the bound key; the proof rejects a lifted token before
    # identity is resolved (threat-model-v2.md §5.2).
    cnf = claims.get("cnf")
    if cnf is not None:
        if proof is None or replay_cache is None:
            raise dpop.DPoPError(
                "token carries cnf (sender-constrained) but no DPoP proof "
                "was presented (threat-model-v2.md §5.1)"
            )
        dpop.verify_proof(
            proof,
            dpop.RESOURCE_HTM,
            dpop.RESOURCE_HTU,
            cnf["jkt"],
            now_fn(),
            replay_cache,
            proof_window_s,
        )

    claimed_actor = resolve_identity(claims)  # check 5 (INV-2)

    chain = actor_chain(claims)
    # claimed_principal_chain == token_chain_summary; §4 keeps them
    # distinct for a future human-readable form.
    return {
        "claimed_actor": claimed_actor,
        "claimed_scope": claims["scope"],
        "claimed_principal_chain": chain,
        "command": command,
        "target": target,
        "timestamp": now_fn(),
        "token_chain_summary": chain,
    }
