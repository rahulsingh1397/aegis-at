"""
tools/siem_action.py — scope-gated SOAR tool, §2 Boundary 3.

Boundary 3 checks (in order):
  1. Signature + expiry  — verify_token (PyJWT)
  2. Chain integrity     — check_chain_integrity()
  3. Scope gate          — check_scope()
  4. Identity resolution — resolve_identity(), INV-2

RFC 8693 §4.1: current actor = outermost act.sub.
"""

from scope_map import scope_for_command
from tokens import actor_chain, verify_token
import time
from typing import Callable


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
) -> dict:
    """Run Boundary 3 verification, return a Boundary 4 action-log record.

    Composes the three verification functions (chain, scope, identity)
    after PyJWT does signature + expiry via verify_token. Stateless:
    returns the record; caller accumulates the log.

    Raises whichever check fails first; record only returned if all pass.
    """
    claims = verify_token(token)  # checks 1-2
    check_chain_integrity(claims)  # check 3
    check_scope(claims, command)  # check 4
    claimed_actor = resolve_identity(claims)  # check 5 (INV-2)

    chain = actor_chain(claims)
    # claimed_principal_chain == token_chain_summary in v1; §4 keeps
    # them distinct for a future human-readable form.
    return {
        "claimed_actor": claimed_actor,
        "claimed_scope": claims["scope"],
        "claimed_principal_chain": chain,
        "command": command,
        "target": target,
        "timestamp": now_fn(),
        "token_chain_summary": chain,
    }
