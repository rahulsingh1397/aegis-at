"""orchestrator.py — RFC 8693 token-exchange validator/minter, §2 Boundary 2
(ported from v1; imports made package-absolute).

The orchestrator receives a token-exchange request from a subagent and mints
a new delegation token. Per the locked §2 Boundary 2 (post-tightening), it
does NOT route, read alert content, or maintain state — it is a thin
validator over `tokens.exchange_token`, which does the spec-compliant minting.

The only validation this module adds beyond what `tokens.exchange_token`
already performs is the human-principal check: the `sub` of the current
token must name a human principal. Signature verification, scope narrowing,
and act-chain nesting per §4.1 are all enforced inside `exchange_token`.

The orchestrator does NOT appear in the minted token's act chain — it is a
stateless minting endpoint, not a delegated principal (see threat-model.md
§5's note on the orchestrator's absence from the chain).

Phase 3 (threat-model-v2.md §5) adds DPoP proof verification + cnf binding;
it does not rewrite this module.
"""

import time

from aegis_at_v2.auth import dpop
from aegis_at_v2.auth.tokens import exchange_token, verify_token


def mint_delegated_token(
    current_token: str,
    new_actor: str,
    narrowed_scope: str,
    audience: str,
    *,
    cnf: str | None = None,
    proof: str | None = None,
    replay_cache: "dpop.ReplayCache | None" = None,
    now: float | None = None,
    proof_window_s: int = dpop.DEFAULT_PROOF_WINDOW_S,
) -> str:
    """Validate and mint a delegation token.

    Args:
        current_token: The subagent's current JWT delegation token. Must
            be cryptographically valid and have a `sub` naming a human
            principal.
        new_actor: The actor identity to embed as the new current actor.
        narrowed_scope: The scope to attach to the new token. Must be a
            subset of `current_token`'s scope.
        audience: The intended audience for the new token. Accepted but
            not enforced (v1 §7 deferred item, unchanged in v2).
        cnf: (Baseline 5, threat-model-v2.md §5.1) the DPoP key thumbprint
            to bind the minted token to. When set, the orchestrator
            REQUIRES `proof` — a DPoP proof from the agent that will hold
            the new token — and verifies that the proof's key matches
            `cnf` before binding. This is what makes the executor obtain a
            token bound to ITS OWN key: an agent cannot get a token bound
            to a key it does not possess. None (B1-B4) mints an unbound
            bearer token, exactly as v1.
        proof / replay_cache / now / proof_window_s: DPoP verification
            context, required iff `cnf` is set. `now` defaults to wall
            clock when omitted.

    Returns:
        A signed JWT delegation token, with `sub` carrying the principal
        from `current_token`, `scope` narrowed per the request, and `act`
        nesting `new_actor` as the current actor per RFC 8693 §4.1.

    Raises:
        jwt.InvalidTokenError: `current_token` is forged or expired.
        ValueError: `current_token`'s `sub` is not a human principal, or
            `narrowed_scope` is not a subset of `current_token`'s scope,
            or `cnf` is set without DPoP context.
        dpop.DPoPError: `cnf` is set but `proof` does not prove possession
            of the bound key (or is replayed / stale).
    """
    # Decode + verify the current token. exchange_token verifies again
    # internally; this gives a clearer failure point at the orchestrator
    # boundary and lets us read sub for the human-principal check.
    claims = verify_token(current_token)

    # The only validation this module adds: the principal must be human.
    if not claims["sub"].startswith("human:"):
        raise ValueError(f"subject must be a human principal, got {claims['sub']!r}")

    # Baseline 5: bind only to a key the receiving agent proves it holds.
    if cnf is not None:
        if proof is None or replay_cache is None:
            raise ValueError(
                "cnf binding requires a DPoP proof and replay_cache "
                "(threat-model-v2.md §5.1)"
            )
        dpop.verify_proof(
            proof,
            dpop.RESOURCE_HTM,
            dpop.TOKEN_ENDPOINT_HTU,
            cnf,
            now if now is not None else time.time(),
            replay_cache,
            proof_window_s,
        )

    # Hand off to the spec-compliant minter: scope narrowing, act
    # nesting per §4.1, principal preservation, signing.
    return exchange_token(current_token, new_actor, narrowed_scope, cnf=cnf)
