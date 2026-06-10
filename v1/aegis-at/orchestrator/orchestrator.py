"""orchestrator.py — RFC 8693 token-exchange validator/minter, §2 Boundary 2.

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

§7 lists may_act enforcement, audience binding, and replay protection as
v2 hardening. v1 accepts `audience` as a parameter but does not enforce it.
"""

from tokens import exchange_token, verify_token


def mint_delegated_token(
    current_token: str,
    new_actor: str,
    narrowed_scope: str,
    audience: str,
) -> str:
    """Validate and mint a delegation token.

    Args:
        current_token: The subagent's current JWT delegation token. Must
            be cryptographically valid and have a `sub` naming a human
            principal.
        new_actor: The actor identity to embed as the new current actor.
        narrowed_scope: The scope to attach to the new token. Must be a
            subset of `current_token`'s scope.
        audience: The intended audience for the new token. v1 accepts
            but does not enforce (see §7 deferred items).

    Returns:
        A signed JWT delegation token, with `sub` carrying the principal
        from `current_token`, `scope` narrowed per the request, and `act`
        nesting `new_actor` as the current actor per RFC 8693 §4.1.

    Raises:
        jwt.InvalidTokenError: `current_token` is forged or expired.
        ValueError: `current_token`'s `sub` is not a human principal, or
            `narrowed_scope` is not a subset of `current_token`'s scope.
    """
    # Decode + verify the current token. exchange_token verifies again
    # internally; this gives a clearer failure point at the orchestrator
    # boundary and lets us read sub for the human-principal check.
    claims = verify_token(current_token)

    # The only validation this module adds: the principal must be human.
    if not claims["sub"].startswith("human:"):
        raise ValueError(f"subject must be a human principal, got {claims['sub']!r}")

    # Hand off to the spec-compliant minter: scope narrowing, act
    # nesting per §4.1, principal preservation, signing.
    return exchange_token(current_token, new_actor, narrowed_scope)
