"""
auth/tokens.py — RFC 8693 delegation tokens (ported verbatim from v1).

v2 port note: code is identical to v1/aegis-at/auth/tokens.py except for
this header. Phase 3 (threat-model-v2.md §5) extends exchange_token with
an optional `cnf` parameter; it does not rewrite this module.

RFC 8693 (OAuth 2.0 Token Exchange) represents delegation with the `act`
claim ("actor"). The key idea:
    - `sub`  = the principal the token is FOR (whose authority is being
               exercised)
    - `act`  = who is ACTING on that principal's behalf, and `act` can
               NEST, forming a verifiable chain back to the original human.

RFC 8693 §4.1 governs the `act` claim (outermost = current actor; nested =
prior actors, informational only). §A.2.5 shows the delegation token shape.
"""

import datetime as dt
import jwt  # PyJWT

# ---------------------------------------------------------------------------
# In a real system the signing key lives in the auth server and is never
# shared. For the harness we generate one here. The adversary model
# (threat-model.md §3) says the attacker CANNOT forge this key -- that
# assumption is what makes a signed chain meaningful.
#
# v2 process note: this key is generated at import time, so each OS process
# has its OWN key. All minting and verification happens in the parent
# harness process (agents only ferry opaque JWT strings over IPC), so this
# is sound — and it doubles as an isolation property: an agent subprocess
# physically cannot mint a token the parent's tool will accept.
# ---------------------------------------------------------------------------
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PRIVATE_PEM = _key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
PUBLIC_PEM = _key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)


def mint_initial_token(principal: str, scope: str) -> str:
    """The human principal's root token. No `act` claim yet -- nobody is
    delegating on their behalf at this point."""
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "sub": principal,
        "scope": scope,
        "iat": now,
        "exp": now + dt.timedelta(minutes=10),
    }
    return jwt.encode(claims, PRIVATE_PEM, algorithm="RS256")


def exchange_token(
    current_token: str,
    new_actor: str,
    narrowed_scope: str | None = None,
    cnf: str | None = None,
) -> str:
    """RFC 8693 token exchange: take an existing token and produce one where
    `new_actor` is now acting on behalf of whoever the current token represents.

    This is the heart of delegation. We:
      1. verify the incoming token (you can only delegate authority you hold),
      2. push the *previous* subject+act into the new token's `act` claim (nesting),
      3. optionally NARROW the scope (you can delegate less than you have, never more).

    cnf (v2, threat-model-v2.md §5): when provided, the minted token carries
    a confirmation claim `cnf: {"jkt": cnf}` (RFC 7800) binding it to the
    holder's DPoP key thumbprint. None (the B1-B4 default) mints an unbound
    bearer token, exactly as v1. This single optional parameter is the only
    token-layer change Baseline 5 requires.
    """
    prior = verify_token(current_token)  # must be valid to delegate from it

    # Build the nested actor chain: the new act wraps the prior actor context.
    prior_inner_act = prior.get("act")  # the nested act from the prior token, if any

    # Scope narrowing rule: never widen. If a narrowed scope is requested it must
    # be a subset of what the current token already carries.
    current_scopes = set(prior.get("scope", "").split())
    if narrowed_scope is not None:
        requested = set(narrowed_scope.split())
        if not requested.issubset(current_scopes):
            raise ValueError(
                f"scope escalation blocked: {requested - current_scopes} not held by delegator"
            )
        effective_scope = narrowed_scope
    else:
        effective_scope = prior.get("scope", "")

    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "sub": prior["sub"],  # authority still traces to the same principal
        "act": (
            {"sub": new_actor, "act": prior_inner_act}
            if prior_inner_act
            else {"sub": new_actor}
        ),
        "scope": effective_scope,
        "iat": now,
        "exp": now + dt.timedelta(minutes=10),
    }
    if cnf is not None:
        claims["cnf"] = {"jkt": cnf}  # RFC 7800 sender-constraint binding
    return jwt.encode(claims, PRIVATE_PEM, algorithm="RS256")


def verify_token(token: str) -> dict:
    """Verify signature + expiry and return the claims. Raises on tamper/forgery."""
    return jwt.decode(token, PUBLIC_PEM, algorithms=["RS256"])


def actor_chain(claims: dict) -> list[str]:
    """Return the delegation path with the CURRENT ACTOR FIRST and the ROOT
    PRINCIPAL LAST. The current actor is the outermost `act.sub` (RFC 8693
    §4.1); identity resolution reads chain[0].

    e.g. ['agent:A' (current), 'agent:orchestrator' (prior), 'human:rahul' (root)]
    """
    chain = []
    node = claims.get("act")
    while node:
        chain.append(node["sub"])
        node = node.get("act")
    chain.append(claims["sub"])  # the root principal sits at the end
    return chain
