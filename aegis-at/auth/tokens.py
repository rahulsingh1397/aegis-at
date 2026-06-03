"""
auth/tokens.py
================
Days 3-4 deliverable: mint and verify RFC 8693 delegation tokens BY HAND.

The point of this file is UNDERSTANDING, not infrastructure. Before you let an
auth server do this for you, you build the `act` claim yourself so you can defend
exactly how the delegation chain works in an interview.

RFC 8693 (OAuth 2.0 Token Exchange) represents delegation with the `act` claim
("actor"). The key idea:
    - `sub`  = the principal the token is FOR (whose authority is being exercised)
    - `act`  = who is ACTING on that principal's behalf, and `act` can NEST,
               forming a verifiable chain back to the original human.

# RFC 8693 §4.1 governs the `act` claim (outermost = current actor; nested =
# prior actors, informational only). §A.2.5 shows the delegation token shape.

So a token where Subagent A acts on behalf of the human principal looks like:

    {
      "sub": "human:rahul",          # ultimate principal
      "act": { "sub": "agent:A" },   # A is acting on rahul's behalf
      "scope": "tool1:read"
    }

A two-hop chain (orchestrator delegated to A) nests further:

    {
      "sub": "human:rahul",
      "act": { "sub": "agent:A",
               "act": { "sub": "agent:orchestrator" } },
      "scope": "tool1:read"
    }

Reading the chain inside-out gives you the full delegation path. THIS nesting is
the property your sibling-impersonation attack will try to break.

Run:  python auth/tokens.py
"""

import datetime as dt
import jwt  # PyJWT

# ---------------------------------------------------------------------------
# In a real system the signing key lives in the auth server and is never shared.
# For the harness we generate one here. The adversary model (threat-model.md §3)
# says the attacker CANNOT forge this key -- that assumption is what makes a
# signed chain meaningful.
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
    current_token: str, new_actor: str, narrowed_scope: str | None = None
) -> str:
    """RFC 8693 token exchange: take an existing token and produce one where
    `new_actor` is now acting on behalf of whoever the current token represents.

    This is the heart of delegation. We:
      1. verify the incoming token (you can only delegate authority you hold),
      2. push the *previous* subject+act into the new token's `act` claim (nesting),
      3. optionally NARROW the scope (you can delegate less than you have, never more).
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


# ---------------------------------------------------------------------------
# Day-3 smoke test: run this file directly and read the output. When this makes
# sense to you, the load-bearing part of the project is real.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("1) Human principal mints a root token")
    root = mint_initial_token("human:rahul", scope="tool1:read tool1:write tool2:read")
    print("   chain:", actor_chain(verify_token(root)))

    print("\n2) Orchestrator receives delegated authority")
    orch = exchange_token(root, new_actor="agent:orchestrator")
    print("   chain:", actor_chain(verify_token(orch)))

    print("\n3) Orchestrator delegates to Subagent A, narrowing scope")
    tok_a = exchange_token(orch, new_actor="agent:A", narrowed_scope="tool1:read")
    print("   chain:", actor_chain(verify_token(tok_a)))
    print("   scope:", verify_token(tok_a)["scope"])

    print("\n4) Scope escalation is blocked (A tries to grab tool2)")
    try:
        exchange_token(tok_a, new_actor="agent:A", narrowed_scope="tool2:read")
    except ValueError as e:
        print("   blocked as expected:", e)

    print("\n5) Forgery is rejected (tampered signature)")
    try:
        verify_token(tok_a[:-4] + "AAAA")
    except Exception as e:
        print("   rejected as expected:", type(e).__name__)
