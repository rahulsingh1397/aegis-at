# Tokens Notes — aegis-at/auth/tokens.py (v1) · v2/aegis_at_v2/auth/tokens.py (v2)

Working notes for the RFC 8693 delegation-token primitive — the
load-bearing crypto substrate of the whole benchmark. This file did not
exist during v1 (the design was captured inline in the threat model and
in `orchestrator_notes.md`); it is created now so the token layer has its
own *why*, and so the v2 `cnf` extension has a documented home.

Implementation (identical except header + the `cnf` parameter):
- v1: `aegis-at/auth/tokens.py` (frozen)
- v2: `v2/aegis_at_v2/auth/tokens.py`

> **INV-1 is this module's reason to exist.** `sub` = PRINCIPAL
> (`human:analyst`). Current actor = top-level `act.sub`. Prior actors
> nested deeper. The EXECUTOR is NOT a token field. Every other module
> trusts that this one builds that shape correctly.

---

## What the token layer is for

RFC 8693 (OAuth 2.0 Token Exchange) represents delegation with the `act`
("actor") claim:

- `sub` — the principal the token is FOR (whose authority is exercised).
- `act` — who is ACTING on that principal's behalf; `act` **nests**,
  forming a verifiable chain back to the original human.

The module is four functions:

| Function | Purpose | RFC anchor |
|---|---|---|
| `mint_initial_token(principal, scope)` | the human's root token, no `act` yet | — |
| `exchange_token(current, new_actor, narrowed_scope=None, cnf=None)` | the delegation step: verify, nest `act`, narrow scope, (v2) optionally bind `cnf` | §2.1 / §4.1 / §A.2.5 |
| `verify_token(token)` | signature + expiry, return claims; raises on tamper/forgery | — |
| `actor_chain(claims)` | the delegation path, **current actor first, root principal last** | §4.1 |

---

## Locked decisions (v1, carried into v2 unchanged)

### Signing key generated at import time, per process

`_key = rsa.generate_private_key(...)` runs at module import
(tokens.py:37). In a real system the key lives in the auth server and is
never shared; the harness generates one. The adversary model (§II.3) says
the attacker CANNOT forge this key — that assumption is what makes a
signed chain meaningful.

**v2 process consequence (important):** because the key is per-import, each
OS process gets its OWN key. In v2's subprocess harness this is *sound and
load-bearing*: all minting and verification happen in the parent (agents
ferry opaque JWT strings over IPC), so there is no cross-process
verification to break — and it doubles as an isolation property, an agent
subprocess physically cannot mint a token the parent's tool will accept.
This is exactly why `agent_bodies.py` must NOT import `tokens` (it would
regenerate a key per spawn for nothing). See `agent_proc_v2.md`.

### Scope narrowing is one-directional (never widen)

`exchange_token` (tokens.py:89–98): a requested `narrowed_scope` must be a
subset of what the current token carries, else `ValueError` ("scope
escalation blocked"). You can delegate less than you hold, never more.
This is the property `siem_action`'s scope gate and the orchestrator both
rely on.

### `actor_chain` returns current-actor-first (INV-2 anchor)

`actor_chain` (tokens.py:122–135) walks `act` from the outside in,
appending each `act.sub`, then appends the root `sub` last. So `chain[0]`
is the current actor (RFC §4.1) and `chain[-1]` is the root principal.
`siem_action.resolve_identity` is literally `actor_chain(claims)[0]` —
one source of truth for "who is the current actor," so the tool and the
tests cannot disagree about INV-2. The name "innermost" is correct ONLY
for chain-walk direction, NEVER for identity (INV-2).

### Nesting preserves prior actors as informational

`exchange_token` (tokens.py:103–107): the new `act` is
`{sub: new_actor, act: <prior act>}`. Prior actors are retained but nested
deeper — informational only per §4.1, never the identity. This is what
lets T2 (3-agent chain) record `[investigator, enrich, analyst]` while
identity still resolves to the single current actor.

---

## ==== v2 additions ====

### `cnf` parameter — the only token-layer change Baseline 5 requires

`exchange_token(current_token, new_actor, narrowed_scope=None, cnf=None)`
(tokens.py:62–67, 112–113). When `cnf` is provided, the minted token
carries `claims["cnf"] = {"jkt": cnf}` (RFC 7800), binding it to the
holder's DPoP key thumbprint. When `cnf is None` — the B1–B4 default — the
minted token is an unbound bearer token, **exactly as v1**: the claims
dict is byte-for-byte identical to the v1 output.

This is deliberately the smallest possible change: one optional keyword,
one conditional line that adds a claim. It does not touch `sub`, `act`,
scope narrowing, signing, or `actor_chain`. INV-1 is unaffected — `cnf`
binds the token to a *key*, it does not name an actor; the actor is still
`act.sub`.

The `cnf` value flows in from `orchestrator.mint_delegated_token`, which
is the layer that *decides* whether to bind (and verifies the receiving
agent actually holds the bound key before doing so). `tokens.py` is a pure
mechanism: it stamps the `cnf` it is given. The policy of when to bind,
and the proof verification, live one layer up. See `dpop_v2.md` and the v2
addition in `orchestrator_notes.md`.

**Verification semantics did NOT change.** `verify_token` still checks
only signature + expiry and returns all claims (including `cnf` if
present). The *enforcement* of `cnf` — requiring a matching DPoP proof —
is the consumer's job (`siem_action`, the orchestrator), not
`verify_token`'s. A `cnf`-bearing token presented with no proof verifies
cryptographically but is rejected by the tool. Keeping `verify_token`
unchanged is what keeps the v1 verification path frozen.

---

## INV walkthrough

- **INV-1 (token structure):** ✓ — `sub`=principal, `act.sub`=current
  actor, nesting for priors, executor absent. `cnf` is orthogonal.
- **INV-2 (current actor = `act.sub`):** ✓ — `actor_chain[0]`; one source
  of truth.
- **INV-3 (siem_action naming):** N/A — token layer, no tool.
- **INV-4 (ground-truth independence):** N/A — the recorder never calls
  this module; it uses the kernel PID.
- **INV-5 (no illegitimate behavior):** ✓ — raises on forgery, expiry,
  scope escalation; never silently substitutes.
- **INV-6 (config flags):** ✓ — `cnf=None` is the B1–B4 flag value; B5
  passes a thumbprint. Same codebase, same function.
- **INV-7 (pre-registered):** N/A directly; underpins the B3/B4/B5
  predictions by being spec-correct (the gap can't be blamed on a minting
  bug).
- **INV-8 (verify against source):** ✓ — §4.1 actor semantics, §A.2.5
  delegation shape, RFC 7800 `cnf` shape verified against the specs.

---

## Cross-references

- **threat-model-v2.md §5** — where `cnf` is pre-registered.
- **dpop_v2.md** — the thumbprint that fills `cnf`, and the proof that
  enforces it.
- **orchestrator_notes.md** — the layer that decides to bind and verifies
  possession first.
- **siem_action.md** — the consumer that enforces `cnf` at the tool.
- **CLAUDE.md INV-1, INV-2** — the structure this module commits to.
- **RFC 8693 §4.1 / §A.2.5**, **RFC 7800** (cnf), **RFC 6749 §3.3**
  (scope).
