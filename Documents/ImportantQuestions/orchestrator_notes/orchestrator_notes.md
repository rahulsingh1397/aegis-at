# Orchestrator Notes — aegis-at/orchestrator/orchestrator.py

Working notes for the token-exchange orchestrator. This module is the
composition layer that ties `tokens.py` and the subagent flow together
to produce the §5 attack mechanism's actual delegation chain. Per the
locked §2 Boundary 2 (post-tightening), this module is a *validator and
minter only* — not a router, not an autonomous decision-maker, not an
attack surface beyond what the threat model already specifies.

Implementation lives in `aegis-at/orchestrator/orchestrator.py`.
This file is the *why*.

> **API note (corrected after reading the real `tokens.py`):** an
> earlier draft of these notes assumed a two-token RFC 8693 §2.1 request
> shape (`subject_token` + `actor_token`). The project's actual minting
> primitive, `tokens.exchange_token`, takes a *single* current token
> (which already carries both the principal in `sub` and the prior actor
> in `act`) plus the new actor's name. The orchestrator's API matches
> that primitive: `mint_delegated_token(current_token, new_actor,
> narrowed_scope, audience)`. This is a v1 simplification; the semantics
> (validate requester, nest actor, narrow scope) are RFC 8693 §2.1 /
> §4.1 compliant even though the parameter shape is condensed.

---

## What the orchestrator is for

Per §2 Boundary 2 (tightened in v1.1): the orchestrator is an RFC 8693
token-exchange endpoint. It receives a token-exchange request from a
subagent, validates that the requesting party is a legitimate delegation
holder acting on behalf of a human principal, and mints a new delegation
token per §4.1 / Appendix A.2.5 — without inspecting alert content.

The orchestrator does NOT:
- read alert content
- decide which agent should act
- route messages between agents
- maintain state between requests
- run as an autonomous loop

It does:
- validate that the requesting party holds a valid current_token
- validate that the named principal is a human
- mint a token whose `act` claim nests the requester per §4.1

This is the smallest possible orchestrator that still produces the §5
attack mechanism. Every line of behavior beyond this would put more of
the system under test inside the attacker's reach than the threat model
allows.

---

## Why this module is structurally important even though it's small

A reviewer reading the §6 result will ask: "is the orchestrator
implementation doing something idiosyncratic that creates the
attribution gap, or does the gap appear in a spec-compliant minimal
implementation?" The orchestrator's smallness is the answer. It does
nothing beyond what RFC 8693 specifies; the result therefore cannot be
blamed on implementation choices.

The §5 "Why this survives every objection" passage explicitly addresses
this: the orchestrator validated tokens cryptographically and built the
chain from the presented token, exactly as RFC 8693 specifies. The
orchestrator code must back this claim line-by-line. If we add any
feature the spec doesn't require, a reviewer can dismiss the result as a
property of *our* orchestrator rather than of the standard.

---

## Locked decisions

### API: pure function `mint_delegated_token(...)`

```python
def mint_delegated_token(
    current_token: str,
    new_actor: str,
    narrowed_scope: str,
    audience: str,
) -> str
```

Returns: a signed JWT delegation token, with `sub` carrying the
principal from `current_token`, `scope` narrowed per the request, and
`act` nesting `new_actor` as the current actor per RFC 8693 §4.1.

Raises: `jwt.InvalidTokenError` (PyJWT) for a forged or expired
`current_token`; `ValueError` for a non-human principal or for a
`narrowed_scope` that is not a subset of the current token's scope.

Rejected alternatives:
- **Class instance `Orchestrator(...)`.** Adds ceremony without
  benefit — no per-instance state worth managing.
- **Two-token RFC §2.1 shape.** The actual primitive takes one token;
  a two-token wrapper would add a translation layer for no gain.

### Token minting: internal reuse of `tokens.exchange_token`

After validation, the orchestrator calls
`tokens.exchange_token(current_token, new_actor, narrowed_scope)`,
which already:
- verifies the token cryptographically (PyJWT via `verify_token`)
- nests the act chain per RFC 8693 §4.1 (INV-1 verified)
- enforces scope narrowing (raises `ValueError` if the requested scope
  is not a subset of the current token's scope)
- copies the principal `sub` from the current token unchanged
- signs the result

The orchestrator's only addition is the human-principal check. By
reusing the primitive, the orchestrator inherits its spec-compliance
directly — a reviewer auditing "is this RFC 8693 §4.1 compliant?" reads
one minter and one thin wrapper, not two duplicated minters.

### Input validation: three checks

1. **`current_token` cryptographically valid.** Done inside
   `exchange_token` via `verify_token`; the orchestrator also decodes it
   up front (to read `sub`), which surfaces a forged/expired token at
   the orchestrator boundary with a clearer failure point.
2. **`current_token.sub` names a human principal.** The orchestrator
   checks that `sub` starts with `"human:"`, raises `ValueError`
   otherwise. This is the only new logic in the module — it catches the
   real failure mode (an agent presented as principal) without
   restricting chain depth.
3. **`narrowed_scope ⊆ scope(current_token)`.** Done inside
   `exchange_token`'s scope-narrowing rule.

Checks 1 and 3 are enforced by the primitive; the orchestrator adds
check 2 and a fail-fast decode for clearer errors. All three are
structural — none touches alert text. Enforced behaviorally by the
non-interference test and statically by a gate grep against forbidden
imports.

Rejected alternative: **require `current_token` to be the root token
(no act claim).** This would forbid multi-hop delegation chains, which
§4.1 explicitly contemplates. v1's Path B attack is single-hop, but
encoding "no multi-hop" would weaken the structural-vs-bug framing —
better to accept any depth and let the human-principal check (check 2)
guard the root.

### Chain shape: orchestrator does NOT appear in the act chain

The minted token's `act` chain contains the new actor and any prior
actors from the input token — but NOT the orchestrator. The orchestrator
is stateless infrastructure; it holds no delegation token and is not a
delegated principal, so RFC 8693's act claim records no hop for it. §5's
"Enrich → orchestrator → analyst" wording is conceptual (describing the
exchange flow), not literal (describing the token's `act` nesting).

For the v1 single-hop attack, the minted token's chain is therefore
2-hop: `[agent:enrich, human:analyst]` on the claimed side (via
`actor_chain`), matching the recorder's 2-hop `true_principal_chain`
of `[true_actor, human:analyst]`. This is what makes the §6 defect
signal clean: a sibling-impersonation defect is a first-element
mismatch (enrich vs contain), not a length mismatch. Actor and
principal_chain defects correlate for the right reason.

Rejected alternative: insert a synthetic `agent:orchestrator` hop to
match §5's wording. Rejected because the hop would be a fiction — the
orchestrator has no token and no cryptographic identity in the chain; a
reviewer auditing the chain would correctly ask "what is this actor and
where is its credential?" Keep the chain literal to RFC 8693 §4.1.

### Threading: synchronous, no autonomous thread

Called synchronously from the requesting subagent's thread. No separate
`Thread`. The orchestrator is a validator/minter, not an agent, so it
runs in the caller's stack. The recorder wraps `siem_action`, NOT
`mint_delegated_token` — calls to the orchestrator produce no
ground-truth log entry. When Enrich later calls `siem_action` from its
own thread, the recorder observes `agent:enrich` as true actor.

Rejected alternative: a `Thread(name="agent:orchestrator")` for
consistency with the recorder's thread-naming. Rejected because the
orchestrator is not an agent in the §1 sense — naming a thread after it
would conflate two roles.

---

## What's deferred to v2 (named so it isn't a gap)

- **`may_act` (RFC 8693 §4.4) enforcement.** Controls authorization,
  not attribution; Contain is legitimately authorized in v1, so
  `may_act` does not prevent the attack. §7 lists this out of scope.
- **Audience binding.** `audience` is accepted but not enforced in v1.
- **Replay protection.** No nonce/jti tracking in v1.
- **Multi-hop subject tokens in tests.** The orchestrator accepts any
  chain depth; v1 tests exercise single-hop only.
- **Signing-key per-process determinism.** `tokens.py` generates a
  fresh RSA keypair at import time, so tokens minted in one process
  don't verify in another. Fine for v1 (single-process harness); a v2
  multi-process baseline sweep would need a shared/persisted key.

---

## INV walkthrough (pre-build)

- **INV-1 (token structure):** ✓ — delegated to `tokens.exchange_token`
  (INV-1 verified). The orchestrator validates, doesn't construct.
- **INV-2 (current actor resolution):** N/A — the orchestrator writes
  the `act` claim the tool later reads; it does not itself resolve
  identity in the Boundary-3 sense.
- **INV-3 (siem_action naming):** N/A — never calls the tool.
- **INV-4 (ground-truth independence):** ✓ — in the system under test,
  not the harness; does not read/write the ground-truth log. The
  recorder wraps `siem_action`, not `mint_delegated_token`, so
  orchestrator calls are uninstrumented.
- **INV-5 (no illegitimate behavior):** ✓ — behaves exactly as RFC 8693
  §2.1 / §4.1 specify; reads no alert content. Enforced by the
  non-interference test and a gate-time grep against forbidden imports.
- **INV-6 (baselines as config flags):** participates in Baselines 3–4
  (delegation chains); bypassed for Baselines 1–2 (direct auth). The
  split is harness-driven; orchestrator tests exercise B3/B4 semantics.
- **INV-7 (pre-registered predictions):** N/A — doesn't measure AIS, but
  its spec-compliance is what makes the §6 Baseline 3 prediction
  load-bearing (forecloses "just an implementation bug").
- **INV-8 (verify against source):** ✓ — the API shape, scope-narrowing
  behavior, and chain shape were all verified against the actual
  `tokens.py` before this module was written, not assumed from memory.

---

## Forward hooks

### For the agents (Enrich and Contain)

- Each agent runs in its own thread named per the recorder's
  convention (`agent:enrich`, `agent:contain`).
- When Enrich decides containment is warranted (§5 normal flow), it
  calls `mint_delegated_token(enrich_token, "agent:enrich",
  "siem:write", audience=...)` from its own thread, then hands the
  returned token to Contain.
- Contain calls `siem_action(...)`. The recorder observes
  `agent:contain` as true_actor; the token's `act` chain names
  `agent:enrich` as claimed_actor. The scorer flags the mismatch.

### For the harness's baseline-config switch

- B1/B2: orchestrator bypassed (shared / per-agent direct auth).
- B3: orchestrator invoked; delegated token drives identity resolution.
- B4: as B3, with tamper-evident logging.

### For the test suite (6 tests in tests/core/test_orchestrator.py)

1. **Happy path** — valid token + human principal + narrowed scope →
   correct sub, scope, current actor.
2. **Forged token** → `InvalidTokenError`.
3. **Non-human principal** → `ValueError`.
4. **Scope expansion** → `ValueError`.
5. **Structural correctness** — minted token's `act` nests the new
   actor per §4.1; the orchestrator does NOT appear in the chain.
6. **Non-interference** — identical parameters → structurally
   equivalent tokens (same sub/scope/act; iat/exp may differ). Paired
   with a static gate grep for forbidden imports.

---

## Open questions deferred

- **Signing key management** (per-process keypair; see v2 note above).
- **`audience` enforcement** (stored, not checked in v1).
- **Determinism of `tokens.exchange_token`.** It embeds `iat`/`exp`
  from wall-clock time, so two calls with identical inputs produce
  different *bytes*. Test 6 (non-interference) therefore compares
  decoded structural fields (sub, scope, act), not raw bytes.

---

## Cross-references

- **threat-model.md §2 Boundary 2** — the orchestrator's role.
- **threat-model.md §4 / §5** — the 2-hop chain shape and the note on
  the orchestrator's absence from the chain.
- **threat-model.md §7** — `may_act` and audience binding scoped out.
- **CLAUDE.md INV-1, INV-5** — obligations the orchestrator holds.
- **tokens_notes.md** — the minting primitive this module wraps.
- **recorder_notes.md** — thread-naming; why orchestrator calls are
  uninstrumented; the matching 2-hop true chain.

---

# ==== v2 additions ====

*Implementation: `v2/aegis_at_v2/orchestrator/orchestrator.py`.
Pre-registered in `threat-model-v2.md §5`. The v1 design above is
unchanged; v2 adds an optional DPoP-binding path that is inert on
B1–B4.*

## The cnf-binding path (Baseline 5)

`mint_delegated_token` gains four keyword-only, defaulted parameters:
`cnf=None, proof=None, replay_cache=None, now=None`
(orchestrator.py:33–38). The v1 positional signature
(`current_token, new_actor, narrowed_scope, audience`) is untouched, so
every B1–B4 caller is unaffected.

When `cnf is None` (the B1–B4 default), the function does exactly what v1
did: human-principal check, then `exchange_token(...)`. The new code is
skipped entirely. **This is the INV-6 guarantee** — B5 differs from B3/B4
by a flag value, not a code fork.

When `cnf` is set (B5):

1. The orchestrator REQUIRES `proof` and `replay_cache`; absent either, it
   raises `ValueError` (orchestrator.py:86–91). You cannot ask for a bound
   token without presenting the proof context.
2. It calls `dpop.verify_proof(...)` against the **token endpoint**
   (`TOKEN_ENDPOINT_HTU`, not the tool's htu) before binding
   (orchestrator.py:92–100). This verifies the *receiving* agent actually
   holds the key named by `cnf`.
3. Only then does it hand `cnf` to `exchange_token(..., cnf=cnf)`
   (orchestrator.py:104), which stamps the RFC 7800 confirmation claim.

## Why the proof-before-bind check is the load-bearing half

This is the mechanism that makes the executor obtain a token bound to ITS
OWN key. The point of B5 is that Contain ends up named as current actor.
That only works if an agent **cannot** acquire a token bound to a key it
does not possess — otherwise Contain could request a token bound to
Enrich's key and the lift would reappear one layer up. The
proof-before-bind check forecloses that: to get a token with
`cnf = jkt(K)`, you must sign the mint request's proof with `K`. Combined
with the tool's proof-before-act check (`siem_action.md` v2 addition), the
binding is enforced at both endpoints — fraudulent bind rejected at the
orchestrator, lifted token rejected at the tool.

## What did NOT change (deliberately)

- The orchestrator still adds exactly one validation of its own beyond
  `exchange_token` — the human-principal check. DPoP verification is
  delegated to `dpop.verify_proof`; the orchestrator composes, it does not
  re-implement crypto (same discipline as wrapping `exchange_token`
  instead of re-minting).
- The orchestrator still does **not** appear in the act chain. `cnf` binds
  the minted token to the receiver's key; it does not add a hop.
- `audience` is still accepted-but-not-enforced (v1 §7 deferred item,
  unchanged).
- INV-5 holds: the orchestrator behaves correctly; the §5.2 lift is
  constructed by the harness pairing a key with the wrong token, not by
  any orchestrator misbehavior.

## v2 cross-references

- **dpop_v2.md** — `verify_proof`, the htm/htu endpoint scoping, the
  replay cache.
- **tokens.md** — the `cnf` parameter on `exchange_token` this layer
  drives.
- **siem_action.md** (v2 addition) — the matching proof-before-act check
  at the tool.
- **threat-model-v2.md §5.1–§5.3** — the locked mechanism and B5=1.0
  prediction.