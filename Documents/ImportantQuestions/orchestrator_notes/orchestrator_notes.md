# Orchestrator Notes — aegis-at/orchestrator/orchestrator.py

Working notes for the token-exchange orchestrator. This module is the
composition layer that ties `tokens.py` and the subagent flow together
to produce the §5 attack mechanism's actual delegation chain. Per the
locked §2 Boundary 2 (post-tightening), this module is a *validator and
minter only* — not a router, not an autonomous decision-maker, not an
attack surface beyond what the threat model already specifies.

Implementation will live in `aegis-at/orchestrator/orchestrator.py`.
This file is the *why*.

---

## What the orchestrator is for

Per §2 Boundary 2 (tightened in v1.1): the orchestrator is an RFC 8693
token-exchange endpoint. It receives a token-exchange request from a
subagent (with subject_token, actor_token, requested_scope, and
audience), validates the request per §2.1, and mints a new delegation
token per §4.1 / Appendix A.2.5 — without inspecting alert content.

The orchestrator does NOT:
- read alert content
- decide which agent should act
- route messages between agents
- maintain state between requests
- run as an autonomous loop

It does:
- validate that the requesting party holds a valid actor_token
- validate that the named principal is a human
- enforce scope-narrowing (requested ⊆ actor's scope)
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
this: *"The orchestrator must have a bug. No. It validated tokens
cryptographically and built the chain from the presented actor_token,
exactly as RFC 8693 specifies."* The orchestrator code must back this
claim line-by-line. If we add any feature the spec doesn't require, a
reviewer can dismiss the result as a property of *our* orchestrator
rather than of the standard.

---

## Locked decisions

### API: pure function `mint_delegated_token(...)`

```python
def mint_delegated_token(
    subject_token: str,
    actor_token: str,
    requested_scope: str,
    audience: str,
) -> str
```

Returns: a signed JWT string representing the newly-minted delegation
token, with `sub` carrying the principal from `subject_token`, `scope`
narrowed per the request, and `act` nesting the actor_token's chain
per RFC 8693 §4.1.

Raises: `InvalidTokenError` (PyJWT) for cryptographically invalid
inputs; `ValueError` for validation failures (non-human principal,
scope expansion, chain-root mismatch).

Renamed from `exchange_token` to avoid collision with
`tokens.exchange_token` (which is the lower-level minting primitive
this function wraps).

Rejected alternatives:
- **Class instance `Orchestrator(signing_key, issuer)`** with methods.
  Adds ceremony without benefit — the orchestrator carries no
  per-instance state worth managing. The signing key is a config
  detail; threading it through a class constructor doesn't make it
  more testable.
- **Module-level config with module init.** Makes the test suite
  set/reset module state between cases — error-prone and the
  opposite of "pure function."

### Token minting: internal reuse of `tokens.exchange_token`

The orchestrator does not duplicate the JWT minting logic. After
validation passes, it calls `tokens.exchange_token` directly, which:
- nests the act chain per RFC 8693 §4.1 (INV-1 verified)
- copies the principal `sub` from the subject_token unchanged
- verifies scope narrowing WHEN a narrowed scope is passed (raises
  `ValueError` if the requested scope is not a subset of the actor's)
- signs the result

The orchestrator's Check 3 also enforces scope narrowing before calling
`tokens.exchange_token`, so the subset check happens twice: once at the
orchestrator boundary (defense in depth, fail-fast with a clearer error
context), and once inside the minter (the primitive's own contract).
Two layers in series, both contributing — not one doing the work of two.
A reviewer auditing scope correctness reads both checks and confirms
they agree.

Why reuse matters for the result: `tokens.exchange_token` is the
spec-compliant minter (per its own INV walkthrough). By reusing it, the
orchestrator inherits its spec-compliance directly. A reviewer auditing
"is this RFC 8693 §4.1 compliant?" reads one function for the structure
and one wrapper for the gating policy — not two duplicated minters.

### Input validation: four structural checks

In order:

1. **`actor_token` cryptographically valid.** PyJWT decode with full
   verification (signature, expiry, well-formed claims). Failure raises
   `InvalidTokenError` from PyJWT. Catches forged or expired tokens
   before any other check runs.

2. **`subject_token` cryptographically valid AND `sub` names a human
   principal.** Decode + signature check + check that `sub` starts with
   `"human:"`. This catches the real failure mode (agent presented as
   principal) without restricting chain depth. Multi-hop subject tokens
   are valid as long as their `sub` is the original human.

3. **`requested_scope ⊆ scope(actor_token)`** (scope-narrowing rule).
   Set-based comparison: requested scopes must be a subset of the
   actor_token's scope claim. Prevents privilege escalation. Same
   semantics as the scope-gate at Boundary 3, and as the check that
   `tokens.exchange_token` performs internally — see the "Token
   minting" subsection above for why both layers are kept.

4. **Actor-chain root of `actor_token` matches `subject_token.sub`.**
   Walk the `act` claim of `actor_token` to its innermost `sub`; that
   must equal `subject_token.sub`. Prevents principal substitution
   (minting "on behalf of Analyst A" with an actor chain leading back
   to Analyst B).

All four are structural — they verify the request is well-formed and
internally consistent. None of them inspects content beyond what the
tokens themselves carry. None of them touches alert text. This is
enforced behaviorally by the non-interference test (see test suite
below), and statically by a gate-time grep against forbidden imports.

Rejected alternative: **subject_token must equal the root token (no
act claim).** This would forbid multi-hop delegation chains, which
§4.1 explicitly contemplates. v1's Path B attack is single-hop, but
encoding "no multi-hop" in the orchestrator would mean a reviewer
asking "what about deeper chains?" gets the answer "we restricted it"
rather than "the gap appears in the simplest case and the same
mechanism produces it at any depth." The latter is the stronger
framing for the structural-vs-bug argument.

### Threading: synchronous, no autonomous thread

The orchestrator is called synchronously from the requesting subagent's
thread. There is no `Thread(target=orchestrator_loop, ...)` and no
message-queue plumbing. The subagent calls
`mint_delegated_token(...)`, the call returns or raises, the subagent
continues.

This matters for the threat-model story: an orchestrator running in
its own thread invites the reviewer question "what's it doing in
there?" — autonomous activity raises the surface area for "this is
where the bug lives." A synchronous function is auditable in a single
call stack. The recorder still observes the calling thread (which will
be `agent:enrich` for the §5 attack, since Enrich initiates the
re-delegation request) when that thread later calls `siem_action`, and
the act chain still records the orchestrator as a prior actor per §4.1
— but the orchestrator itself executes no code outside the subagent's
stack.

Rejected alternative: a `threading.Thread(name="agent:orchestrator")`
for consistency with the recorder's thread-naming pattern. Rejected
because the orchestrator is *not* an agent in the §1 sense — it's
infrastructure that subagents call. Putting it in a thread named after
an agent would conflate two different roles in the threat model.

---

## What's deferred to v2 (named so it isn't a gap)

- **`may_act` (RFC 8693 §4.4) enforcement.** The `may_act` claim
  controls authorization (who is permitted to act on whose behalf), not
  attribution. Since Contain is legitimately authorized in the v1
  scenario, `may_act` does not prevent the attack; whether it offers
  defense-in-depth is a v2 question. §7 already lists this as out of
  scope.

- **Audience binding (`aud` claim).** The orchestrator accepts an
  `audience` parameter but does not yet enforce that the returned token
  is only valid at the named audience. Audience binding is a separate
  hardening axis; the v1 attack works regardless of audience strictness.

- **Replay protection.** No nonce/jti tracking in v1. Single-use token
  enforcement is a v2 hardening.

- **Multi-hop subject tokens in tests.** v1's measurement scopes to
  single-hop delegation (Enrich → orchestrator). The orchestrator
  accepts multi-hop subject tokens by design (check 2 above), but tests
  do not yet exercise the multi-hop case. The Path B attack works at
  any chain depth; v1 measures depth 1.

---

## INV walkthrough (pre-build)

- **INV-1 (token structure):** ✓ — the orchestrator does not construct
  tokens directly; it delegates to `tokens.exchange_token`, which is
  INV-1 verified. The orchestrator's contribution is validation, not
  structure.
- **INV-2 (current actor resolution):** N/A directly; the orchestrator
  writes the `act` claim that downstream verification reads. Check 4
  walks the chain to validate root-consistency but does not "resolve
  identity" in the §3-Boundary sense — that's the tool's job.
- **INV-3 (siem_action naming):** N/A — the orchestrator never calls
  the tool.
- **INV-4 (ground-truth independence):** ✓ — the orchestrator is in
  the system under test, not the harness. It does not read or write
  the ground-truth log. The recorder wraps `siem_action` and observes
  only tool invocations; calls to `mint_delegated_token` produce no
  ground-truth log entry because the recorder is not on that call
  path. When Enrich later calls `siem_action` from the same thread,
  the recorder observes `agent:enrich` as the true actor — consistent
  with the §5 normal-flow framing and uninstrumented by orchestrator
  activity.
- **INV-5 (no illegitimate behavior):** ✓ — the orchestrator behaves
  exactly as RFC 8693 §2.1 / §4.1 specify. It does not read alert
  content. This is enforced by the non-interference test (test 5
  below) and by a gate-time grep against forbidden imports
  (`scope_map`, alert-shaped names). The §5 attack works *because*
  the orchestrator behaves correctly, not despite it.
- **INV-6 (baselines as config flags):** the orchestrator participates
  in Baselines 3 and 4 (delegation chains added). For Baselines 1 and
  2 (no delegation), the orchestrator is bypassed — agents authenticate
  with their own credentials directly. This split is config-driven at
  the harness layer; orchestrator tests therefore exercise B3/B4
  semantics. Coverage for B1/B2 lives in the harness's baseline-sweep
  tests, not here.
- **INV-7 (pre-registered predictions):** N/A — the orchestrator
  doesn't measure AIS. But its correctness is what makes the §6
  Baseline 3 prediction load-bearing: if the orchestrator were buggy,
  the predicted AIS≈0 could be dismissed as an implementation defect.
  A spec-compliant orchestrator forecloses that reading.
- **INV-8 (verify against source):** ✓ — every claim about RFC 8693
  semantics in this module traces to a specific §  in the RFC. Check 4
  (chain-root consistency) is the most novel check; INV-8 commits to a
  test that verifies the chain walk against the spec example in
  Appendix A.2.5.

---

## Forward hooks

### For the agents (Enrich and Contain)

- Each agent runs in its own thread (named per the recorder's
  convention: `Thread(target=enrich_loop, name="agent:enrich")`,
  `Thread(target=contain_loop, name="agent:contain")`).
- When Enrich decides containment is warranted (per §5 normal flow), it
  calls `mint_delegated_token(subject_token=analyst_token,
  actor_token=enrich_token, requested_scope="siem:write", audience=...)`
  *from its own thread*. The call returns the delegated token; Enrich
  then hands that token off to Contain (in v1 this is a function call
  in the same process, since they're sibling threads of the harness).
- Contain receives the delegated token and calls `siem_action(...)`.
  The recorder, called from inside the wrapped `siem_action`, observes
  `threading.current_thread().name == "agent:contain"` — establishing
  true_actor = contain. The token's `act` chain names Enrich as the
  current actor, establishing claimed_actor = enrich. The AIS scorer
  flags the mismatch.
- Note on observability: the recorder wraps `siem_action`, NOT
  `mint_delegated_token`. The orchestrator is uninstrumented by the
  recorder. Calls to `mint_delegated_token` produce no ground-truth
  log entry. If Enrich later calls `siem_action` directly (e.g., for a
  read operation during enrichment), the recorder observes
  `agent:enrich` as the true actor — consistent and correct.

### For the harness's baseline-config switch

- Baselines 1 and 2: orchestrator is not invoked. Agents authenticate
  directly with shared (B1) or per-agent (B2) credentials.
- Baseline 3: orchestrator IS invoked; the delegated token's `act`
  chain drives the tool's identity resolution.
- Baseline 4: same as B3 but with tamper-evident logging on the
  action log. Orchestrator behavior is unchanged from B3.

### For the test suite

Tests live in `tests/core/test_orchestrator.py`. Coverage:

1. **Happy path:** valid subject_token + valid actor_token + narrowed
   scope → minted token has correct structure (sub, scope, nested act).

2. **Validation failures (one test per check):**
   - Forged actor_token → `InvalidTokenError`
   - Non-human `sub` in subject_token → `ValueError`
   - Scope expansion (requested ⊄ actor) → `ValueError`
   - Chain-root mismatch → `ValueError`

3. **Structural correctness:** the minted token's `act` chain nests
   the actor_token's claims per §4.1, with the requester as current
   actor and prior actors preserved.

4. **Spec example verification (INV-8):** mint a token whose structure
   matches RFC 8693 Appendix A.2.5 (the canonical delegation example).

5. **Non-interference (INV-5 safeguard, Rule 12).** The orchestrator
   must not depend on anything outside its four parameters. Test:
   call `mint_delegated_token` with the same valid (subject_token,
   actor_token, requested_scope, audience) tuple multiple times,
   varying *non-parameter state* between calls (different
   `time.time()` mocks, different `threading.current_thread().name`,
   different module-level globals). Assert the minted token is
   byte-identical across calls. If the orchestrator ever depends on
   alert content, thread state, time, or any module global, this test
   fails loud. A future change that adds alert-based routing logic —
   even with good intent — would break this test before it ships.
   Pair with a static gate check: grep `aegis-at/orchestrator/` for
   forbidden imports (`scope_map`, anything named `alert`).

Total: 8 tests in `tests/core/test_orchestrator.py`.

---

## Open questions deferred

- **Signing key management.** v1 uses a single shared HMAC key (from
  `tokens.py`) for all minted tokens. v2 with asymmetric keys per
  issuer is a separate hardening. Trigger to revisit: the harness
  needs to distinguish between tokens minted by different
  orchestrators, which doesn't happen in v1.

- **`audience` parameter handling.** v1 stores it in the token claim
  but doesn't enforce it. Trigger: a test that checks audience-binding
  prevention; not load-bearing for the Path B measurement.

- **Telemetry / observability.** v1 logs nothing about its own
  operation (the orchestrator is invisible to the action log). v2 may
  want orchestrator-level audit records for forensic comparison.
  Currently no consumer for that data, so deferred.

- **Determinism of `tokens.exchange_token`.** Test 5 (non-interference)
  assumes calls with identical parameters produce byte-identical
  tokens. If `tokens.exchange_token` ever introduces nondeterminism
  (random nonces, current time in claims), test 5 needs to either
  (a) mock the source of nondeterminism, or (b) assert equivalence
  modulo that field. Trigger: tokens.py changes its claim set.

---

## Cross-references

- **threat-model.md §2 Boundary 2** — the orchestrator's role,
  post-tightening.
- **threat-model.md §5** — the attack flow this module participates in.
- **threat-model.md §7** — `may_act` and audience binding scoped out.
- **CLAUDE.md INV-1, INV-5** — token structure and no-illegitimate-
  behavior obligations the orchestrator must hold.
- **tokens_notes.md (auth/tokens.py)** — the minting primitive this
  module wraps.
- **recorder_notes.md** — thread-naming convention for agents that
  call the orchestrator; explanation of why orchestrator calls are
  uninstrumented.