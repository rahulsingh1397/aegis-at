# Tools Notes — aegis-at/tools/

Working notes for the tools directory. Covers `siem_action.py` decisions:
the verification function decomposition, what lives where, what's
deliberately *not* in the tool, and the contracts that the entry point
(added next) will compose.

Implementation: `aegis-at/tools/siem_action.py`. This file is the *why*.

---

## What `tools/` is for

The implementation directory for SOAR-style tools the agents can invoke.
v1 has exactly one tool — `siem_action` — by design (§1: minimum
configuration in which sibling impersonation is possible). The
directory is named for "tools" because v2 may grow more.

The directory is intentionally NOT the place for:

- Token mechanics (that's `auth/`).
- Shared policy contracts (that's `policy/`).
- Agent or orchestrator logic (separate directory when added).
- The action log itself (the tool is stateless; the harness owns logs).

---

## Where the tool sits in the data flow

```
                        ┌───────────────────────────────┐
                        │  human:analyst (root, §1)     │
                        └────────────────┬──────────────┘
                                         │ OIDC sign-in (B1)
                                         ▼
                        ┌───────────────────────────────┐
                        │  Orchestrator                 │
                        │  (mints + re-delegates, B2)   │
                        └────────────────┬──────────────┘
                                         │ delegation tokens
                  ┌──────────────────────┴──────────────────────┐
                  ▼                                             ▼
       ┌──────────────────────┐                    ┌──────────────────────┐
       │  Agent-Enrich        │                    │  Agent-Contain       │
       │  siem:read           │                    │  siem:write          │
       └──────────┬───────────┘                    └──────────┬───────────┘
                  │                                           │
                  │  presents token + command (B3)            │
                  └─────────────────┬─────────────────────────┘
                                    ▼
                  ┌─────────────────────────────────────┐
                  │  siem_action(command, target, tok)  │  ← THIS MODULE
                  │  ┌───────────────────────────────┐  │
                  │  │ check 1: signature  (PyJWT)   │  │
                  │  │ check 2: expiry     (PyJWT)   │  │
                  │  │ check 3: chain integrity      │  │
                  │  │ check 4: scope gate (policy/) │  │
                  │  │ check 5: identity   (RFC 4.1) │  │
                  │  └───────────────────────────────┘  │
                  └─────────────────┬───────────────────┘
                                    │ Boundary-4 record
                                    ▼
                  ┌─────────────────────────────────────┐
                  │  Harness (caller) — owns action log │
                  │  also runs ground-truth recorder    │
                  │  (B5, INV-4) in parallel            │
                  └─────────────────────────────────────┘
```

The tool is the choke point: every agent action passes through here,
every action produces a Boundary-4 record, and every action is observed
in parallel by the recorder (added next module).

---

## The five Boundary 3 checks — where each lives

| # | Check | Owner | Function |
|---|-------|-------|----------|
| 1 | Signature | PyJWT (in `verify_token`) | `jwt.decode()` raises `InvalidSignatureError` |
| 2 | Expiry | PyJWT (in `verify_token`) | `jwt.decode()` raises `ExpiredSignatureError` |
| 3 | Chain integrity | `tools/siem_action.py` | `check_chain_integrity()` |
| 4 | Scope gate | `tools/siem_action.py` | `check_scope()` (consumes `policy/scope_map`) |
| 5 | Identity resolution | `tools/siem_action.py` | `resolve_identity()` (INV-2) |

The split matters for two reasons:

1. **No duplication.** PyJWT already handles 1 and 2 robustly. A
   `check_expiry()` in the tool would duplicate logic and introduce a
   second source of truth — eventually they would drift. We verified
   PyJWT's expiry check fires correctly (test: a token with `exp` in the
   past raises `ExpiredSignatureError`) before deciding to leave it
   there.
2. **Test-surface clarity.** Tool tests assert the tool-owned checks.
   PyJWT tests itself; we don't re-test PyJWT.

---

## Locked decisions (v1)

### Why expiry is NOT a tool-level function

This was the first design call and got pushback from the other tool,
which proposed adding `check_expiry()` to `siem_action.py` as "check 1
of the five Boundary 3 checks." Rejected for the reasons above —
PyJWT's `jwt.decode()` already validates `exp`, confirmed by running:

```python
expired = pyjwt.encode({"sub": "human:test", "exp": time.time() - 3600}, ...)
verify_token(expired)  # raises ExpiredSignatureError
```

Rule 9 applies: a `check_expiry()` test would pass whether PyJWT raised
or our wrapper raised — it can't distinguish, so it isn't testing
intent. Tool functions exist only for checks PyJWT doesn't do.

### Three verification functions, not one combined `verify()`

`check_scope`, `check_chain_integrity`, and `resolve_identity` are
separate functions, not one combined `verify(claims, command)`. Reasons:

- Each is independently testable. Failures point at exactly one check.
- Each can be called in isolation if a future caller needs to (e.g.
  the orchestrator may want to verify a token's scope without executing
  a command).
- Composition lives in the entry point (Step 2), which is the right
  place for it — Rule 2 (simplicity first), Rule 3 (surgical changes).

### Set-containment for scope (not equality)

Per RFC 6749 §3.3, OAuth scopes are space-separated multi-valued
strings. A token carrying `"siem:read siem:write"` must satisfy both
read and write commands. So `check_scope()` does set-containment, not
string equality. Test: `test_multi_scope_token_satisfies_either_command`
pins this.

### `resolve_identity` returns `chain[0]`, not a hand-rolled lookup

`resolve_identity()` is one line: `return actor_chain(claims)[0]`. We
deliberately did *not* hand-roll the chain walk inside the tool.

Reasons:

- `actor_chain()` is already in `auth/tokens.py`, already tested
  (`test_three_hop_chain_current_actor_first`), already documented as
  "current actor first, root principal last" per RFC 8693 §4.1.
- Duplicating the walk would create two sources of truth for INV-2.
- If the tool resolved differently from `actor_chain`, the resolver
  could disagree with the tests, and the test passing wouldn't prove
  what we think it proves.

The cost: an extra import (`actor_chain` from `tokens`). Negligible.

### Why no `check_chain_integrity()` cryptographic check

`check_chain_integrity` checks *structure* (every node has a `sub`
field, chain terminates at the principal). It does NOT re-verify the
cryptographic signature on the chain. That's PyJWT's job — happened
already in `verify_token`. The structural check exists for tokens that
pass signature verification but are still malformed (e.g. someone built
an `act` claim without a `sub` and signed it). Rare but possible;
fail-loud is cheap.

---

## INV walkthrough (verification-functions layer)

How the three functions check out against project invariants:

- **INV-1 (token structure):** N/A here, but `resolve_identity` READS
  the structure INV-1 commits to. If INV-1 is violated upstream
  (sub = executor instead of principal), `resolve_identity` returns
  the wrong identity. The tool is downstream of INV-1's protection.
- **INV-2 (current actor = top-level `act.sub`):** ✓ `resolve_identity`
  returns `chain[0]`, which is the current actor by `actor_chain`'s
  definition. The test `test_identity_resolves_to_current_actor_not_root`
  pins this.
- **INV-3 (siem_action naming):** ✓ — file is named `siem_action.py`;
  no `query_siem` anywhere in the module.
- **INV-4 (ground-truth independence):** N/A directly, but creates a
  hard constraint on the recorder: the recorder MUST NOT call any of
  these functions to derive `true_*` fields. Specifically, the recorder
  must NOT call `resolve_identity()` — that would make ground truth
  read identity from the token, which is INV-4 violation. The recorder
  observes the calling PROCESS independently.
- **INV-5 (no illegitimate behavior):** ✓ — every function raises on
  invalid input. None default, swallow, or silently substitute.
- **INV-6 (one codebase, baselines as config flags):** This module
  will be config-flag-aware in the entry point (Step 2) — different
  baselines may extract the actor from different fields. The
  *verification* functions are baseline-independent; the entry point
  will be baseline-aware.
- **INV-7 (pre-registered predictions):** N/A here — predictions are
  consumed by the scorer, not the tool. The tool's job is to produce
  honest records; if records are wrong, the scorer should detect that.
- **INV-8 (verify against source):** ✓ — PyJWT expiry behavior was
  verified by running it. Scope set-containment is grounded in RFC 6749
  §3.3. Identity resolution is grounded in RFC 8693 §4.1.

---

## What the entry point (Step 2, not yet built) will compose

For future-me reading this when starting the next module: the entry
point `siem_action(command, target, token, now_fn=time.time)` will
call these functions in this order:

```
1. claims = verify_token(token)           # checks 1, 2
2. check_chain_integrity(claims)          # check 3
3. check_scope(claims, command)           # check 4
4. claimed_actor = resolve_identity(claims)  # check 5
5. build record from above + chain + clock
6. return record
```

The entry point is stateless: it returns the record, doesn't store it.
The harness accumulates records into the action log.

Three decisions locked for the entry point ahead of build:

1. **Clock injection.** `now_fn=time.time` default; tests pass a fixed
   clock. Determinism without production cost.
2. **`token_chain_summary` = `actor_chain` output.** Same data as
   `claimed_principal_chain` for v1. The threat-model schema keeps
   them distinct for a future human-readable form; v1 uses identical
   structure for both. A code comment will name this so a future
   reader doesn't think it's a bug.
3. **Stateless tool.** The harness owns log accumulation. Tool returns
   the record; caller decides what to do with it.

---

## Forward hooks

### For the entry point (next, Step 2)

- Composes the four functions in the order above.
- Builds the Boundary-4 record per §4 schema.
- Tests will live in the same file (`tests/core/test_siem_action.py`)
  and exercise: happy path, scope violation, expired token (PyJWT
  bubbling up unchanged), unknown command.

### For the ground-truth recorder (Step 3)

- The recorder wraps the entry point — but does NOT use any function
  from this module to derive ground truth.
- It observes the calling process *before* `verify_token` runs (per
  §2 Boundary 5: causal precedence).
- It derives `true_scope` by calling `scope_for_command(observed_command)`
  — the policy module. NOT by reading the token's scope.
- INV-4 is the binding constraint: any recorder code that touches the
  token at all should be flagged.

### For the orchestrator (later)

- The orchestrator will use `auth/tokens.py` directly to mint and
  exchange. It does not need anything from this module.
- The orchestrator's *agents* (Enrich, Contain) will call `siem_action()`
  with their delegated tokens.

### For the AIS scorer (later)

- Consumes the Boundary-4 records this tool produces (claimed-actor
  side) plus the recorder's records (true-actor side).
- Matches records by `(command, target, timestamp)` per §4.
- Strict triple-match on `(actor, scope, principal_chain)`.

---

## Open questions deferred

- **Should `siem_action` log to a file or just return the record?** v1
  decision: return only, harness owns persistence. If the harness needs
  to write to disk for offline scoring, the *harness* does it.
- **How does the entry point handle a token whose scope claim is empty
  (`""` or missing)?** Currently `check_scope` treats it as an empty
  set, which means any non-empty required scope will fail with
  `ScopeViolationError`. This is the correct behavior, but no test
  pins it yet — worth a test in the entry-point round.
- **Does the tool need to support multiple targets per call?** v1 says
  no — one command, one target, one record. Multi-target is a future
  extension if needed.
- **Rate limiting / replay detection?** Out of scope for v1 (per §3:
  attacker can repeat attempts; no rate limit assumed in the model).

## Entry-point design decisions (locked before Step 2 build)

The `siem_action()` entry point composes the three verification functions
into a single call that produces a Boundary-4 record. Three decisions
locked before building:

### Clock injection

`siem_action(command, target, token, now_fn=time.time)`. The clock is a
parameter with a default, not a hardcoded call. Tests pass a fixed
function (`lambda: 1_700_000_000.0`); production uses `time.time`.

Why: timestamps are the only non-deterministic input. Without injection,
tests either assert "timestamp is approximately now" (flaky) or skip
asserting on it (the field becomes untested). Injection makes the
record fully deterministic in tests with no production cost.

Rejected alternative: hardcode `time.time()` inside the function. Common
pattern, but it forces tests to monkey-patch the clock or accept
non-determinism. Injection is cleaner.

### token_chain_summary = actor_chain output

The Boundary-4 schema (§4) defines both `claimed_principal_chain` and
`token_chain_summary` as distinct fields. For v1, they carry **identical
data** — both are the output of `actor_chain(claims)`.

Why distinct in the schema, identical in v1: the schema reserves
`token_chain_summary` for a future human-readable form (e.g.
`"enrich → orchestrator → analyst"`). v1 has no such form, so both
fields use the structural list. A code comment in the entry point
will name this so a future reader doesn't think it's a bug.

If v2 introduces a human-readable summary, `token_chain_summary` is
where it goes; `claimed_principal_chain` stays structural.

### Stateless tool, harness owns the log

The entry point returns the Boundary-4 record. It does NOT append it to
any list. The caller (harness in v1) accumulates records.

Why: a module-level log inside `siem_action.py` would create test-
isolation problems (each test's records bleed into the next), require
cleanup fixtures, and couple the tool to a storage decision that's
properly the harness's concern.

Consequence: tests that exercise multiple calls collect returned
records themselves. The harness for v1 will be a simple list; later
harnesses might write to a file or database. The tool doesn't care.

Rejected alternative: a `log_sink` parameter defaulting to `None`.
Workable, but adds a parameter that's almost never set explicitly.
Statelessness is cleaner.


### Checklist walkthrough — siem_action() entry point

- Before you start: composes Boundary 3 checks into one call producing
  a Boundary 4 record (§2 + §4).
- Step 0 (gate): ✓ green, 19 tests pass.
- Step 1 (INV-8): ✓ PyJWT expiry behavior verified by running.
  RFC 8693 §4.1 governs identity. RFC 6749 §3.3 governs scope shape.
- Step 2:
  - INV-1: ✓ consumes tokens correctly shaped by auth/tokens.py;
    record's chain is actor_chain() output, which preserves INV-1.
  - INV-4: N/A: tool, not recorder. Creates obligation for recorder
    (added next): must not call siem_action's helpers to derive truth.
  - INV-5: ✓ raises on every check failure; no swallowing.
- Step 3 (INV-7): N/A: tool doesn't measure AIS; produces records the
  scorer will consume.
- Step 4 (quality): ✓ surgical (4 lines + entry-point), tests in
  tests/core/, fail-loud on every check, nothing silent.
---

## Cross-references

- **threat-model.md §1**: defines `siem_action` as the single scope-gated tool.
- **threat-model.md §2 Boundary 3**: the five verification checks.
- **threat-model.md §4**: Boundary-4 record schema.
- **CLAUDE.md INV-2**: current-actor identity resolution.
- **CLAUDE.md INV-3**: `siem_action` naming, not `query_siem`.
- **CLAUDE.md INV-4**: ground-truth independence (constrains recorder).
- **policy_notes.md**: shared scope-gate contract this module consumes.
- **RFC 8693 §4.1**: outermost `act` claim = current actor.
- **RFC 6749 §3.3**: scopes are space-separated multi-valued strings.

---

