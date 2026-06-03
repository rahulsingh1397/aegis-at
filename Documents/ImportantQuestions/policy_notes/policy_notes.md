# Policy Notes — aegis-at/policy/

Working notes for the policy directory. Covers decisions about scope
mapping, the shared-contract pattern, and what the policy directory does
NOT cover. Lives in `Documents/ImportantQuestions/policy_notes/` so the
reasoning trail is preserved with the rest of the project's decision
history, not buried in code comments.

The implementation is in `aegis-at/policy/scope_map.py`. This file is
the *why*, not the *what*.

---

## What the policy directory exists for

Some questions need a single answer that multiple components agree on.
The clearest example, for v1: "what scope does command X require?"
Three places need this answer:

1. The tool (`siem_action`) — enforces the scope gate at §2 Boundary 3.
2. The ground-truth recorder (§2 Boundary 5) — derives `true_scope` from
   the observed command, per §4.
3. The orchestrator — when minting a token for an agent that will call
   command X, it needs to know what scope to attach.

If any two of those disagreed on the mapping, the AIS measurement would
be silently wrong: claimed_scope and true_scope could diverge for
reasons unrelated to the attack. The fix is to make the mapping one
file, imported by all three, with a test that locks the set.

This is what the `policy/` directory is for: shared contracts that
multiple parts of the system depend on. It is intentionally NOT the
place for token mechanics (that's `auth/`), for tool implementations
(that's whatever directory the tool lives in), or for orchestration
logic. Keeping `policy/` narrow is the discipline.

---

## Locked decisions (v1)

### Commands

v1 ships exactly two commands:

- `keyword_search` → `siem:read` — the read-class command Enrich uses.
- `isolate_host` → `siem:write` — the action command Contain executes.

This is the minimum that makes the sibling-impersonation attack
measurable: one read command and one write command, with the asymmetry
that gives the attack a meaningful target (a "covering tracks" outcome
requires the misattributed action to be high-consequence; isolate_host
is the asymmetry).

### Rejected alternatives

- **Full set from threat-model summary** (`explore_schema`,
  `execute_adaptive_query`, `keyword_search`, `isolate_host`). Rejected
  for v1: adding read commands doesn't change what the attack measures;
  it only inflates the test surface. The extra commands belong in a v2
  expansion when other attack flavors are in scope (per §7).
- **More than one write command.** Rejected for v1: every additional
  write command adds an attack target without changing what gets
  measured. v1 deliberately has one high-consequence action.

### Unknown commands: fail loud

Per CLAUDE.md Rule 12, an unknown command is an error, not a default.
The map raises `ValueError` with a message that names the file and
tells the reader exactly what to do ("Add to policy/scope_map.py with
a test"). Two alternatives were rejected:

- **Default unknowns to `siem:write`** (safer-by-default). Rejected:
  this would let unknown commands sneak past code review and into the
  attack path with the strictest scope, making them look intentional.
  Fail-loud forces deliberate addition.
- **Default unknowns to `siem:read`** (permissive). Rejected outright:
  permissive defaults on a security policy are exactly the wrong
  reflex.

### Where the policy lives

`aegis-at/policy/scope_map.py`, not `aegis-at/auth/` and not inline in
the tool. Reasons:

- It's a policy decision ("what command requires what scope?"), not a
  token mechanism. Keeping `auth/` narrowly about RFC 8693 + key
  management + chain verification means a refactor of the tool doesn't
  drag policy along with it.
- Inline-in-tool was rejected because the recorder and orchestrator
  also need this answer. Inlining couples the policy to one consumer.
- The dedicated directory makes the shared-contract pattern visible:
  "if multiple components need to agree on something, it goes here."

---

## Conventions inside `policy/`

These are not load-bearing rules — they're conventions, and pushing back
is fine. But they're worth naming so future additions follow the same
shape.

- The map itself is module-level and named with a leading underscore
  (`_SCOPE_REQUIRED`). Callers go through `scope_for_command()`. The
  underscore is the Python convention for "private; don't mutate from
  outside."
- Every public function has a docstring that names the invariant it
  protects, not just what it does. (Rule 9 applied to policy code.)
- A `known_commands()` accessor exists so tests don't reach into
  internals.
- A "lock the set" test exists (`test_known_commands_lists_exactly_v1_set`)
  that fails loud if anyone adds a command without going through the
  deliberate path. This is the tripwire that catches drift.

---

## Invariant mapping (INV-1 through INV-8)

How `policy/scope_map.py` checks out against the project invariants:

- **INV-1 (token structure):** N/A — policy file, no tokens.
- **INV-2 (current-actor resolution):** N/A — no identity resolution.
- **INV-3 (siem_action naming):** ✓ — only references `siem_action`'s
  commands, never `query_siem`.
- **INV-4 (ground-truth independence):** N/A here, but creates an
  obligation for the recorder: it must call `scope_for_command()` with
  the command it OBSERVED (from the harness layer), never with a
  command extracted from the token. See §4 ground-truth schema.
- **INV-5 (no illegitimate behavior):** ✓ — pure policy lookup, no
  behavior to corrupt.
- **INV-6 (baselines as config flags):** Indirectly relevant — every
  baseline imports the same `scope_for_command()`. The map cannot
  diverge between baselines.
- **INV-7 (pre-registered predictions):** N/A — policy doesn't measure
  AIS, it's consumed by code that does.
- **INV-8 (verify against the source):** ✓ — scope strings (`siem:read`,
  `siem:write`) come directly from threat-model §1; no paraphrase.

---

## Forward hooks

### For `siem_action` (next module up)

The tool will import:

```python
from scope_map import scope_for_command
```

…and use it inside the scope-gate check (§2 Boundary 3, check #4).
The tool MUST raise (not silently reject) if the command is unknown —
the map already does this. The tool's own rejection logic for
scope-mismatch (token has `siem:read` but command needs `siem:write`)
sits on top.

### For the ground-truth recorder (Boundary 5)

The recorder will import `scope_for_command()` to derive `true_scope`
per §4. CRITICAL CONSTRAINT (INV-4): the recorder must pass it the
command it OBSERVED from the harness layer — never a command field
extracted from the token. If recorder code ever does
`scope_for_command(token_claims["command"])`, that's a circular
measurement and an INV-4 violation. The recorder's command comes from
where it intercepts the tool call, not from anything the agent presents.

### For the orchestrator (Path B re-delegation)

When the orchestrator mints a token for an agent that's about to call
a specific command, it should attach the scope returned by
`scope_for_command()`. This keeps the orchestrator from accidentally
attaching an over-broad scope (which would defeat the Baseline 2 = 1.0
assumption by making attribution care less about the scope axis).

---

## Open questions deferred

- **Should the orchestrator ever mint tokens for commands not in the
  map?** Currently no — the map IS the v1 contract. If an orchestrator
  test wants to exercise an unknown command, that's a test of the
  fail-loud path, not a reason to expand the map. Decision: keep the
  map small; expand only when the threat model expands.

- **Will baselines ever need different command→scope maps?** Possibly,
  for future attack variants (e.g., scope-attenuation bypass per §7
  backlog). v1 says no — one map across all four baselines, per INV-6.
  If a future variant needs a different map, it gets its own file with
  a clear name, not a mutation of this one.

- **What about scopes that combine read+write?** v1 has none. RFC 6749
  scopes are space-separated multi-valued, so a token could carry
  `"siem:read siem:write"`. The current `scope_for_command()` returns a
  single scope string per command; the tool's scope-gate will need to
  do set-containment when checking (the token's scope set must contain
  the required scope). That's a tool concern, not a policy concern,
  but worth noting here so the tool implementation doesn't trip on it.

---

## Cross-references

- **threat-model.md §1**: defines the one-tool / scope-gated architecture.
- **threat-model.md §2 Boundary 3**: the scope-gate verification check.
- **threat-model.md §4**: ground-truth schema, `true_scope` derivation.
- **CLAUDE.md INV-3, INV-4, INV-6**: project invariants this module
  touches or creates obligations for.
- **CHECKLIST.md Step 2 INV-4 bullet**: the "recorder must not touch
  the token" rule that constrains how the recorder consumes this policy.
