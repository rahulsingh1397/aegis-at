# AEGIS-AT — Per-Module Review Checklist

Run this before marking any module **done** and before committing it.
It is deliberately short. If it grows past one screen, prune it — an
unused checklist is worse than none.

The mechanical checks (tool name, "innermost" near identity, lint, core
tests) are handled by the **version gate for the module under review**:
`./scripts/check.sh` (v1/root), `v2/scripts/check_v2.sh` (v2), or
`v3/scripts/check_v3.sh` (v3). **Run the relevant gate first.** This file
covers only what a script *cannot* judge: the invariants that require
understanding *why* the code is shaped the way it is.

Reference the threat model for the version you are touching:
`Documents/ThreatModel/threat-model.md` (v1),
`Documents/ThreatModel/ThreatModelv2/threat-model-v2.md` (v2), or
`Documents/ThreatModel/ThreatModelv3/threat-model-v3.md` (v3). Every
invariant below traces to a section of the relevant versioned spec.

---

## Before you start
- [ ] Name the threat-model section this module implements
      (e.g. "§5 attack mechanism"). If you can't, read the spec again
      or ask before coding.

## Scaffolding fast-path
If the module has **no behavior** (empty `__init__.py`, README, config
stub): only Step 0 applies. Note "scaffolding: no behavior" in the
commit message; skip the rest.

---

## Step 0 — Mechanical gate (every module)
- [ ] The relevant version gate exits 0 (`./scripts/check.sh`,
      `v2/scripts/check_v2.sh`, or `v3/scripts/check_v3.sh`). If it failed:
      read the failure verbatim, fix the cited file, re-run. Don't commit
      around a red gate. (Rule 12.)

## Step 1 — Verify against the source (INV-8)
- [ ] Any claim this module makes about what RFC 8693, a token, or a
      library actually does was checked against the **source** — not
      from memory or a paraphrase. INV-8 is first because it's how the
      threat-model errors got caught; the rest of the review assumes
      you've done it.

## Step 2 — Judgment invariants (what a script can't check)

*For each invariant below: tick it if it applies, or write "N/A: reason"
on one line (e.g. "N/A: token layer, not the recorder"). Don't tick if
it doesn't apply.*

**INV-1 — Token structure (§5, RFC 8693 §4.1 / A.2.5).**
- [ ] `sub` is the **principal** (`human:analyst`), not an agent.
- [ ] Current actor is the **top-level `act.sub`**; prior actors nested deeper.
- [ ] The **executor does not appear** as a token field.

**INV-4 — Ground-truth independence (§2 Boundary 5).**
- [ ] Ground-truth recorder reads identity from the **executing process**,
      never from a token or any agent-supplied field.
- [ ] No ground-truth code path touches the `act` claim.
- [ ] Three axes hold: process boundary, credential isolation, causal precedence.

**INV-5 — No illegitimate component behavior (§5).**
- [ ] Every component in the path behaves *correctly*. Attack works through
      legitimate machinery, not a bug.
- [ ] No component reads identity from alert text.
- [ ] No test passes only because a component misbehaves.

## Step 3 — Correctness intent

**INV-7 — Pre-registered predictions (§6, §8).**
- [ ] If this module affects measured AIS, the result is compared against
      the pre-registered prediction (B1≈0, B2≈1.0, B3≈0, B4≈0).
- [ ] A contradiction is **reported as a finding**, not coded around.
- [ ] (Checkpoint) The no-attack flow yields correct attribution at
      Baseline 2 **before** act claims are added.

## Step 4 — General quality (CLAUDE.md rules, briefly)
- [ ] Surgical: touched only what this change needs (Rule 3).
- [ ] Read the callers/exports before changing shared code (Rule 8).
- [ ] Core-path module (tokens / scorer / attack / recorder)? It has tests
      in `tests/core/` that encode **why** the behavior matters (Rule 9).
- [ ] Nothing was skipped silently. "Done" means done (Rule 12).

---

### What "done" means
A module is done when: `check.sh` passes, every applicable box above is
ticked (or marked "N/A: reason" inline), and — for core-path modules — its
tests live in `tests/core/` and pass. Anything less is "in progress,"
and saying otherwise violates Rule 12.