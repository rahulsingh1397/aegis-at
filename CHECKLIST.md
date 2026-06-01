# AEGIS-AT — Per-Module Review Checklist

Run this before marking any module **done** and before committing it.
It is deliberately short. If it grows past one screen, prune it — an
unused checklist is worse than none.

The mechanical checks (tool name, "innermost" near identity, lint, core
tests) are handled by `./scripts/check.sh`. **Run that first.** This file
covers only what a script *cannot* judge: the invariants that require
understanding *why* the code is shaped the way it is.

Reference: `Documents/ThreatModel/threat-model.md` is the spec. Every
invariant below traces to a section of it.

---

## Step 0 — Mechanical gate
- [ ] `./scripts/check.sh` passes (exits 0). If it failed, stop and fix.

## Step 1 — Judgment invariants (the ones a script can't check)

**INV-1 — Token structure (§5, RFC 8693 §4.1 / A.2.5).**
- [ ] In any minted delegation token, `sub` is the **principal**
      (`human:analyst`), not an agent.
- [ ] The current actor is the **top-level `act.sub`**; prior actors are
      nested deeper.
- [ ] The **executor does not appear** as a token field. (If you see the
      executing agent written into the token, that is the non-compliant
      shape we rejected.)

**INV-4 — Ground-truth independence (§2 Boundary 5).**
- [ ] The ground-truth recorder reads identity from the **executing
      process**, never from a token or any agent-supplied field.
- [ ] No ground-truth code path touches the `act` claim. (If it does, the
      measurement is circular and invalid.)
- [ ] The three axes still hold: process boundary, credential isolation,
      causal precedence.

**INV-5 — No illegitimate component behavior (§5).**
- [ ] Every component in the path behaves *correctly*. The attack works
      through legitimate machinery, not a bug.
- [ ] No component reads identity from alert text.
- [ ] If a test passes only because a component misbehaves, it is testing
      the wrong thing — fix the test, not the invariant.

## Step 2 — Correctness intent

**INV-7 — Pre-registered predictions (§6, §8).**
- [ ] If this module affects measured AIS, the result is compared against
      the pre-registered prediction (B1≈0, B2≈1.0, B3≈0, B4≈0).
- [ ] A contradiction with the prediction is **reported as a finding**,
      not silently coded around.
- [ ] (Checkpoint) The no-attack flow yields correct attribution at
      Baseline 2 **before** act claims are added.

## Step 3 — General quality (the .claud.md rules, briefly)
- [ ] Surgical: touched only what this change needs (Rule 3).
- [ ] Read the callers/exports before changing shared code (Rule 8).
- [ ] Core-path module (tokens / scorer / attack)? It has tests that
      encode **why** the behavior matters, not just what (Rule 9).
- [ ] Nothing was skipped silently. "Done" means done (Rule 12).

## Step 4 — Verify domain claims (INV-8)
- [ ] Any new claim about what RFC 8693 / a token / a library does was
      checked against the **source**, not from memory or a paraphrase.

---

### What "done" means
A module is done when: `check.sh` passes, every box above is ticked (or
explicitly N/A with a one-line reason), and — for core-path modules — its
tests pass and encode intent. Anything less is "in progress," and saying
otherwise violates Rule 12.
