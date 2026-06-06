## Rule 1 — Think Before Coding
State assumptions explicitly. Ask rather than guess.
Push back when a simpler approach exists. Stop when confused.

## Rule 2 — Simplicity First
Minimum code that solves the problem. Nothing speculative.
No abstractions for single-use code.

## Rule 3 — Surgical Changes
Touch only what you must. Don't improve adjacent code.
Match existing style. Don't refactor what isn't broken.

## Rule 4 — Goal-Driven Execution
Define success criteria. Loop until verified.
Strong success criteria let Codex loop independently.

## Rule 5 — Use the model only for judgment calls
Use for: classification, drafting, summarization, extraction.
Do NOT use for: routing, retries, status-code handling, deterministic transforms.
If code can answer, code answers.

## Rule 6 — Token budgets are not advisory
Per-task: 4,000 tokens. Per-session: 30,000 tokens.
If approaching budget, summarize and start fresh.
Surface the breach. Do not silently overrun.

## Rule 7 — Surface conflicts, don't average them
If two patterns contradict, pick one (more recent / more tested).
Explain why. Flag the other for cleanup.
Don't blend conflicting patterns.

## Rule 8 — Read before you write
Before adding code, read exports, immediate callers, shared utilities.
If unsure why existing code is structured a certain way, ask.

## Rule 9 — Tests verify intent, not just behavior
Tests must encode WHY behavior matters, not just WHAT it does.
A test that can't fail when business logic changes is wrong.

## Rule 10 — Checkpoint after every significant step
Summarize what was done, what's verified, what's left.
Don't continue from a state you can't describe back.
If you lose track, stop and restate.

## Rule 11 — Match the codebase's conventions, even if you disagree
Conformance > taste inside the codebase.
If you think a convention is harmful, surface it. Don't fork it silently.

## Rule 12 — Fail loud
"Completed" is wrong if anything was skipped silently.
"Tests pass" is wrong if any were skipped.
Default to surfacing uncertainty, not hiding it.

---

# AEGIS-AT Project Invariants

These are SPECIFIC to this codebase and sit on top of Rules 1–12 above.
The 12 rules govern *how* to code; these govern *what must be true* in
this project. Violating any of these is a correctness bug, not a style
issue. The spec is `Documents/ThreatModel/threat-model.md`; each invariant
names the section it derives from. Most encode an error this project made
or nearly made — they exist because generic good-coding rules would not
have caught them.

## The gate (run on every change)
1. `./scripts/check.sh` — mechanical: enforces INV-2 and INV-3 by grep,
   plus lint/format and `tests/core`. Must exit 0.
2. `CHECKLIST.md` — human: the judgment invariants below that no script
   can verify (INV-1, INV-4, INV-5) plus correctness intent.
Mechanical first, then human. "Done" requires both (Rule 12).

## INV-1 — Token structure is RFC 8693-compliant (§5)
`sub` = PRINCIPAL (`human:analyst`). Current actor = top-level `act.sub`.
Prior actors nested deeper. The EXECUTOR is NOT a token field. `sub` = an
agent, or the executor written into the token, is the non-compliant shape
we rejected. (RFC 8693 §4.1 / Appendix A.2.5.)

## INV-2 — Identity = MOST-RECENT actor (§2 B3; RFC §4.1) [grep-enforced]
The tool reads `claimed_actor` from the top-level `act.sub` (current /
most-recent actor), NEVER the "innermost" subject (that is the root
principal). "innermost" is correct ONLY for chain-walk *direction*, never
for identity resolution. RFC 8693 §4.1 MANDATES current-actor and FORBIDS
using prior actors for the decision.

## INV-3 — Tool name is `siem_action`, everywhere [grep-enforced]
Never `query_siem`. One tool, scope-gated. Identity comes from the
verified act claim only — never a self-reported field.

## INV-4 — Ground truth is independent by construction (§2 B5)
The ground-truth recorder observes the executing PROCESS. It must NEVER
read identity from a token or any agent-supplied field. If ground-truth
code touches the `act` claim, the measurement is circular and INVALID.
Hold all three axes: process boundary, credential isolation, causal
precedence.

## INV-5 — Attack uses NO illegitimate component behavior (§5)
Every component behaves correctly. Enrich's escalation is CORRECT (the
alert genuinely warrants containment). No component reads identity from
alert text. A test that passes only because a component misbehaves is
testing the wrong thing.

## INV-6 — Baselines are config flags over ONE codebase (§6)
Not four implementations. An AIS difference between baselines must be
attributable to the flag, not to incidental code differences.

## INV-7 — Predictions are pre-registered (§6, §8)
Predicted curve: B1≈0, B2≈1.0, B3≈0, B4≈0. A contradiction is a FINDING to
report, never something to code around. Load-bearing checkpoint: verify
the no-attack flow yields correct attribution at Baseline 2 BEFORE adding
act claims.

## INV-8 — Verify domain claims against the source
For any claim about what RFC 8693, a token, or a library actually does:
read the spec / run the code. Do not trust paraphrase — including prior
session notes or this file. This discipline is what caught the
threat-model errors.