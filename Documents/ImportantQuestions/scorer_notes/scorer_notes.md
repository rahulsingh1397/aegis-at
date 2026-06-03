# Scorer Notes — aegis-at/harness/scorer.py (planned)

Working notes for the AIS scorer. The scorer is the module that converts
the two record streams (claimed records from `siem_action`, ground-truth
records from the recorder) into the per-baseline AIS values §6's curve
depends on. This file is the *why*; implementation lives in
`aegis-at/harness/scorer.py`.

---

## What the scorer is for

Per §4, AIS for a baseline B is:

```
AIS(B) = | {a ∈ A(B) : is_correct(a)} | / |A(B)|
```

…where `A(B)` is the set of adversarial actions in baseline B's run.
`is_correct(a)` is the strict triple match: claimed and true records
must agree on `actor`, `scope`, and `principal_chain` (per ordered-list
equality on the chain).

The scorer takes the two logs the harness has accumulated plus the
harness's list of adversarial actions, and returns a structured result
including AIS, defect breakdown, and the 95% Wilson confidence interval.

It's the module where bugs become invisible: every other module raises
on failure; the scorer produces a number. A wrong number is the result
the project publishes. So tests have to verify not just "matches return
1.0" but "exactly which mismatch shapes count as defects."

---

## Locked decisions

### Pairing: by `(command, target, timestamp)` triple

§4's stated key. The recorder's shared-clock design (the closure
pattern in `recorder.py`) is what makes this work — both records carry
the same timestamp by construction.

Rejected alternatives:
- **Index-based pairing.** Silently misaligns whenever the tool raises
  (claimed absent, ground-truth present). The recorder writes ground
  truth before the tool runs, so index-shift after a tool error is
  the failure mode.
- **Timestamp alone.** Collisions are possible if two calls happen at
  the same `time.time()` resolution. The three-field key is
  deterministic.

### Unpaired records: symmetric — both directions are defects

Three defect shapes are counted:
1. Both records present, any of (actor, scope, principal_chain) disagree.
2. Ground-truth record present, no matching claimed record (action
   happened, tool didn't log it).
3. Claimed record present, no matching ground-truth record (logged,
   no independent evidence).

Rejected alternative: asymmetric (only direction 2 counts). An
asymmetric policy would let phantom claimed records — log entries
without independent observation — silently pass as "correct." In an
audit context, a logged action with no independent record is a real
attribution failure (forged log, bypassed recorder). Symmetric
handling is what §4's "strict triple match" actually implies.

The adversarial filter applies BEFORE this analysis: only records
matching the harness's adversarial-action triples enter the pairing
check at all. Non-adversarial calls (calibration, setup) are skipped
in both directions.

### Adversarial-action filter: harness-supplied triple list

The harness, not the recorder or the tool, knows which actions are
adversarial — because the harness is the entity that constructs the
attacker-shaped alerts. It passes a list of
`(command, target, timestamp)` triples to the scorer, identifying the
adversarial set.

Rejected alternatives:
- **Adversarial flag in the record.** Would require either the
  recorder or the tool to know which alert caused the call, which
  pushes harness state into modules that shouldn't carry it.
- **All actions count.** Per §4, the denominator is specifically
  attacker-triggered actions. Non-adversarial calls would dilute the
  measurement.
- **Action IDs.** Adds a field the records don't currently have; the
  triple already serves as a unique key.

### Result object: structured, with defect breakdown and Wilson CI

The scorer returns a dataclass or dict with:

```
ScorerResult:
  ais: float                      # the point estimate
  numerator: int                  # paired-and-matching count
  denominator: int                # |A(B)|
  ci_low: float                   # Wilson 95% lower
  ci_high: float                  # Wilson 95% upper
  defects: list[Defect]           # one entry per defect, with breakdown
```

Each `Defect` carries the triple, the defect shape (fields mismatched,
or which side was missing), and the two records (or None) for forensic
inspection.

Per §4: "Reporting the distribution of defect types across a baseline
shows whether the attack breaks attribution uniformly across all three
fields or concentrates on one. This is the diagnostic signal for §6."
The defect list is what enables that report.

Rejected alternatives:
- **Just the float.** Loses the defect breakdown §4 requires.
- **Float + defects tuple.** Same content, less discoverable. The
  structured object reads better at call sites.

---

## Wilson confidence interval

§4 specifies Wilson interval at 95%, not Wald or Clopper-Pearson.
The Wilson interval is well-defined for `n = 0` (returns the trivial
[0, 1] bounds) and gives sensible bounds at the edges (AIS = 0 or 1).

Implementation choice: use `statsmodels.stats.proportion.proportion_confint`
with `method='wilson'`. If the dependency is undesirable, the formula
is short enough to inline. Decision: start with `statsmodels` (already
ergonomic), inline only if dependency footprint becomes an issue.

INV-8 commits: verify the implementation produces the documented bounds
for two known cases (e.g., `n=100, k=95` → roughly `[0.886, 0.978]`)
before locking.

---

## INV walkthrough (pre-build)

- **INV-1 (token structure):** N/A — scorer doesn't touch tokens.
- **INV-2 (current actor):** N/A directly; the scorer compares
  `claimed_actor` against `true_actor` but doesn't resolve identity
  from tokens. Both fields arrive pre-resolved in the records.
- **INV-3 (siem_action naming):** ✓ — scorer references siem_action's
  output, never `query_siem`.
- **INV-4 (ground-truth independence):** ✓ — scorer reads two
  pre-built logs; the recorder's independence is already established
  upstream. The scorer cannot violate INV-4; it can only respect or
  fail to respect §4's matching rules.
- **INV-5 (no illegitimate behavior):** ✓ — pure computation; no
  attack surface.
- **INV-6 (baselines as config flags):** the scorer is
  baseline-agnostic — it computes AIS over whatever records are
  passed. The caller picks which baseline's logs to score.
- **INV-7 (pre-registered predictions):** the SCORER honors §4
  exactly; the predictions in §6 are about what the curve will look
  like, not about the scorer's logic. If the measured curve
  contradicts §6's hypotheses, that's a finding to report (per
  Rule 12), not a scorer bug to fix.
- **INV-8 (verify against source):** ✓ — Wilson interval verified
  against a known case before locking. Strict triple match honors §4
  verbatim.

---

## Defect taxonomy

For each adversarial action, exactly one of the following:

```
MATCH:
  All three fields agree. Contributes 1 to numerator.

DEFECT_FIELD_MISMATCH:
  Both records present. One or more of (actor, scope,
  principal_chain) disagree. Captured with `mismatched_fields` set.

DEFECT_GT_WITHOUT_CLAIMED:
  Ground-truth record present, no claimed record paired by triple.
  Action happened; tool didn't log it (or tool raised before logging).

DEFECT_CLAIMED_WITHOUT_GT:
  Claimed record present, no ground-truth record paired by triple.
  Tool logged it; recorder didn't observe (or was bypassed).
```

The §5 attack mechanism produces DEFECT_FIELD_MISMATCH with
`mismatched_fields = {actor, principal_chain}` (per §6: "actor and
principal_chain defects are expected to be correlated" because both
flag when Enrich occupies the current-actor position). Scope defects
should be rare in v1 — they require the tool to misread the scope
field, which it doesn't.

---

## Forward hooks

### For the harness (next module up)

- The harness collects two logs during a baseline run: the action log
  (returned values from wrapped `siem_action` calls) and the
  ground-truth log (the list the recorder appends to).
- The harness tracks which actions are adversarial (the triples it
  injected via attacker-shaped alerts).
- The harness calls `score_ais(claimed_log, gt_log, adversarial_triples)`
  once per baseline, stores results, and produces the curve.

### For the test suite

- Tests construct synthetic claimed/ground-truth log pairs covering
  each defect shape and the matching case.
- One test per defect shape (4 total).
- One test for the symmetric handling (both unpaired directions
  produce defects).
- One test for the adversarial filter (non-adversarial calls don't
  enter the denominator).
- One test for the Wilson CI (known case verification, INV-8).
- One test for the empty-set case (`n = 0` returns valid result, not
  a divide-by-zero).

### For the §6 baseline sweep

- Each baseline produces one `ScorerResult`.
- The four results compose into the §6 curve.
- The defect breakdown across baselines is what supports the §6
  finding ("Baseline 3 attribution fails uniformly on actor and
  principal_chain, not scope").

---

## Open questions deferred

- **Floating-point timestamp equality for pairing.** If timestamps
  are passed through `time.time()` and propagated by closure, they
  should be bit-identical between claimed and true records. But if
  any layer ever rounds or serializes, equality could fail. Decision
  for v1: use `==` and add a test that catches the issue if it
  appears. If it ever does, switch to small-epsilon equality with
  a noted limitation.
- **Should the scorer log its own findings to a file?** v1 returns
  the result object only; the harness owns persistence (same pattern
  as the tool).
- **Multi-baseline aggregation.** §6's curve compares four baselines.
  Aggregation lives in the harness/sweep code, not the scorer. The
  scorer is per-baseline.

---

## Cross-references

- **threat-model.md §4** — AIS metric definition, ground-truth schema,
  Wilson CI requirement.
- **threat-model.md §6** — predicted curve; the scorer is what
  produces measured values to compare against.
- **CLAUDE.md INV-7** — pre-registered predictions; the scorer
  enforces §4 honestly so contradictions surface.
- **recorder_notes.md** — shared-clock design that enables the
  triple-pairing key.
- **tools_notes.md** — Boundary-4 record schema this module consumes.