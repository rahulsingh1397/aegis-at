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

### Adversarial-action filter: harness-supplied frozenset of triples

The harness, not the recorder or the tool, knows which actions are
adversarial — because the harness is the entity that constructs the
attacker-shaped alerts. It passes a `frozenset` of
`(command, target, timestamp)` triples to the scorer, identifying the
adversarial set.

Why `frozenset`: immutable, hashable, O(1) membership check — the
membership test runs once per record in each log, so set semantics
matter at larger N.

Rejected alternatives:
- **Adversarial flag in the record.** Would require either the
  recorder or the tool to know which alert caused the call, which
  pushes harness state into modules that shouldn't carry it.
- **All actions count.** Per §4, the denominator is specifically
  attacker-triggered actions. Non-adversarial calls would dilute the
  measurement.
- **Action IDs.** Adds a field the records don't currently have; the
  triple already serves as a unique key.
- **`list` or `set` (mutable).** No reason to allow the filter to be
  mutated mid-call; frozenset signals "this is the locked adversarial
  set for this scoring run."

### Result object: dict with TypedDict annotations

The scorer returns a plain dict, matching the convention of every
other record schema in the codebase (action-log records from
`siem_action`, ground-truth records from the recorder). TypedDict
annotations provide static type hints without changing runtime
structure.

```
ScorerResult (TypedDict):
  ais: float                      # the point estimate
  numerator: int                  # paired-and-matching count
  denominator: int                # |A(B)|
  ci_low: float                   # Wilson 95% lower
  ci_high: float                  # Wilson 95% upper
  defects: list[Defect]           # one entry per defect, with breakdown
```

Each `Defect` (also a TypedDict) carries the triple, the defect shape
(fields mismatched, or which side was missing), and the two records
(or None) for forensic inspection.

Per §4: "Reporting the distribution of defect types across a baseline
shows whether the attack breaks attribution uniformly across all three
fields or concentrates on one. This is the diagnostic signal for §6."
The defect list is what enables that report.

Rejected alternatives:
- **Dataclasses.** Cleaner call-site syntax (`result.ais`) but breaks
  the existing record-schema convention. Rule 11 (match the codebase's
  conventions) wins.
- **Just the float.** Loses the defect breakdown §4 requires.
- **Float + defects tuple.** Same content, less discoverable.

---

## Wilson confidence interval — inline implementation

§4 specifies Wilson interval at 95%, not Wald or Clopper-Pearson.
Implement inline (~10 lines, closed form). No new dependency.

The Wilson interval at confidence level 1−α for k successes in n trials:

```
center = (k + z²/2) / (n + z²)
spread = z * sqrt(k*(n-k)/n + z²/4) / (n + z²)
ci_low  = center - spread
ci_high = center + spread
```

…where `z = 1.96` for 95% confidence. Handles `n = 0` by returning
[0.0, 1.0] (the trivial bounds).

INV-8 anchor: verify against `n=100, k=95 → roughly [0.886, 0.978]`
in a test before locking. If the test passes the formula is correct;
if it doesn't, the implementation is wrong, not the spec.

Rejected: `statsmodels.stats.proportion.proportion_confint`. Adds a
~50MB dependency for one closed-form function. Over-fetching.

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
  injected via attacker-shaped alerts) as a `frozenset`.
- The harness calls `score_ais(claimed_log, gt_log, adversarial_triples)`
  once per baseline, stores results, and produces the curve.

### For the test suite

- Tests construct synthetic claimed/ground-truth log pairs covering
  each defect shape and the matching case.
- One test per defect shape (4 total: match + 3 defect types).
- One test for symmetric handling (both unpaired directions produce
  defects, with the right shape).
- One test for the adversarial filter (non-adversarial calls don't
  enter the denominator).
- One test for the Wilson CI (known case verification, INV-8 anchor).
- One test for the empty-set case (`n = 0` returns valid result, not
  a divide-by-zero).
- One test for the timestamp-equality property (claimed and true
  records that came from the same closure carry the same float;
  this is the load-bearing pairing test).

### For the §6 baseline sweep

- Each baseline produces one `ScorerResult`.
- The four results compose into the §6 curve.
- The defect breakdown across baselines is what supports the §6
  finding ("Baseline 3 attribution fails uniformly on actor and
  principal_chain, not scope").

---

## Open questions deferred

These are decisions we deliberately did NOT make in v1, along with
the trigger conditions for revisiting them. Naming them here prevents
re-litigation during the build and tells a reviewer which cases were
considered and bounded.

- **Floating-point timestamp equality for pairing.** The recorder's
  closure pattern pins `ts` once and both records carry the same
  Python float object, so `==` is exact in v1. The pairing test
  verifies this property explicitly — both records carry the same
  float value (and, where Python's float identity holds, the same
  object). If a future serialization layer (JSON, database) breaks
  this property, the test fails loud rather than the scorer silently
  mispairing. **Trigger to revisit:** test fails for precision-loss
  reasons → switch to small-epsilon equality (`abs(t1 - t2) < 1e-9`)
  with the limitation documented.

- **Should the scorer log its own findings to a file?** v1 returns
  the result object only; the harness owns persistence (same pattern
  as the tool). Mixing computation and persistence in the scorer
  would couple it to a file-format decision and force cleanup
  fixtures in every test. **Trigger to revisit:** if multiple harness
  consumers reinvent the same persistence layer, then a
  `scorer.write_report(result, path)` helper might be worth adding.

- **Multi-baseline aggregation.** §6's curve compares four baselines.
  The scorer is per-baseline by design; aggregation across baselines
  (marginal improvement, comparative plotting, the §6 table)
  lives in the harness/sweep code, not here. **Trigger to revisit:**
  none — this separation is deliberate and should hold.

---

## Cross-references

- **threat-model.md §4** — AIS metric definition, ground-truth schema,
  Wilson CI requirement.
- **threat-model.md §6** — predicted curve; the scorer is what
  produces measured values to compare against.
- **CLAUDE.md INV-7** — pre-registered predictions; the scorer
  enforces §4 honestly so contradictions surface.
- **CLAUDE.md Rule 11** — match the codebase's conventions; dict
  result follows existing record-schema pattern.
- **recorder_notes.md** — shared-clock design that enables the
  triple-pairing key.
- **tools_notes.md** — Boundary-4 record schema this module consumes.

---

# ==== v2 additions ====

*Implementation: `v2/aegis_at_v2/harness/scorer.py` (LIS) and
`harness/sweep.py` (the curve emitters). Pre-registered in
`threat-model-v2.md §4.2 / §6`. The AIS path above is ported verbatim and
unchanged; v2 adds a second, parallel metric.*

## score_lis() — the Log Integrity Score (§4.2)

`score_lis(tampered_indices, detected_indices) -> LisResult`
(scorer.py:181–218). Symmetric in spirit to `score_ais` but measuring a
**different question**:

```
LIS = | tampered ∩ detected | / | tampered |
```

- `tampered_indices` — which committed log entries the harness rewrote
  after the fact.
- `detected_indices` — which the log's chain verification flagged
  (`TamperEvidentLog.verify`, see `tamper_logV2.md`).

Two boundary conventions, both deliberate:
- **No tamper injected** (`tampered` empty) → LIS = 1.0 ("nothing to
  miss", scorer.py:203–210).
- **No integrity artifact** (B1–B3, B5: `detected` empty, `tampered`
  non-empty) → LIS = 0.0 **by definition** — a rewrite is undetectable.

`LisResult` (scorer.py:173–178) carries `lis`, `detected`, `tampered`, and
both sorted index lists, for the same forensic-inspection reason the
`Defect` list exists on the AIS side.

## The AIS/LIS asymmetry is the point (§6.3)

The docstring states it explicitly (scorer.py:196–199): a baseline can
score **LIS = 1.0 and AIS = 0.0 simultaneously**. LIS asks "was a post-hoc
rewrite caught?"; AIS asks "is the recorded actor correct?". B4 is exactly
this: tamper-proof (LIS=1.0) yet mis-attributing (AIS=0.0), because the
wrong actor was committed upstream at minting, before any logging layer
saw the entry. The two metrics are scored and reported **separately** —
never combined into one number — so this asymmetry stays visible. A
reviewer who expects "tamper-evident ⇒ trustworthy attribution" is exactly
who this separation is for.

## Why LIS is a pure function (no log object dependency)

`score_lis` takes two index lists, not a `TamperEvidentLog`. The tamper
injection and `verify()` happen in the harness/sweep layer; the scorer
only divides. This mirrors v1's "scorer is pure computation, harness owns
orchestration" decision — the scorer never reaches into the log, the same
way it never reaches into the tool or recorder. Keeps the scorer testable
with synthetic index lists and free of integrity-artifact state.

## sweep.py: measure_lis() + emit_lis_curve()

The sweep gained an LIS pass parallel to the AIS curve: per baseline it
writes entries, signs the head, rewrites a committed entry, calls
`verify`, and feeds the indices to `score_lis`. `emit_lis_curve` produces
the per-baseline LIS curve (B1–B3, B5 = 0.0; B4 = 1.0) alongside the AIS
curve. The two curves are emitted from one sweep so the B4 AIS=0.0 /
LIS=1.0 cell is produced by the same run — no chance of the two metrics
coming from different configurations.

## Note on is_non_monotonic() and Phase 4

`is_non_monotonic` (scorer.py:221–242) still checks `b4 == b3` exactly. Its
own docstring flags the evolution: while B4 ran B3's code path that
equality was exact; now that B4 has a real hash-chained execution, the
intended form is `abs(b4 - b3) < eps`. The AIS values are still exactly
equal in the deterministic runs (B4 AIS = B3 AIS = 0.0 by §6.3), so the
exact check still passes — but the tolerance form is the correct shape for
the stochastic sweep (§8), where it should be updated. Flagged here so it
isn't mistaken for an oversight (Rule 12 / surface conflicts).

## v2 cross-references

- **tamper_logV2.md** — `TamperEvidentLog.verify` that produces
  `detected_indices`.
- **threat-model-v2.md §4.2 / §6.2 / §6.3** — locked LIS definition and
  the AIS/LIS asymmetry prediction.
- **SweepNotes.md** — the curve-emission layer that drives both metrics.