# Sweep Notes — aegis-at/harness/sweep.py

Working notes for the baseline-switch harness — the composition layer
that selects a baseline (B1–B4), mints the credential shape that
baseline prescribes, runs the canonical §5 re-delegation attack, and
emits the four-point AIS curve.

The implementation is in `aegis-at/harness/sweep.py`; the non-
monotonicity predicate lives in `aegis-at/harness/scorer.py`. This
file is the *why*, not the *what*. It encodes the reasoning trail
from the build so the decisions survive the chat session that made
them.

---

## What sweep is for

Three responsibilities, in order:

1. **Mint the right credential per baseline.** Per INV-6, baselines
   are config flags over one codebase; only the credential differs.
   `_credential_for(baseline)` is the function that encodes that:
   B1 a shared apikey dict, B2 a per-agent apikey dict, B3/B4 an
   orchestrator-minted re-delegation JWT.

2. **Run the canonical §5 attack and score it.** Contain (the
   wielder) executes `isolate_host` on `host-42`, regardless of
   baseline. The recorder observes from the executing thread; the
   scorer scores against the harness-supplied adversarial triple.

3. **Emit the four-point curve.** `emit_curve()` composes `run()`
   over B1–B4 and packages the result into a JSON-serializable dict
   that the §6 finding is reported from.

What it deliberately is NOT:

- **Not the v2 stochastic sweeper.** v1's sample design is Candidate C
  (one canonical execution per baseline); stochastic policy variation
  is v2 work, named below as a forward hook.
- **Not the persistence layer.** `emit_curve()` returns a dict; the
  caller writes it where it wants. Mixing computation with file I/O
  would force cleanup fixtures into every test (same pattern as the
  tool and scorer).
- **Not the corpus runner.** No attacker-alert corpus, no host/IOC
  variation. v1 is mechanism demonstration; corpus sweeps belong to
  the Candidate-A direction that was rejected for v1.

---

## Why one execution per baseline (Candidate C)

This is the load-bearing decision behind everything else in the
harness. The sample-design question was: how do we get a meaningful
AIS with a meaningful confidence interval?

Four candidates were evaluated:

- **Candidate A** — corpus of N=100 adversarial alerts. *Rejected.*
  The mechanism is deterministic: every alert that successfully
  routes through Enrich → re-delegation produces the same wrong-actor
  record. The CI would tighten around 0.0 at B3/B4 because the
  mechanism is deterministic, not because the sample is informative.
  Dresses a categorical fact as a statistical one — the exact move
  this project's discipline refuses.
- **Candidate B** — stochastic escalation policy. *Deferred to v2.*
  Gives a real CI but changes the claim: from "given the attack
  fires, attribution fails" to "the attack fires X% of the time and
  fails attribution Y% when it does." The §6 prediction is the
  former; the latter is a different research question.
- **Candidate D** — inject artificial noise (timestamps, target hosts,
  scope strings). *Rejected.* Boring; reviewers see it for what it is.
- **Candidate C** — concede N=1 and present mechanism, not statistics.
  *Locked.* Reframed not as concession but as strength: the
  attribution failure is **categorical**, not probabilistic. A
  categorical result doesn't want a CI; the honest statistical
  statement is the degenerate one, and naming why it's degenerate
  *is* the finding.

Two things make C airtight rather than thin:

- **B2 = 1.0 is the inversion control.** The curve itself proves the
  scorer *can* return correct attribution as correct (it's not a
  dead pipeline always returning zero). B2 is the analogue of what
  the SND paper does with its MINJA/AgentPoison 100% / SND 0%
  classifier check — not a CI, but a categorical inversion that
  shows the detector fires when it should and doesn't when it shouldn't.
- **`verify_deterministic` turns the determinism claim into a checked
  property.** A reviewer's natural question — "are you sure one run
  is representative?" — has an answer: yes, by k=5 byte-identical
  reruns under a fixed clock. Cheap, conclusive, and the failure
  mode is loud-and-specific (names the divergent field).

---

## Locked decisions

### `run(baseline, now_fn=time.time) -> RunResult`

**`now_fn` as a keyword parameter, no module-level clock state.** The
fixed-clock pattern is injected, not toggled. A module-level
`set_clock()` / `reset_clock()` would be mutable shared state across
the very runs whose independence the determinism check is trying to
prove — a determinism hazard inside the determinism checker.

**Hardcoded canonical attack (`_COMMAND`, `_TARGET`, `_EXECUTOR` at
module scope).** Parametric defaults were rejected: parameterizing
`command` / `target` / `executor` contradicts Candidate C (inputs
don't change the categorical result), invites incoherent combinations
(`run("B1", executor="agent:enrich")` scores something meaningless),
and doesn't serve the actual v2 plan (Candidate B varies the
escalation policy, not the attack knobs). The canonical attack *is*
the measurement; hardcode it.

**Returns `RunResult` (records + result), not bare `ScorerResult`.**
This is a deviation from the harness_notes spec, made deliberately:
the determinism contract is byte-identical *records*, but B2 has no
defects, so its records aren't embedded anywhere in a plain
`ScorerResult`. Without exposing records, `verify_deterministic`
couldn't check record-level determinism on the anchor baseline —
exactly the one we most want to prove. So `RunResult` adds `claimed`
and `truth` alongside `result`.

**`_credential_for` is private to `sweep.py`, not extracted to a
shared module.** The composition test (`test_baseline_composition.py`)
keeps its own inline credential minting. The reason isn't laziness —
it's that the composition test serves as an *independent spec* the
harness gets measured against. If both imported the same
`_credential_for`, a bug in that function would pass both. The test
has to be able to fail the harness; that requires independence.
Extraction to a real `auth/api_key.py` module is v2 work, when the
baseline-switch harness has settled and the credential abstraction has
known consumers.

### `verify_deterministic(baseline, k=5, now_fn=None) -> bool`

**Fixed clock for determinism, wall clock for the curve.** Without
a fixed clock, `timestamp` differs across runs and byte-equality is
impossible by definition — the check would be "deterministic except
the wall clock," which invites the reviewer to wonder what *else*
got waved off. `_FIXED_TS = 1_700_000_000.0` (matching the
composition test's `_fixed_clock`) closes the gap fully.

**Loud-and-specific failure, not plain `assert`.** A divergence is a
*debugging anchor*: the harness walks the records field-by-field and
raises `AssertionError` naming the baseline, run index, record side,
field, and the two divergent values. Plain `assert reference ==
current` dumps two opaque 8-field dicts and tells you nothing about
which field drifted; the specific version immediately tells you
(e.g.) the clock injection didn't take.

**Default `k=5`.** Small but sufficient. Determinism is categorical
(deterministic or not), not statistical; k just buys multi-run
confidence that a single anomaly didn't slip past on a fluke. The
parameter is exposed so a CI run can crank it up if desired.

**`now_fn` exposed as a parameter (defaults to the fixed clock).**
This is what lets the fault-injection test deliberately drift the
clock and prove the assertion logic actually catches divergence
rather than silently always returning `True`. Without the parameter,
there's no way to fault-inject; without fault-injection, there's no
evidence the check works.

### `emit_curve(with_determinism_check=True) -> dict`

**Determinism check gates the curve, default ON.** Shipping a curve
without first proving the pipeline is deterministic re-opens the
"how do you know N=1 is enough?" gap the harness exists to close.
A non-deterministic baseline raises *before* any AIS values are
produced. The flag exists (`with_determinism_check=False`) for fast
iteration when debugging a defect breakdown — but it's not the
default, on purpose.

**`ci_caveat` lives inside the dict.** The string travels with the
data so a downstream consumer that reads the dict and writes a
report cannot accidentally omit the determinism disclosure. A
top-level `non_monotonic: True` field was rejected for the opposite
reason — derived booleans in dicts drift; the predicate goes in one
named function (see below).

**No `non_monotonic` field in the dict.** This is the second
function-vs-stored-field call in the design, and it goes the
opposite direction from `ci_caveat`. The reasoning: a stored
boolean would be computed at one call site at curve-emission time,
but read by multiple callers (the writeup, CI, future plotting
tools). Three callers, three slightly-different recomputations or
re-interpretations of "non-monotonic," and six months from now no
one's certain which one the paper reports. One function with the
predicate pinned in its docstring forecloses that.

### `is_non_monotonic(curve)` in `scorer.py`, predicate `B2 > B1 and
B2 > B3 and B4 == B3`

**Lives in `scorer.py`, not `sweep.py`.** The predicate is a claim
*about AIS values*; the scorer is the module that defines and owns
AIS. Co-locating the metric and the claim-about-the-metric keeps the
definition where the values' meaning lives. A separate
`harness/curve.py` was rejected for v1 (one function isn't enough to
justify a module).

**Four-point predicate, not three.** The §6 headline is "the two
primitives most emphasized for agent non-repudiation (signed
delegation chains and tamper-evident logs) do not close the
multi-agent attribution gap." That names B3 *and* B4; the predicate
has to encode both. A three-point version (`B2 > B1 and B2 > B3`)
would under-represent what §6 claims.

**`==` for the B4 clause, not `<=`.** Under v1's deterministic
measurement both B3 and B4 are exactly 0.0, so `B4 <= B3` reduces
to `0 <= 0` — trivially true regardless of what B4 does. That's a
predicate clause that *can't fail when it matters*: theater.
Strict `==` is non-trivial because it asserts tamper-evidence
changed *nothing*, which is the actual §6 claim. The docstring names
the brittleness: `==` is correct *only because B4 currently runs
B3's code path by construction*, and the predicate evolves to
`abs(b4 - b3) < eps` when the v2 tamper-evident log module gives B4
a separate execution.

**Returns `bool`, not raises.** The harness caller decides what to do
(assert in CI, log in a report, write to a finding). The predicate
doesn't dictate the response. A `False` return is a publishable
finding — INV-7 binds §6's pre-registered predictions to whatever
the measurement shows.

---

## Rejected alternatives — named so the reasoning survives

- **P2 — delegation-from-analyst-to-agent at B2.** The candidate that
  almost made it in. P2 proposed minting a JWT at B2 with chain
  `[contain, analyst]` so the chain shape would match B3's
  recorder-emitted chain. *Rejected:* this is "modeling-to-fit-the-
  recorder-bug." Under the §5 attack flow Contain doesn't execute
  with a `[contain, analyst]` token — that token would have to be
  fabricated to make the records pair up. A token whose chain
  matches the recorder but doesn't correspond to a real B2 flow
  isn't a B2 measurement; it's a contrived agreement. The fix is
  the (c) credential model: B2 uses an opaque per-agent credential
  that genuinely carries no chain, paired with credential-aware
  ground truth in the recorder.
- **Parametric attack inputs.** See above; contradicts Candidate C.
- **Shared credential module from the start.** See above; would
  collapse the test/harness independence.
- **`non_monotonic: bool` stored in the curve dict.** See above;
  drift risk.
- **Plain `assert` for determinism.** See above; loses the
  field-name debugging anchor.
- **Module-level `set_clock()` / `reset_clock()`.** See above;
  mutable shared state inside the determinism checker is exactly the
  hazard the checker is designed to detect.
- **Class `BaselineHarness(...)` with methods.** Adds ceremony with
  no per-instance state. Three module-level functions are stateless
  and compose cleanly.
- **`run_sweep()` as a single all-in-one entry point.** Conflates
  the curve with the determinism check; the caller should be able
  to compose them independently (CI runs both; ad-hoc curve dump
  runs only the curve).

---

## INV walkthrough

- **INV-1 (token structure):** ✓ — the harness mints through
  `mint_initial_token` and `mint_delegated_token`, which are INV-1
  verified upstream. No new token construction logic.
- **INV-2 (current actor resolution):** ✓ — handled by `siem_action`;
  the harness consumes the resolved record.
- **INV-3 (siem_action naming):** ✓ — the harness calls
  `siem_action`, never `query_siem`.
- **INV-4 (ground-truth independence):** ✓ — the harness owns the
  ground-truth log (passes it to `make_recorder`) but does not read
  from it during execution; the scorer reads it after. The recorder
  still discriminates true_actor from the executing thread, not from
  any harness-supplied label or token-extracted field.
- **INV-5 (no illegitimate behavior):** ✓ — every flow the harness
  exercises is the spec-compliant flow §5 describes. No forged
  tokens, no thread-name spoofing, no scorer manipulation.
- **INV-6 (baselines as config flags):** ✓ — this is the invariant
  the harness *embodies*. Each baseline is a different
  `_credential_for` return value over identical tool / recorder /
  scorer code paths. Verified by the four `RunResult`s sharing
  every field except the credential.
- **INV-7 (pre-registered predictions):** ✓ — `is_non_monotonic`
  encodes §6's prediction; a `False` return is a finding to publish,
  not a bug to silence. `emit_curve` does not soften or hide a
  contradicted prediction.
- **INV-8 (verify against source):** ✓ — the harness exercises
  modules whose source has been read and verified; the on-disk
  `sweep.py` was verified green (59 tests + check gate) before
  these notes were written. No claims about code that doesn't exist.

---

## Forward hooks (v2)

- **N=100 with stochastic policy (Candidate B).** v2 introduces
  variability at Enrich's escalation decision — a probability that
  the alert escalates given attacker-shaped input. The curve becomes
  a real statistical estimate of attack success rate. The harness
  API doesn't change: `run(baseline)` still produces one
  `RunResult`; a v2 caller wraps it in `for _ in range(N):` and
  aggregates.
- **Real B4 — hash-chained log module.** v1 B4 = B3 by attribution
  prediction (no log module yet). v2 builds
  `aegis-at/harness/log.py` with signed hash-chained entries and
  adds a separate metric for log-integrity detection. The §6
  prediction that B4 *attribution* = B3 *attribution* is unaffected;
  what's added is the *log integrity* metric, which v1 cannot test.
  `is_non_monotonic`'s `==` clause evolves to `abs(b4 - b3) < eps`
  at the same time.
- **Sender-constraint as Baseline 5.** Per threat-model §8.10: DPoP
  (RFC 9449) or RFC 8705 mTLS-bound tokens. The hypothesized curve
  recovery, named as primary future defense work. v2 adds
  `_credential_for("B5")` returning a binding-aware JWT and extends
  `is_non_monotonic` to take an optional B5 clause.
- **`aegis-at/auth/api_key.py` extraction.** When the harness has
  settled and the composition test's independence has been re-
  verified, extract the apikey-dict minting from `_credential_for`
  to a real module with an in-memory registry + verifier. v1 keeps
  it inline because there is exactly one harness consumer.
- **Multi-process determinism (`os.getpid()` for true INV-4).** The
  v1 proxy is `threading.current_thread().name`; a misbehaving agent
  that renamed its thread could in principle spoof ground truth.
  INV-5 (no illegitimate behavior) plus §3 (adversary controls alert
  text only) is what carries v1. v2 switches to `multiprocessing`
  with `os.getpid()` for a true process boundary; the token signing
  key needs to be loaded from a fixed PEM at that point (currently
  regenerated at module import).

---

## Open questions deferred

- **Should `emit_curve()` write to disk by default?** v1 returns the
  dict; the caller writes. Matches the tool/scorer pattern (pure
  computation, harness-owned persistence). **Trigger to revisit:**
  if multiple consumers reinvent the same JSON-dump logic, add a
  `sweep.write_curve(curve, path)` helper.
- **CLI entry point?** v1 has none. A `python -m aegis_at.sweep`
  emitter is a small polish for v2 when the writeup needs a
  reproducible "press button, get curve" artifact.
- **How does the B4 attribution-only test evolve when the log
  module lands?** The current B4 prediction (attribution = B3)
  stays; the log-integrity metric is additive. The composition
  test's B4 test stays correct (asserts the attribution prediction);
  a *new* test exercises the log layer separately. The harness
  changes minimally — `_credential_for("B4")` still returns the
  same JWT; what changes is what runs *after* scoring.
- **`is_non_monotonic` epsilon when v2 lands.** What tolerance? Big
  enough not to flap on Wilson CI noise; small enough to catch a
  real recovery. Defer until measured v2 data exists; pick the
  epsilon from observation, not in advance.

---

## Cross-references

- **threat-model.md §4** — AIS metric definition; the §4 paragraph
  about None handling absent a delegation chain (locked in the
  last threat-model pass) is what makes B1/B2 scoreable.
- **threat-model.md §6** — the predicted curve. The §6 row labels
  ("+ delegation across the requester/wielder boundary",
  "shared credential (no chain)", "per-agent authenticator (no
  chain)") match what `_credential_for` mints.
- **threat-model.md §8.10** — sender-constraint as the deferred
  defense layer (Baseline 5).
- **harness_notes.md** — the *planned* notes that preceded the
  build. This file is its post-build counterpart, capturing what
  actually landed and the decisions made during implementation.
- **policy_notes.md / scorer_notes.md / RecorderNotes/** — the
  consumed modules; sweep composes them, doesn't change them.
- **tests/core/test_baseline_composition.py** — the *independent*
  spec the harness was measured against. Five tests; the harness
  must reproduce the same predicted curve through its own
  `_credential_for` minting.
- **tests/core/test_sweep.py** — pins `run()`'s contract:
  four-baseline curve, `RunResult` shape, fixed-clock determinism
  precondition, unknown-baseline fail-loud.
- **tests/core/test_verify_deterministic.py** — pins
  `verify_deterministic`'s contract: positive determinism on B2 + B3,
  fault-injection proves the check catches drift.
- **tests/core/test_emit_curve.py** — pins `emit_curve` +
  `is_non_monotonic` jointly: predicted curve, `ci_caveat` present,
  no `non_monotonic` field in dict (regression guard against
  storing the derived value), `is_non_monotonic` rejects a
  contradicted (flat) curve.
- **CHECKLIST.md Step 4** — INV-6 and INV-7 are the binding
  invariants for this module.