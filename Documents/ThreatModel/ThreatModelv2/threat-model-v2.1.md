# Threat Model v2.1 — Amendment to v2.0

> **Status: AMENDMENT, hash-locked.** This file is locked by
> `threat-model-v2.1.sha256` and the CI test `v2/tests/test_threat_model_v2_locked.py`.
> It amends `threat-model-v2.md` (v2.0) per that file's §10 change discipline.
> **No pre-registered prediction changes.** Every locked value in v2.0
> (B5 AIS = 1.0; T2 curve; B4 LIS = 1.0 / AIS = 0.0; stochastic point
> predictions) stands verbatim. This amendment adds disclosures and
> clarifications surfaced in external review; it does not relax, tighten, or
> retrofit any prediction. v2.0 remains the immutable pre-registration of the
> predictions; this file is the immutable record of the clarifications.

---

## §A0. Why this amendment exists

An external review of the v2.0 artifact raised five points that are matters
of *disclosure and precision*, not of prediction. Per v2.0 §10 ("the original
is never edited; amendments go in `threat-model-v2.1.md`"), they are recorded
here and re-locked. Each is cross-referenced to the v2.0 section it refines.

## §A1. Tool-execution context — a real change to the measurement substrate (refines §3, §9)

**The fact.** In v1, an agent's thread called `siem_action` directly, in the
agent's own process. In v2, agents are `multiprocessing.Process` children and
the tool call crosses the process boundary: the agent sends
`(command, target, credential, proof)` over the kernel pipe, and the **parent
harness** invokes the recorder and `siem_action` on the agent's behalf
(`harness/sweep.py::run.tool_handler`). **The tool therefore executes inside
the harness process, not the agent process.** This is a genuine architectural
change and was under-stated in v2.0 §3, which described the recorder but not
the relocation of tool execution.

**Why it is necessary.** PID-based ground truth (§3) requires the harness to
resolve `os.getpid()` for the *executing* agent at the tool boundary. The
kernel registers the agent's PID at spawn and serves its tool calls; resolving
identity at the harness-side wrapper is what makes the recorder independent of
any agent-supplied field (INV-4). An in-agent tool call cannot be observed
this way without an out-of-band channel that would reintroduce a spoofable
self-report.

**Why it does not affect the result (validity argument).** The attack's three
load-bearing steps all occur *before* the tool call: alert-content injection
(Boundary 1), token minting (Boundary 2), and the re-delegation hand-off. The
tool's verification logic (`verify_token`, chain integrity, scope gate,
identity resolution, and the B5 DPoP check) is byte-identical to v1's and runs
on the same inputs regardless of which process hosts it. The credential each
baseline presents is unchanged. What moved is *where the verified record is
produced*, not *what is verified or what is recorded*. The harness was already
the measurement instrument (it owns the logs and the scorer); centralizing
tool execution puts the tool on the same side as the recorder it is compared
against, which is neutral to the claimed-vs-true comparison because the claimed
record still derives solely from the presented token and the true record still
derives solely from the kernel PID.

**Honest framing correction.** The v2.0 paper language "system under test
inherited verbatim from v1" is too strong. The correct statement: *the attack
path, delegation logic, token verification, and per-baseline credentials are
inherited unchanged; tool execution was centralized in the harness to enable
PID-based attribution.* This is added to the conceded limitations (below) and
to the paper's validity-threats section.

**§A1.1 — Added concession (extends §9).**

| ID | Concession | Why it does not threaten the result |
|---|---|---|
| L10 | Tool execution is centralized in the harness process (not the agent process) to enable PID-based ground truth. | The injection, minting, and hand-off all precede the tool call; the tool's verification logic and the presented credential are byte-identical to v1; only the host process of an unchanged computation moved. A production deployment would run the tool as its own service and observe the caller's authenticated identity at that service boundary — the same construction, relocated. |

## §A2. DPoP binding precision (refines §5.1)

**What the orchestrator verifies.** On a `cnf`-bearing exchange,
`orchestrator.mint_delegated_token` calls `dpop.verify_proof`, which checks
that the presented proof proves possession of the key whose thumbprint equals
`cnf` (plus htm/htu binding, freshness, and replay). It binds the minted
token's `cnf` to that proven key.

**What establishes name ↔ key correspondence.** The orchestrator verifies
*possession of the bound key*, not that the name written into `act.sub`
belongs to that key's holder. In the benchmark, the correspondence is
established two ways: (i) by construction — the harness mints the executor's
token naming the executor and bound to the executor's own freshly-generated
key; and (ii) at execution time — the agent that signs the *call-time* proof
the tool checks is the PID-registered executor (the kernel identity, §3), so
the key actually wielded at the resource is the executor's. The recovery to
AIS = 1.0 follows from the executor wielding a token bound to its own key and
naming itself.

**The variant explicitly out of scope.** "An agent obtains a token that *names
a different actor* but is bound to its *own* key" is principal laundering — a
distinct attack class v1 and v2 backlog (v1 §7 / v2.0 scope). Defending it
requires an orchestrator-side agent-key registry (name → registered key)
checked at mint time; that registry is named as the production requirement and
is future work. v2's B5 result is for the *token-lift* attack in scope (§5.2),
which is rejected because the lifted token is bound to the original holder's
key.

**Replay cache — correcting "bounded TTL."** v2.0 §5.1 says the replay cache
has a "bounded TTL." The implementation (`dpop.ReplayCache`) is in fact an
**unbounded, per-run, single-use `jti` set** held in the parent harness: a
fresh cache per `run()`, every `jti` single-use, no eviction. Because each run
is short and deterministic, no eviction is needed and no flakiness arises. A
production cache would bound retention to the proof window (default 60 s); the
v2 cache's lifetime is the run, which is shorter. This corrects the prose; the
behavior tested (replay rejected, §5.4) is unaffected.

**Proof generation location (confirmation, not change).** The call-time proof
is generated *inside the agent subprocess* (`agent_bodies.dpop_executor_body`
rebuilds the key from its PEM and signs in-process), so the private key never
crosses the process boundary; only the signed proof does. This is the intended
construction and is verified by the B5 tests.

## §A3. Investigator's scope is pinned (refines §7.1)

v2.0 §7.1 calls Investigator a "read-plus-correlate" agent. That describes its
*standing role*. The **containment token it re-delegates** carries
`siem:write`, exactly as Enrich's does in T1 — it must, or the executor
(Contain) could not perform `isolate_host`. Pinned precisely:

- Root token: `human:analyst`, scope `siem:read siem:write`.
- Every re-delegation hop (`agent:enrich`, then `agent:investigator` on T2)
  narrows to `siem:write` (`harness/sweep.py::_delegated_chain`).
- So under B3/B4 the claimed scope is `siem:write` and the true scope is
  `siem:write` — **scope matches on both sides; it is not a defect.** The
  defect is on `actor` and `principal_chain` only. Giving Investigator's
  containment token `siem:write` does not "prevent" the misattribution
  (scope agreement is expected and orthogonal to actor agreement); it is
  required for the action to execute at all, identical to v1's single hop.

This pins the per-hop scope so the T2 result cannot be attributed to an
unregistered scope choice.

## §A4. Stochastic seed and determinism (refines §8)

- The stochastic sweep is seeded by a fixed `base_seed = 20260610`
  (`stochastic.stochastic_sweep` default), recorded in the artifact. The whole
  grid is a deterministic function of this seed; the realized escalation
  counts and therefore the Wilson interval bounds are reproducible exactly.
- The tests assert the **point predictions** (per-cell AIS = the pre-registered
  bit) and interval *containment*, not exact bounds — the point values are
  seed-independent (structural), while the exact bounds are a deterministic
  function of the fixed seed.
- **Both denominators of §4.3 are reported.** The adversarial-trigger
  denominator (escalated trials, ~Bin(N, p)) and the expanded/structural
  denominator (all N re-delegated containments) yield identical point AIS;
  the expanded denominator gives tighter intervals (its size is always N). The
  paper now reports both columns.

## §A5. Predictions carried verbatim (no change)

For the avoidance of doubt, all v2.0 locked predictions are unchanged:
B1 = 0.0, B2 = 1.0, B3 = 0.0, B4 = 0.0, B5 = 1.0 on **both** T1 and T2;
B4 LIS = 1.0 with B1–B3, B5 LIS = 0.0; B4 AIS = 0.0 alongside LIS = 1.0;
stochastic curve shape invariant across p. This amendment adds no prediction
and removes none.

## §A6. Change discipline (unchanged from v2.0 §10)

This file is committed with its own `threat-model-v2.1.sha256` lock; the CI
test verifies both v2.0 and v2.1. A further amendment would be
`threat-model-v2.2.md`. Neither v2.0 nor this file is ever edited in place.
