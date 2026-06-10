# Threat Model v2 — Attribution Integrity Benchmark (AEGIS-AT)

> **Status: PRE-REGISTERED AND LOCKED.** This file is hash-locked by
> `threat-model-v2.sha256` and the CI test `v2/tests/test_threat_model_v2_locked.py`.
> Any edit fails the build. To change a prediction, add `threat-model-v2.1.md`
> with its own lock — never silently edit this file.
>
> Every v2 test asserting an AIS / LIS / CI value cites its prediction by
> section number (`threat-model-v2.md §X.Y`) in its docstring.

---

## §1. Relationship to v1

v1 (`threat-model.md`, frozen; code under `v1/`) established the finding:
RFC 8693 delegation regresses attribution from AIS = 1.0 (per-agent identity,
B2) to AIS = 0.0 (B3), and tamper-evident logging (B4, attribution-only stub)
does not recover it. The curve B1=0, B2=1.0, B3=0, B4=0 was pre-registered,
then reproduced deterministically (59 tests).

v2 retires four limitations v1 conceded in its §8 / the paper's §11–§12,
without re-opening anything v1 got right:

| v1 concession | v2 change | This file |
|---|---|---|
| §8.9 thread-name ground-truth proxy | process-boundary recorder (`os.getpid()`) | §3 |
| §8.10 sender-constraint named, not measured | Baseline 5: DPoP-bound tokens (RFC 9449) | §5 |
| Boundary 4 / §6 B4 attribution-only stub | real hash-chained log + LIS metric | §6 |
| §8.1 n=1 topology | 3-agent linear topology T2 | §7 |
| §4 degenerate CIs (categorical attack) | stochastic policy + Wilson CIs | §8 |

Everything not restated here is inherited from v1's threat model unchanged:
the system under test (§1–§2 of v1), the adversary model (§3 of v1), the AIS
metric definition (§4 of v1), the attack mechanism (§5 of v1), and baselines
B1–B4 (§6 of v1).

## §2. Adversary model delta

The v2 adversary is the v1 adversary (alert-content control only; no token
forgery; no process compromise; no ground-truth access) with two additions
scoped to Baseline 5:

- **§2.1 — Token lift attempt.** The mechanism B5 must defeat is the v1
  hand-off itself: Contain presenting a token whose `cnf` is bound to
  Enrich's key. This is not new adversary capability — it is the same
  legitimate-component hand-off from v1 §5 — but under B5 it becomes the
  event the defense must refuse.
- **§2.2 — Proof replay attempt.** The harness replays a previously-valid
  DPoP proof (same `jti`) against `siem_action`. The replay cache must
  reject it. The adversary still cannot steal private keys: each agent's
  DPoP keypair is generated in, and never leaves, that agent's process.

INV-5 still holds: no component misbehaves. The lift and the replay are
injected by the harness as test stimuli, not modeled as agent misconduct.

## §3. Process-boundary ground truth (replaces v1 §8.9 proxy)

The v2 recorder identifies the true actor by **OS process identity**:
agents run as `multiprocessing.Process` children; the harness records the
agent registered for a PID **before the agent's user code runs**, and
resolves `true_actor` from `os.getpid()` observed at the harness-side tool
wrapper. Identity never derives from a token or any agent-supplied field
(INV-4: process boundary, credential isolation, causal precedence — all
three axes from v1 §2 Boundary 5 carry over, now with a real process
boundary instead of a thread-name proxy).

**§3.1 — Prediction (regression gate).** Re-running v1's two-agent topology
T1 under the subprocess harness reproduces the v1 curve exactly:
B1 = 0.0, B2 = 1.0, B3 = 0.0, B4 = 0.0. If it does not, the new harness is
wrong — not the v1 result.

**§3.2 — Prediction (spoof resistance).** An agent that renames its thread
or its process title does not change PID-based attribution. AIS for the
spoof-attempt run equals AIS for the clean run on every baseline.

## §4. Metrics

**§4.1 — AIS.** Unchanged from v1 §4: strict triple match on
`(actor, scope, principal_chain)` over adversarial actions, per baseline.

**§4.2 — LIS (Log Integrity Score), new.** For a log of N entries subjected
to an adversarial rewrite of k ≥ 1 entries after writing:

```
LIS(B) = (# tampered entries detected by chain verification) / (# tampered entries)
```

LIS = 1.0 means every injected tamper is detected; LIS = 0.0 means none is.
For baselines without a hash chain (B1–B3, B5) there is no integrity
artifact to verify, so LIS is **0.0 by definition** (a rewrite is
undetectable). LIS is reported with the same Wilson interval machinery as
AIS where the denominator is a sample.

**§4.3 — Expanded denominator, new.** Alongside the v1 adversarial-trigger
AIS, v2 reports AIS over **all re-delegated containment actions** (attacked
or not), per v1 §8.8's structural-property framing. Prediction: the two
denominators yield the same per-baseline AIS values, because the
misattribution is latent in the re-delegation pattern, not created by the
attacker.

## §5. Baseline 5 — DPoP-bound tokens (RFC 9449)

The headline v2 measurement: does sender-constraint recover attribution?

**§5.1 — Mechanism.** Each agent holds a DPoP keypair. Tokens minted for an
agent carry `cnf: {"jkt": <thumbprint of that agent's public key>}`
(RFC 9449 §6 / RFC 7800). `siem_action` requires, on every call:

1. a valid DPoP proof JWT (`htm`, `htu`, `iat`, `jti`) signed by the
   caller's key;
2. `proof key thumbprint == token.cnf.jkt`;
3. `jti` absent from the replay cache (bounded TTL, held in the parent
   harness process);
4. `iat` within the proof window (default 60 s).

The orchestrator, when re-delegating, requires a DPoP proof from the agent
that will receive the new token and binds the new token's `cnf` to that
agent's `jkt`. Non-B5 baselines pass `cnf = None` and are unchanged.

**§5.2 — What B5 changes about the v1 hand-off.** Under B1–B4, Contain can
present the token minted naming Enrich (unbound bearer). Under B5 that
presentation fails check (2): the token's `cnf.jkt` is Enrich's thumbprint,
and Contain cannot produce a proof under Enrich's key. Contain must obtain
its own token — naming itself as current actor — so the claimed actor
tracks the executor.

**§5.3 — Prediction (the lock).** **B5 AIS = 1.0 on both topologies (T1
and T2).** If measured otherwise, that is the v2 finding and is reported as
such; the pre-identified candidate cause is a gap in how `cnf` binding
survives multi-hop re-exchange (T2). No code is written to make the
prediction true beyond the mechanism specified in §5.1.

**§5.4 — Prediction (replay).** A replayed proof (`jti` reuse) is rejected;
a stale proof (`iat` outside the window) is rejected. Neither produces a
logged action.

## §6. Hash-chained log + B4 made real

**§6.1 — Mechanism.** Each log entry under B4 carries
`prev_hash = SHA-256(entry_bytes || prev_hash)`; the chain head is signed
by a logger key held only by the parent harness process (same isolation
pattern as the recorder — no agent, orchestrator, or tool holds it).

**§6.2 — Prediction (integrity).** B4 LIS = 1.0 under tamper injection
(harness rewrites a random committed entry; verification catches it).
B1–B3 and B5 LIS = 0.0 (no chain; §4.2).

**§6.3 — Prediction (attribution unchanged).** **B4 AIS remains 0.0** with
the real chain. The wrong actor is committed upstream at minting, before
any logging layer sees the entry — v1's Boundary 4 argument, now backed by
a real artifact instead of a stub.

## §7. Topology T2 — 3-agent linear chain

**§7.1 — Shape.** Enrich → Investigator → Contain, a linear chain of
depth 2 (two re-delegation hops). Investigator is a mid-chain agent with
read-plus-correlate scope; it receives Enrich's escalation, performs its
own (correct) judgment, and re-delegates containment onward. Linear is
chosen over fan-in deliberately: linear isolates the chain-depth question;
fan-in introduces concurrent-write log-ordering confounds outside the
question v2 asks.

**§7.2 — Prediction.** The full B1–B5 sweep on T2 yields the same curve
shape as T1: B1 = 0.0, B2 = 1.0, B3 = 0.0, B4 = 0.0, B5 = 1.0. At B3/B4
the claimed actor on T2 is the *most recent requester in the chain*
(Investigator, the deepest re-delegating agent) — still not the executor
(Contain) — so the gap persists at depth 2; it does not heal with depth.

**§7.3 — Regression.** T1 remains in the sweep; its curve must continue to
match v1 (§3.1).

## §8. Stochastic policy + Wilson CIs

**§8.1 — Design.** Enrich's escalation becomes Bernoulli(p),
p ∈ {0.1, 0.5, 0.9}, seeded and reproducible. N = 100 attacks per
(topology × baseline × p) cell, floor. **Adaptive escalation:** any cell
with Wilson 95% half-width > 0.1 at N = 100 is extended to N = 500.

**§8.2 — Prediction.** The curve shape is invariant across p — the
regression is structural (v1 §8.8), so p scales the *number* of adversarial
actions in the denominator, not the per-action correctness. Point
predictions per cell: B1 = 0.0, B2 = 1.0, B3 = 0.0, B4 = 0.0, B5 = 1.0,
with Wilson intervals that must contain these values. Boundary cells with
few adversarial actions (B1 at p = 0.1) may have wide intervals at N = 100;
that is what the adaptive escalation is for, not a prediction failure.

**§8.3 — Reporting.** Both denominators of §4.3 are reported for every
cell. No cell may be dropped; a cell that contradicts §8.2 is a finding.

## §9. What v2 still concedes (named so the omissions are deliberate)

| ID | Concession | Reason to defer |
|---|---|---|
| L1' | n = 2 topologies (T1, T2); fan-in and cross-org untested | each adds confounds (concurrent writes; cross-trust-domain); v3 |
| L4' | DPoP only; mTLS-bound tokens (RFC 8705) named, not measured | requires TLS infrastructure; predicted to behave identically; v3 Baseline 5b |
| L6 | scripted agents, no LLM-in-the-loop | API-key dependency breaks reproducibility; invites scope creep; v3 |
| L9 | synthetic Bernoulli policy, not real user behavior | real telemetry awaits an industry partner; v3 |

## §10. Change discipline

- This file is committed **before** any v2 attack or defense code.
- `threat-model-v2.sha256` records SHA-256 over the LF-normalized bytes of
  this file (CRLF → LF before hashing, so Windows checkouts hash
  identically).
- `v2/tests/test_threat_model_v2_locked.py` recomputes the hash on every
  test run and fails on any drift.
- Amendments go in `threat-model-v2.1.md` (and so on), each with its own
  lock. The amendment states what changed and why. The original is never
  edited.
- A measurement that contradicts a prediction in §3, §5, §6, §7, or §8 is
  reported as a finding. It is never coded around (INV-7).

---
