# AEGIS-AT v2 — `aegis_at_v2/` package

The active Python implementation of the **Attribution Integrity Benchmark**.
Extends v1 (frozen under [`../../v1/aegis-at/`](../../v1/aegis-at/), git tag
`v1.0.0`) with five changes that retire v1's four conceded limitations and
measure the standardized fix v1 only named.

> 📖 **New here? Start at the [repository root readme](../../readme.md)** for
> the full story (the finding, why it matters, the attack, the threat model).
> This file is the developer-facing guide to the `aegis_at_v2/` package
> itself.
>
> The canonical, citable write-up is the 14-page v2 paper at
> [`../../Documents/Paper/v2/aegis-at-v2.pdf`](../../Documents/Paper/v2/aegis-at-v2.pdf).
> The full argument is locked in
> [`../../Documents/ThreatModel/ThreatModelv2/threat-model-v2.md`](../../Documents/ThreatModel/ThreatModelv2/threat-model-v2.md)
> + the
> [`threat-model-v2.1.md`](../../Documents/ThreatModel/ThreatModelv2/threat-model-v2.1.md)
> amendment.

## The question (extended from v1)

v1 measured whether the *recommended* primitives (per-agent identity, signed
delegation, tamper-evident logs) preserve attribution under sibling
impersonation. They did not — B3 regressed AIS from 1.0 to 0.0 and B4 stayed
at 0.0. v2 asks the open follow-up: does **sender-constraint (DPoP, RFC 9449)**
recover the curve, does the gap survive at chain depth ≥ 2, and is the
finding statistical (real CIs) rather than categorical?

## The finding (one line)

**B1 = 0.0, B2 = 1.0, B3 = 0.0, B4 = 0.0, B5 = 1.0** on both topologies (T1,
T2). DPoP recovers attribution exactly as v1 conjectured; a real
hash-chained log produces **LIS = 1.0 alongside AIS = 0.0 at B4** (a
tamper-proof record of the *wrong* actor); the curve shape is invariant to
attack frequency. Every locked prediction was reproduced — none contradicted.

## Status — phases shipped ✅

- [x] Phase 1 — Pre-registration with SHA-256 lock + CI gate ([`tests/test_threat_model_v2_locked.py`](../tests/test_threat_model_v2_locked.py))
- [x] Phase 2 — Process-boundary recorder ([`harness/agent_proc.py`](harness/agent_proc.py), [`agent_bodies.py`](harness/agent_bodies.py), [`recorder.py`](harness/recorder.py))
- [x] Phase 3 — Baseline 5: DPoP sender-constraint ([`auth/dpop.py`](auth/dpop.py))
- [x] Phase 4 — Hash-chained log + LIS metric ([`harness/tamper_log.py`](harness/tamper_log.py), [`harness/scorer.py`](harness/scorer.py) `score_lis`)
- [x] Phase 5 — Topology T2 (3-agent chain) ([`topologies/`](topologies/), [`harness/sweep.py`](harness/sweep.py))
- [x] Phase 6 — Stochastic Bernoulli(p) + Wilson CIs + adaptive N ([`harness/stochastic.py`](harness/stochastic.py))
- [x] Phase 7 — Paper ([`../../Documents/Paper/v2/aegis-at-v2.tex`](../../Documents/Paper/v2/aegis-at-v2.tex), 14 pp)
- [x] **74 v2 tests + 59 frozen v1 tests green; both gates exit 0**

v3 future work (mutual-TLS / RFC 8705 as Baseline 5b, fan-in and cross-org
topologies, LLM-in-the-loop, real attack-frequency telemetry) is named in
§13 of the paper and §9 of the threat model.

## Package layout

```
v2/aegis_at_v2/
├── auth/
│   ├── tokens.py            RFC 8693 mint + verify + chain walk (ported from v1, + optional cnf)
│   └── dpop.py              RFC 9449 sender-constraint: Ed25519 keys, proofs, jkt, verify
├── policy/
│   └── scope_map.py         Static command→scope contract (ported verbatim from v1)
├── tools/
│   └── siem_action.py       Scope-gated tool — Boundary 3 (+ DPoP cnf/proof check)
├── orchestrator/
│   └── orchestrator.py      Stateless RFC 8693 minter (+ cnf binding on re-delegation)
├── harness/
│   ├── agent_proc.py        Subprocess kernel: PID registry, fail-loud on PID-spoof
│   ├── agent_bodies.py      Code that runs INSIDE agent subprocesses (leaf module — no auth/tools)
│   ├── recorder.py          Ground-truth recorder — Boundary 5 (reads kernel PID, never the token)
│   ├── tamper_log.py        Hash-chained, signed tamper-evident log (Baseline 4 made real)
│   ├── scorer.py            AIS + LIS metrics, defect breakdown, Wilson CI
│   ├── sweep.py             Baseline + topology switch + canonical attack + verify_deterministic + emit_curves
│   └── stochastic.py        Bernoulli(p) sweep, Wilson CIs, adaptive N=100→500
└── topologies/
    ├── base.py              The Topology value object (chain as data, not code)
    ├── two_agent.py         T1 — Enrich → Contain (v1's topology, regression anchor)
    └── three_agent.py       T2 — Enrich → Investigator → Contain (3-agent linear chain)
```

Tests live one level up at [`../tests/`](../tests/); the v2 gate is
[`../scripts/check_v2.sh`](../scripts/check_v2.sh).

> **No `harness/attacks/` package exists.** The attack is one function —
> `sweep.run(baseline, topology=...)` — that executes the canonical §5
> re-delegation path. The stochastic sweep evaluates it once per cell
> (`stochastic.correctness_bit`, memoised) and draws seeded Bernoulli
> escalations — re-running the deterministic subprocess N times would
> change nothing but wall-clock.

## Quick start

All commands are run **from the repository root** (the v2 test harness
imports `aegis_at_v2` via [`../tests/conftest.py`](../tests/conftest.py),
which anchors `sys.path` off the v2 root).

```bash
# install (covers v1, v2, and the paper-figure build)
pip install -r requirements.txt

# 1) the gate — 74 v2 tests
cd v2 && python -m pytest -q
cd ..

# 2) v1 frozen regression — 59 tests still green
cd v1 && bash scripts/check.sh
cd ..

# 3) emit the v2 AIS curve end-to-end (both topologies)
python -c "
import sys; sys.path.insert(0, 'v2')
from aegis_at_v2.harness import sweep
from aegis_at_v2.harness.scorer import is_non_monotonic
curves = sweep.emit_curves(with_determinism_check=False)
for topo, c in curves.items():
    print(topo, {b: c[b]['ais'] for b in ('B1','B2','B3','B4','B5')},
          'non-monotonic:', is_non_monotonic(c))
"
# expected: T1 {B1:0.0, B2:1.0, B3:0.0, B4:0.0, B5:1.0} non-monotonic: True
#           T2 {B1:0.0, B2:1.0, B3:0.0, B4:0.0, B5:1.0} non-monotonic: True

# 4) LIS curve (Phase 4)
python -c "
import sys; sys.path.insert(0, 'v2')
from aegis_at_v2.harness import sweep
print({b: r['lis'] for b, r in sweep.emit_lis_curve().items()})
"
# expected: {B1:0.0, B2:0.0, B3:0.0, B4:1.0, B5:0.0}

# 5) stochastic grid with Wilson CIs (Phase 6) — fixed seed 20260610
python -c "
import sys; sys.path.insert(0, 'v2')
from aegis_at_v2.harness import stochastic as st
g = st.stochastic_sweep()
print('shape invariant across p and topology:', st.curve_shape_invariant(g))
"
# expected: True

# 6) regenerate the paper figures from the live harness
python Documents/Paper/v2/figures/make_figures.py
```

## The five v2 baselines (config flags, one codebase)

The five baselines are **configuration flags over identical code** — only the
credential differs ([`harness/sweep.py::_credential_for`](harness/sweep.py)).
Same tool, recorder, scorer, attack. That's what makes the five AIS values
comparable rather than apples-to-oranges (INV-6).

| Baseline | Credential | Signal read | Tracks executor? | AIS |
|:--:|:--|:--|:--:|:--:|
| B1 | shared service account | one shared identity | undefined | 0.0 |
| B2 | per-agent opaque credential | execution-time authenticator | yes | **1.0** |
| B3 | RFC 8693 re-delegation JWT (unbound bearer) | delegation current actor (`act.sub`) | no | 0.0 |
| B4 | same as B3, with hash-chained tamper-evident log | delegation current actor | no | 0.0 |
| B5 | DPoP-bound token (executor re-exchanges for its own) | re-exchanged current actor | yes | **1.0** |

Plus the new **Log Integrity Score (LIS)**, scored separately from AIS: B4 = 1.0,
all others = 0.0 by definition (no integrity artifact).

## The two topologies (chain depth as data)

| Topology | Re-delegation chain | Claimed actor at B3/B4 | Where it lives |
|:--:|:--|:--|:--|
| **T1** | Enrich → Contain | `agent:enrich` (requester) | [`topologies/two_agent.py`](topologies/two_agent.py) |
| **T2** | Enrich → Investigator → Contain | `agent:investigator` (deepest requester) | [`topologies/three_agent.py`](topologies/three_agent.py) |

The §7.2 prediction (confirmed): the curve is **identical on both** — the
gap does not heal with chain depth; depth merely names a different
non-executor. Adding a topology is adding a hop list in
[`topologies/`](topologies/), never a forked codebase.

## What's new vs v1, module-by-module

| Module | Status | What changed |
|:--|:--|:--|
| [`auth/tokens.py`](auth/tokens.py) | extended | optional `cnf={"jkt": ...}` parameter (B5); v1 path unchanged when `cnf=None` |
| [`auth/dpop.py`](auth/dpop.py) | **new** | RFC 9449 primitive — Ed25519, proof JWT, RFC 7638 thumbprint, replay cache, freshness window |
| [`policy/scope_map.py`](policy/scope_map.py) | unchanged | ported verbatim from v1 |
| [`tools/siem_action.py`](tools/siem_action.py) | extended | DPoP proof + replay check when token carries `cnf` |
| [`orchestrator/orchestrator.py`](orchestrator/orchestrator.py) | extended | verifies proof before binding `cnf` (no token bound to a key you don't hold) |
| [`harness/recorder.py`](harness/recorder.py) | rewritten | reads `true_actor` from the agent-process kernel's PID registry (not thread name) |
| [`harness/agent_proc.py`](harness/agent_proc.py) | **new** | subprocess kernel; cross-checks self-reported PID; fail-loud on mismatch |
| [`harness/agent_bodies.py`](harness/agent_bodies.py) | **new** | what runs inside agent subprocesses; leaf module (no auth/tools imports — keeps spawn cheap) |
| [`harness/tamper_log.py`](harness/tamper_log.py) | **new** | hash-chained, Ed25519-signed log; `verify` returns broken-link indices |
| [`harness/scorer.py`](harness/scorer.py) | extended | `score_lis` alongside `score_ais`; `is_non_monotonic` uses `abs(b4-b3) < eps` |
| [`harness/sweep.py`](harness/sweep.py) | extended | `topology` parameter; `emit_curves` (both topologies); `measure_lis`; `emit_lis_curve` |
| [`harness/stochastic.py`](harness/stochastic.py) | **new** | Bernoulli(p) sweep, Wilson CIs, adaptive N=100→500 |
| [`topologies/`](topologies/) | **new** | T1, T2 as data (a `Topology` declaring a `redelegation_chain` tuple) |

## Honest disclosure: the one architectural change

**Tool execution moved into the harness process.** In v1 each agent's
thread called `siem_action` directly. In v2 the agent is a subprocess; it
ships its credential (and DPoP proof, for B5) over a pipe, and the parent
harness invokes the recorder and `siem_action` on the agent's behalf
([`sweep.py::run.tool_handler`](harness/sweep.py)). This is required for
PID-based ground truth and is neutral to the comparison — the tool's
verification logic and the presented credential are byte-identical to v1,
and the claimed record still derives solely from the presented token — but
it is a real substrate change. It is recorded as **conceded limitation
L10** in [`threat-model-v2.1.md`](../../Documents/ThreatModel/ThreatModelv2/threat-model-v2.1.md) §A1
and as **validity threat item 6** in the paper.

## Project invariants enforced here

Full text in [`../../CLAUDE.md`](../../CLAUDE.md). The load-bearing ones for
this package:

- **INV-1** — token shape is RFC 8693-compliant; `sub` = principal, current actor = top-level `act.sub`, executor is NOT a token field.
- **INV-2** *(grep-enforced)* — identity resolves to the **most-recent actor** (top-level `act.sub`), never the "innermost" subject.
- **INV-3** *(grep-enforced)* — the tool is named `siem_action` everywhere, never `query_siem`.
- **INV-4** — the recorder reads identity from the kernel's PID registry (set by the OS at spawn), never a token or agent-supplied field. v2 makes this real, not a thread-name proxy.
- **INV-6** — baselines (and topologies) are config flags over one codebase. Differences cannot be blamed on incidental implementation quality.
- **INV-7** — every AIS / LIS / point prediction is asserted against a value pre-registered in [`../../Documents/ThreatModel/ThreatModelv2/threat-model-v2.md`](../../Documents/ThreatModel/ThreatModelv2/threat-model-v2.md) before the measuring code ran. The threat model is **SHA-256 locked**; any edit fails the build.
- **INV-8** — every domain claim (RFC 8693, RFC 9449, RFC 7800, PyJWT behaviour) is verified against source, not paraphrased.

## What is genuinely owned here

The pre-registered measurement design — the v2.1 amendment to the threat
model, the AIS/LIS metric definitions, the DPoP integration, the
process-boundary recorder design, the topology-as-data abstraction, and
the exact-vs-sampled stochastic sweep. The auth / cryptography plumbing
uses standard tooling (PyJWT, `cryptography`); **the measurement design
is the contribution.**

## License

Code in this directory is **Apache-2.0** (see [`../../LICENSE`](../../LICENSE)).
Documentation under [`../../Documents/`](../../Documents/) is CC BY 4.0.
