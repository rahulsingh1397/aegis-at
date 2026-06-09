# AEGIS-AT — `aegis-at/` package

The Python implementation of the **Attribution Integrity Benchmark**: a minimal
multi-agent SOC pipeline that measures whether delegation-chain attribution survives
an adversarial **sibling-impersonation** attack, scored as an **Attribution Integrity
Score (AIS)** across four progressive defense baselines.

> 📖 **New here? Start at the [repository root readme](../readme.md)** for the full
> story (the finding, why it matters, the attack, the threat model). This file is the
> developer-facing guide to the `aegis-at/` package itself.
>
> The canonical, citable write-up is the 16-page paper in
> [`../Documents/Paper/`](../Documents/Paper/) (PDF + LaTeX + Markdown). The full
> argument lives in [`../Documents/ThreatModel/threat-model.md`](../Documents/ThreatModel/threat-model.md).

## The question

Modern agent frameworks claim every action is traceable to a responsible party (via
RFC 8693 `act`-claim delegation). This benchmark tests whether that attribution holds
under adversarial pressure, rather than assuming it.

## The finding (one line)

A non-monotonic AIS curve — **B1 = 0.0, B2 = 1.0, B3 = 0.0, B4 = 0.0.** Adding RFC
8693 delegation regresses attribution from perfect to zero, and tamper-evident logging
does not recover it. The cause is structural: RFC 8693 records the agent that
*requested* delegated authority, not the one that *executed* — and the standard has no
field for the executor.

## Status — v1 shipped ✅

- [x] Threat model — [`../Documents/ThreatModel/threat-model.md`](../Documents/ThreatModel/threat-model.md)
- [x] RFC 8693 delegation tokens by hand — [`auth/tokens.py`](auth/tokens.py)
- [x] Static command→scope contract — [`policy/scope_map.py`](policy/scope_map.py)
- [x] Scope-gated tool (Boundary 3) — [`tools/siem_action.py`](tools/siem_action.py)
- [x] Stateless RFC 8693 minter (Boundary 2) — [`orchestrator/orchestrator.py`](orchestrator/orchestrator.py)
- [x] Independent ground-truth recorder (Boundary 5) — [`harness/recorder.py`](harness/recorder.py)
- [x] AIS metric + defect breakdown + non-monotonicity predicate — [`harness/scorer.py`](harness/scorer.py)
- [x] Baseline sweep + canonical attack + determinism check — [`harness/sweep.py`](harness/sweep.py)
- [x] **59 tests green; AIS curve reproduces deterministically**

v2 future work (sender-constrained Baseline 5, multi-topology, stochastic policy,
hash-chained log integrity) is named in §12 of the paper.

## Package layout

```
aegis-at/
├── requirements.txt           pyjwt, cryptography
├── auth/tokens.py             RFC 8693 mint + verify + chain walk (run it directly — see below)
├── policy/scope_map.py        Static command→scope map (shared contract; tool + recorder import it)
├── tools/siem_action.py       Scope-gated SOAR tool — Boundary 3 (sig, expiry, chain, scope, identity)
├── orchestrator/
│   └── orchestrator.py        Stateless RFC 8693 validator/minter — Boundary 2
├── harness/
│   ├── recorder.py            Out-of-band true-actor witness — Boundary 5 (reads the thread, never the token)
│   ├── scorer.py              AIS metric, defect breakdown, Wilson CI, is_non_monotonic(curve)
│   └── sweep.py               Baseline switch + canonical attack + verify_deterministic + emit_curve
├── agents/                    (empty — agents are scripted inside harness/sweep.py by design; see §11.5)
├── configs/                   (empty — baselines are flags in sweep.py, not config files; INV-6)
└── results/                   (gitignored — AIS-curve outputs land here)
```

> **No `harness/attacks/` package exists.** The attack is a single function —
> `sweep.run(baseline)` — that executes the canonical §5 re-delegation path. Keeping
> it one function (not a package) preserves the one-degree-of-freedom cleanliness.

## Quick start

All commands are run **from the repository root** (the test harness imports modules
via `tests/conftest.py`, which anchors paths off the repo root).

```bash
# install
pip install -r aegis-at/requirements.txt

# 1) the auth primitive — chain nesting, scope narrowing, forgery rejection
python aegis-at/auth/tokens.py

# 2) the gate — 59 tests
pytest tests/core -v

# 3) full mechanical gate (invariant greps + ruff + black + tests)
bash scripts/check.sh

# 4) emit the AIS curve end-to-end
python -c "
import sys, pathlib
A = pathlib.Path('aegis-at')
for d in ('auth','policy','tools','harness','orchestrator'):
    sys.path.insert(0, str(A/d))
from sweep import emit_curve
from scorer import is_non_monotonic
curve = emit_curve()
for b in ('B1','B2','B3','B4'):
    print(f'  {b}: AIS={curve[b][\"ais\"]}')
print('is_non_monotonic:', is_non_monotonic(curve))
"
# expected: B1=0.0  B2=1.0  B3=0.0  B4=0.0  is_non_monotonic: True
```

## The defense baselines (config flags, one codebase)

The four baselines are **configuration flags over identical code** — only the
credential differs (`harness/sweep.py::_credential_for`). Same tool, recorder, scorer,
and attack. That's what makes the four AIS values comparable rather than
apples-to-oranges (INV-6).

| Baseline | Credential | Signal read | Tracks executor? | AIS |
|:--:|:--|:--|:--:|:--:|
| B1 | shared service account | one shared identity | undefined | 0.0 |
| B2 | per-agent opaque credential | execution-time authenticator | yes | 1.0 |
| B3 | RFC 8693 re-delegation JWT | delegation current actor (`act.sub`) | no | 0.0 |
| B4 | same as B3 (+ tamper-evident log, *attribution-only in v1*) | delegation current actor | no | 0.0 |

## Project invariants enforced here

The grep-enforced invariants run in [`../scripts/check.sh`](../scripts/check.sh); the
judgment invariants live in [`../CHECKLIST.md`](../CHECKLIST.md). Full text in
[`../CLAUDE.md`](../CLAUDE.md). The load-bearing ones for this package:

- **INV-2** *(grep-enforced)* — identity resolves to the **most-recent actor**
  (top-level `act.sub`), never the "innermost" subject (the root principal).
- **INV-3** *(grep-enforced)* — the tool is named `siem_action` everywhere, never `query_siem`.
- **INV-4** — the recorder reads identity from the executing thread/process, never a
  token or agent-supplied field.
- **INV-6** — baselines are config flags over one codebase.
- **INV-7** — every AIS value is asserted against a prediction pre-registered in the
  threat model before the attack code was written.

## What is genuinely owned here

The threat model, the AIS metric definition, the attack mechanism, and the validity
analysis (paper §11). The agent scaffolding and auth plumbing are assembled with
standard tooling — **the measurement design is the contribution.**

## Scope discipline

One failure mode (sibling impersonation via multi-agent re-delegation), measured
rigorously. Direct prompt injection, delegation forgery, scope-attenuation bypass,
audit-log tampering, and principal laundering are explicit future work — see paper §7
and §12.

## License

Code in this directory is **Apache-2.0** (see [`../LICENSE`](../LICENSE)).
Documentation under [`../Documents/`](../Documents/) is CC BY 4.0.