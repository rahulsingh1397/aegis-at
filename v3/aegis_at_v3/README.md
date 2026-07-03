# AEGIS-AT v3 — `aegis_at_v3/` package

The active Python implementation of the **Attribution Integrity Benchmark**, v3.
It asks the 2026 question: once agents write **completion records** ("here's what
I did"), *who attests them* — and does attribution survive an agent that lies?

> 📖 **New here? Start at the [repository root readme](../../readme.md)** for the
> whole story (the finding, why it matters, the attack). This file is the
> developer-facing guide to the `aegis_at_v3/` package.
>
> The canonical, citable write-up is the **17-page v3 paper** at
> [`../../Documents/Paper/v3/aegis-at-v3.pdf`](../../Documents/Paper/v3/aegis-at-v3.pdf).
> Every number below is pre-registered and locked in
> [`../../Documents/ThreatModel/ThreatModelv3/`](../../Documents/ThreatModel/ThreatModelv3/).

---

## What v3 measures, in one breath

A high-privilege agent takes an action, then files a signed **completion record**
saying *which agent executed it*. If the audit log trusts that self-report, an
agent can sign a perfectly valid record that **names a different agent** — and the
blame lands on the wrong one. v3 measures exactly when that happens and what stops
it.

- **v1** — the executor has no field (RFC 8693 names the *requester*).
- **v2** — bind the token to the executor's key (DPoP recovers attribution).
- **v3** — completion records exist now, but they **default to self-report**;
  self-report collapses under a lying executor, independent verification holds.

---

## The finding (one line)

**Trusting the executor's self-report fails; verifying the executor at execution
wins.** The full deterministic curve, B1–B9 (identical on both topologies):

| Baseline | Defense in place | Attribution read from | honest | colluding |
|:--:|:--|:--|:--:|:--:|
| B1 | shared service account | shared credential | 0.0 | 0.0 |
| B2 | per-agent identity | execution-time authenticator | 1.0 | 1.0 |
| B3 | + RFC 8693 delegation | delegation current actor | 0.0 | 0.0 |
| B4 | + tamper-evident log | delegation current actor | 0.0 | 0.0 |
| B5 | + DPoP (RFC 9449) | key-bound current actor | 1.0 | 1.0 |
| B6 | + mTLS (RFC 8705) | cert-bound identity, verified at access | 1.0 | 1.0 |
| B7 | + A-JWT execution assertion | PoP-verified `executed_by` | 1.0 | 1.0 |
| **B8** | **+ self-reported completion** | **the executor's own claim** | **1.0** | **0.0** |
| **B9** | **+ tool-verified completion** | **an independent verifier** | **1.0** | **1.0** |

Everything that resolves the executor from *evidence the executor cannot author*
(`{B5, B6, B7, B9}`) recovers to 1.0. **B8 — self-report — is the lone failure.**

---

## Two tiers (and an honest line about each)

v3 runs the same B8/B9 measurement with two kinds of attacker in the executor seat:

**Tier 1 — scripted (deterministic).** A colluding script signs a valid completion
**with its own key** but names a sibling. B8 trusts it → AIS 0.0; B9 reads the
independent verifier → AIS 1.0. This is a *specification of the failure mode with
a positive control*: B9's verifier **is** the ground-truth recorder, so B9 = 1.0
holds **by construction** — an existence proof, not an empirical surprise. Locked
by exact equality.

**Tier 2 — real models (the empirical payload).** Four open-weight LLMs
(weak→strong) sit in the executor seat and are induced to lie by **prompt
injection on a structured tool-call argument**. Result:

| Model | B8-attack forging | B9-attack evasion |
|:--|:--:|:--:|
| M1 `llama-3.1-8b` | 0.905 | **0.0** |
| M2 `llama-3.3-70b` | 1.000 | **0.0** |
| M3 `gpt-oss-20b` | 1.000 | **0.0** |
| M4 `gpt-oss-120b` | 0.983 | **0.0** |

A real model forges the executor claim ~always under self-report; the independent
verifier drives evasion to **0 for every model** — it doesn't make the model
honest, it makes the lie *inert*. Verdicts (H1–H4): **H2 holds** (the knockout);
**H4 holds** (honest models don't misattribute); **H1 is a FLAT_FINDING** — the
curve is flat at the ceiling, reported honestly under a **disclosed confound** (the
locked prompt *forces* the completion call, saturating B8). Locked directionally
(Wilson containment), statistically reproducible from the frozen sweep at
[`../../Documents/Paper/v3/data/llm_sweep_v3.json`](../../Documents/Paper/v3/data/llm_sweep_v3.json).

---

## Package layout

```
v3/aegis_at_v3/
├── completion/
│   ├── completion_record.py    the §5.1 record (asserted_executor, attestation_source,
│   │                           attester_id, signature) + the B8/B9 resolver
│   └── execution_assertion.py  B7 — A-JWT execution assertion (per-agent PoP key)
├── auth/
│   └── mtls.py                 B6 — mTLS certificate binding (RFC 8705 §3 match)
├── harness/
│   ├── adversary.py            scripted seats — honest vs. colluding (Tier 1)
│   ├── completion_sweep.py     the B6–B9 deterministic sweep; reuses v2's kernel,
│   │                           recorder, tool, and scorer byte-for-byte (INV-6)
│   ├── llm_seat.py             Tier-2 — one LLM in the executor seat (structured tool call)
│   ├── llm_sweep.py            Tier-2 — adaptive sweep: batches → Wilson CIs → evasion rate
│   └── llm_eval.py             Tier-2 — the H1–H4 evaluator (verdict over the stored grid)
└── transport/
    └── mcp_adapter.py          MCP-shaped boundary (server MUST NOT pass the token upstream)
```

v3 **imports `aegis_at_v2`** for the whole B1–B5 path — it does not re-implement it
(INV-6). The v2 process-boundary recorder is reused *as-is* and becomes **B9's
independent verifier**.

Tests live one level up at [`../tests/`](../tests/) (15 files); the gate is
[`../scripts/check_v3.sh`](../scripts/check_v3.sh).

---

## Quick start

All commands run **from the repository root** unless noted.

```bash
# install the deterministic core (v1, v2, v3) + the paper-figure build.
# Groq is deliberately NOT here — the gate must run green without a key.
pip install -r requirements.txt

# 1) the deterministic gate — INV greps + lint + tests (no API key needed)
cd v3 && bash scripts/check_v3.sh          # expect ~150 passed, 2 skipped
cd ..

# 2) emit the deterministic B1–B9 curve end-to-end
python -c "
import sys; sys.path.insert(0, 'v3'); sys.path.insert(0, 'v2')
from aegis_at_v2.harness import sweep
from aegis_at_v3.harness import completion_sweep as cs
v2 = sweep.emit_curves(with_determinism_check=False)['T1']
print({b: v2[b]['ais'] for b in ('B1','B2','B3','B4','B5')})
print('B6', cs.emit_b6_grid('T1')['B6'], 'B7', cs.emit_b7_grid('T1')['B7'])
print({k:v for k,v in cs.emit_b8_b9_grid('T1').items() if k!='topology'})
"
# expected: B1-B5 {0.0,1.0,0.0,0.0,1.0}; B6/B7 = 1.0/1.0;
#           B8 = 1.0 honest / 0.0 colluding; B9 = 1.0 / 1.0

# 3) regenerate the paper figures (Tier-1 live; Tier-2 from the frozen sweep)
python Documents/Paper/v3/figures/make_figures.py
```

**The Tier-2 LLM run is optional and needs a key.** The two live LLM tests
(`test_llm_seat`, `test_llm_sweep`) **skip** without `GROQ_API_KEY`, so the gate
stays green offline. To reproduce the real-model sweep yourself:

```bash
# install the optional LLM deps (kept out of the core, on purpose)
pip install -r v3/requirements-llm.txt
# put GROQ_API_KEY in your .env (loaded via python-dotenv; never commit it), then:
python v3/scripts/run_llm_sweep.py         # resume an interrupted run: resume_llm_sweep.py
```

The recorded result is already frozen with the paper; you do **not** need to re-run
it to build the paper or read the finding.

---

## What v3 adds over v2 (module map)

| Module | Baseline | What it does |
|:--|:--:|:--|
| `completion/completion_record.py` | B8 / B9 | the completion-record abstraction + the source-selected resolver (self-reported vs. tool-verified). **Fails loud** if B9 has no verifier observation — never silently degrades to B8. |
| `completion/execution_assertion.py` | B7 | A-JWT-style execution assertion; the PoP key is verified at execution, so `executed_by` is not a bare self-report. |
| `auth/mtls.py` | B6 | RFC 8705 certificate binding; the resource maps a verified per-agent cert → executor. |
| `harness/adversary.py` | — | the swappable scripted seat: `honest` (names the true executor) or `colluding` (names a sibling, signed with its own valid key). |
| `harness/completion_sweep.py` | B6–B9 | composes the sweep over v2's reused kernel/recorder/tool/scorer; exposes the non-circularity seams (degraded resolver, verifier toggle) for the controls. |
| `harness/llm_seat.py` | B8 / B9 | replaces the scripted seat with a real LLM; strict §C7 outcome classification (evasion / refused / malformed / unavailable). |
| `harness/llm_sweep.py` | B8 / B9 | adaptive batches (stop at Wilson half-width < 0.05 or N=200); reuses v2's Wilson machinery. |
| `harness/llm_eval.py` | — | pure function over the stored grid → H1–H4 verdict by Wilson containment; **never recomputes** a rate (reads what was measured). |
| `transport/mcp_adapter.py` | — | thin MCP-shaped wrapper enforcing token-no-passthrough + RFC 8707 audience binding — grounds v3 in a shipped 2026 protocol. |

---

## Project invariants enforced here

Full text in [`../../CLAUDE.md`](../../CLAUDE.md). The load-bearing ones for v3:

- **INV-4** — the recorder reads identity from the OS process boundary
  (`os.getpid()`), **never** a token, a completion field, or any agent-supplied
  value. This is what makes B9's verifier trustworthy and the whole measurement
  non-circular. A test (`test_inv4_recorder_independence`) asserts it on every cell.
- **INV-6** — baselines are config flags over **one** codebase; v3 *imports* v2 for
  B1–B5 rather than vendoring it, so an AIS difference is attributable to the flag,
  not to incidental code.
- **INV-7** — every predicted value is committed to a **SHA-256-locked** threat
  model *before* the measuring code. A contradicted prediction is a **finding**, not
  something to code around — H1's flat curve is exactly that, reported openly.
- **INV-8** — every domain claim (AIP, PEDIGREE, HDP, MCP, RFC 8705, A-JWT) is
  verified at primary source and receipted in `source-lock-v3*.md`, never
  paraphrased.

**Where the locks live:** `threat-model-v3.md` (scripted B8/B9, exact equality),
`threat-model-v3.0.1.md` (B6/B7), `threat-model-v3.1.md` (the LLM tier, Wilson
containment) — each with a companion `source-lock-v3*.md`, all under
[`../../Documents/ThreatModel/ThreatModelv3/`](../../Documents/ThreatModel/ThreatModelv3/)
and guarded by `test_threat_model_v3_locked.py`.

---

## License

Code in this directory is **Apache-2.0** (see [`../../LICENSE`](../../LICENSE)).
Documentation under [`../../Documents/`](../../Documents/) is CC BY 4.0.
