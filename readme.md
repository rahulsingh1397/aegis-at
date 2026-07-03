# AEGIS-AT — Attribution Integrity Benchmark

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20693303.svg)](https://doi.org/10.5281/zenodo.20693303)
&nbsp;[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**AEGIS-AT measures whether an audit log names the agent that actually performed
an action when a sibling-agent impersonation attack is in play.**

It is a public red-team benchmark for attribution integrity in multi-agent AI.
The harness implements a deliberately small Security Operations Center (SOC)
pipeline, runs the same scenario across progressive defense baselines, and scores
whether the logged `(actor, scope, principal_chain)` matches independently
observed ground truth using the **Attribution Integrity Score (AIS)**.

## Project arc

- **v1 — the executor has no field.** RFC 8693 delegation names the requester,
  not necessarily the agent that executed the action, so AIS regresses from
  **1.0** to **0.0**.
- **v2 — bind the token to the executor's key.** DPoP sender-constraint recovers
  AIS to **1.0**; tamper-evident logging alone only preserves a truthful-looking
  record of the wrong actor.
- **v3 — completion records now exist, but who attests them?** Self-reported
  completions fail under collusion. Independently observed/tool-verified
  attribution holds. Four real LLMs forge the self-reported executor under
  attack, while B9 remains **0% evasion**.

**In one sentence:** self-reported attribution is not enough; executor identity
must come from evidence the executor cannot author.

> **v1 is frozen** (git tag `v1.0.0`, under [`v1/`](v1/)) as a self-contained
> artifact. **v2** adds sender-constraint, a process-boundary recorder,
> tamper-evident logging, topology depth, and stochastic confidence intervals.
> **v3** adds completion-record attribution, B6–B9, and the Tier-2 real-model LLM
> ladder. For the v1-only artifact see [`v1/README.md`](v1/aegis-at/README.md).

---

## The v2 finding

![AIS across five baselines, two topologies](Documents/Paper/v2/figures/fig_ais_curve.png)

| Baseline | Defense in place         | Signal read                  | Tracks executor? | AIS  |
| :------: | :----------------------- | :--------------------------- | :--------------: | :--: |
|   B1     | Shared service account   | shared credential            | undefined        | 0.0  |
|   B2     | Per-agent identity       | execution-time authenticator | yes              | 1.0  |
|   B3     | + RFC 8693 delegation    | delegation current actor     | no               | 0.0  |
|   B4     | + tamper-evident log     | delegation current actor     | no               | 0.0  |
|   B5     | + DPoP sender-constraint | re-exchanged current actor   | yes              | **1.0** |

The curve is **non-monotonic**: attribution is perfect under per-agent identity
(B2), **regresses to zero** when RFC 8693 delegation is added (B3), **stays at
zero** under tamper-evident logging (B4) — and **recovers to 1.0** once
sender-constrained tokens (DPoP) force the executor to name itself (B5). The two
primitives most emphasized for agent non-repudiation (signed delegation,
tamper-evident logs) do not close the gap; the under-emphasized one (DPoP) does.

**Why it regresses — the structural mechanism (not a bug):**
RFC 8693's "current actor" (`act.sub`) is the party that *requested* the
delegated authority. In a multi-agent hand-off, the agent that *executes* the
action can differ from the one named in the token — and the standard provides no
field that records the executor. §4.1's `MUST` is scoped to the **access-control
decision**, not audit logging; combined with unbound bearer tokens and a
mint-before-execution topology, the realistic implementation logs the
*requester*. **v2's Baseline 5 closes this**: DPoP (RFC 9449) binds the token to
its holder's key, so the lift that constitutes the attack is rejected and the
executor must re-exchange for a token naming itself.

---

## What's new in v2

Five changes, each a flag or module over the **same** codebase, so the new
numbers stay comparable to v1's:

1. **Baseline 5 — sender-constrained tokens (DPoP / RFC 9449).** The executor
   must hold the key its token is bound to (`cnf: {jkt}`, RFC 7800; per-request
   proof JWT). AIS recovers to **1.0** — the fix v1 named but did not measure.
2. **Process-boundary recorder.** `multiprocessing` + `os.getpid()` replaces
   v1's `threading.current_thread().name`. PID-based attribution is set by the
   kernel and is **unspoofable** by an in-process thread/title rename.
3. **Hash-chained log + Log Integrity Score (LIS).** A real tamper-evident log
   (SHA-256 chain, signed head) makes Baseline 4 concrete. LIS reaches **1.0**
   (every tamper detected) while AIS stays **0.0** — a tamper-proof record of the
   *wrong* actor.
4. **Second topology (T2).** A 3-agent chain `Enrich → Investigator → Contain`
   shows the gap **does not heal with chain depth**: the curve is identical to
   the 2-agent T1, and the claimed actor is just a deeper requester.
5. **Stochastic policy + Wilson CIs.** Bernoulli(p) escalation, N ≥ 100 per cell
   with adaptive escalation to N=500, retiring v1's degenerate intervals. The
   curve shape is invariant to attack frequency.

### The AIS / LIS asymmetry (B4) and frequency invariance

| ![AIS vs LIS per baseline](Documents/Paper/v2/figures/fig_ais_lis.png) | ![Stochastic AIS with Wilson CIs](Documents/Paper/v2/figures/fig_stochastic_ci.png) |
| :--: | :--: |
| B4 is tamper-proof (LIS = 1.0) yet mis-attributing (AIS = 0.0). | The curve shape is invariant across escalation probability p. |

*(Figures are generated from the live harness — see [Reproduce](#reproduce).)*

---

## Why it matters

Picture a hospital's automated security response. A low-privilege triage agent
reads an alert and escalates; a high-privilege containment agent quarantines a
machine. Afterward the audit log must answer one question: *which agent took the
high-consequence action?* If the system trusts the agent's own report, an
attacker who shapes the alert can make the executor pin its action on a sibling
agent while the record still looks signed, structured, and compliant.

The standards landscape is actively asking for exactly this measurement (NIST
NCCoE, Feb 2026; OpenID Foundation, Mar 2026), and the confused-deputy gap has
shown up in production (the "Clinejection" incident, Feb 2026). AEGIS-AT measures
the attribution question one layer down — *when a privileged action is taken, does
the audit record name the agent that executed it?* v2 shows which standardized
execution-time layer fixes requester/executor confusion; v3 shows the same lesson
again for completion-era self-reporting under a real-model adversary.

---

## What AEGIS-AT is

A deliberately minimal system, built so the causal chain is clean and the
measurement is defensible:

- **Two agents, one tool** (T1; three agents for T2). `Agent-Enrich`
  (low-privilege, read-only) and `Agent-Contain` (high-privilege, executes
  `isolate_host`) share a single scope-gated SOAR tool, `siem_action`.
- **One core question.** After a high-consequence action, does the audit record
  name the agent that actually executed it?
- **One attack family.** Attacker-controlled alert text steers the system toward
  sibling misattribution: first through requester/executor confusion in the
  delegation chain, then through a forged self-reported completion record.
- **Baselines as config flags over one codebase.** The tool, recorder, and scorer
  stay shared; each baseline changes the attribution source or credential binding.
  This keeps AIS values comparable rather than apples-to-oranges.
- **Independent ground truth.** The recorder observes the true executing OS
  process (`os.getpid()`), never a token, completion field, or agent-supplied
  identity. The score compares what the system claims against what happened.
- **Strict metrics.** AIS is the fraction of adversarial actions whose claimed
  `(actor, scope, principal_chain)` exactly matches ground truth. LIS separately
  measures whether post-hoc log tampering is detected.

---

## Status

| Layer | Artifacts | State |
| :-- | :-- | :-- |
| v1 | `v1/aegis-at/`, `v1/tests/core/`, `v1/scripts/check.sh`, `Documents/Paper/v1/` | **Frozen at tag `v1.0.0`** |
| v2 | `v2/aegis_at_v2/`, `v2/tests/`, `Documents/ThreatModel/ThreatModelv2/`, `Documents/Paper/v2/` | Sender-constraint result complete |
| v3 | `v3/aegis_at_v3/`, `v3/tests/`, `Documents/ThreatModel/ThreatModelv3/`, `Documents/Paper/v3/` | Completion-record + real-model LLM tier complete; paper in progress |

Every predicted value is **pre-registered** in SHA-256-locked threat models before
the measuring code that asserts it. Contradicted predictions are reported as
findings, not reconciled. Tier-1 figures regenerate from the live harness; Tier-2
LLM figures are drawn from the recorded sweep.

### Scope

Deliberate boundaries, stated up front:

- **v1/v2 are deterministic/scripted.** They isolate delegation-layer attribution
  from model behavior.
- **v3 adds real models only for B8/B9.** The LLM tier tests self-reported vs
  independently observed completion attribution, not every baseline.
- **One focused attack family.** The benchmark measures sibling-agent
  misattribution under controlled alert-text injection/collusion, not every
  possible agent-security failure.
- **Independent observation is the key defense.** DPoP, mTLS, A-JWT, and
  process-boundary/tool verification all recover attribution because they resolve
  executor identity from evidence the executor cannot author.

---

## Reproduce

```bash
pip install -r requirements.txt

# v3 — deterministic gate; live LLM tests skip without GROQ_API_KEY
(cd v3 && bash scripts/check_v3.sh)

# v2 — sender-constraint result
(cd v2 && python -m pytest -q)

# v1 (frozen) — original gate
(cd v1 && bash scripts/check.sh)

# verify the pre-registration locks (LF-normalized, same as the CI gate).
# The canonical check is the pytest gate above; this reproduces it by hand:
python - <<'PY'
import hashlib, pathlib
d = pathlib.Path("Documents/ThreatModel/ThreatModelv3")
for stem in ("threat-model-v3", "threat-model-v3.0.1", "threat-model-v3.1"):
    got = hashlib.sha256((d/f"{stem}.md").read_bytes().replace(b"\r\n", b"\n")).hexdigest()
    want = (d/f"{stem}.sha256").read_text().split()[0]
    print(stem, "OK" if got == want else "DRIFT")
PY

# regenerate the v3 paper figures from the harness/recorded sweep
python Documents/Paper/v3/figures/make_figures.py

# build the v3 paper (requires a LaTeX toolchain)
(cd Documents/Paper/v3 && pdflatex aegis-at-v3.tex)   # or: make
```

The deterministic gates reproduce without any provider key. Tier-2 LLM rates are
statistically reproducible from the recorded sweep; live provider calls require
`GROQ_API_KEY` and are not part of the default deterministic gate.

---

## Repository map

```
Documents/
  ThreatModel/
    threat-model.md                     v1 — frozen 8-section argument.
    ThreatModelv2/                      v2 — locked DPoP/process-boundary/stochastic argument.
    ThreatModelv3/                      v3 — locked B6–B9 + LLM-tier argument.
  Paper/
    v1/aegis-at.tex / .pdf              v1 paper.
    v2/aegis-at-v2.tex / .pdf           v2 paper.
    v3/aegis-at-v3.tex / .pdf           v3 paper.
    v3/figures/make_figures.py          regenerates v3 figures.
  ImportantQuestions/                   Working notes — the *why* behind each module.
  InitialDocs/v2/                       Consolidated v2 reference.
v1/                                     frozen at tag v1.0.0.
v2/aegis_at_v2/                         RFC 8693, DPoP, recorder, scorer, sweep.
v3/aegis_at_v3/
  auth/mtls.py                          B6 mTLS certificate binding.
  completion/completion_record.py       B8/B9 completion-record abstraction.
  completion/execution_assertion.py     B7 A-JWT-style execution assertion.
  harness/completion_sweep.py           deterministic B1–B9 sweep.
  harness/llm_{seat,sweep,eval}.py      Tier-2 real-model ladder.
  transport/mcp_adapter.py              MCP-shaped no-token-passthrough boundary.
v3/tests/                               deterministic core + LLM evaluator tests.
```

Start with `Documents/Paper/v3/aegis-at-v3.pdf` for the full current argument,
`Documents/ThreatModel/ThreatModelv3/threat-model-v3.1.md` for the locked LLM-tier
hypotheses, or `v3/aegis_at_v3/harness/completion_sweep.py` + `v3/tests/` for the
executable result.

---

## Background & related work

AEGIS-AT sits inside an active standards conversation and a string of real-world
incidents. All citations were checked against their live primary sources.

**The standards call:**

- **NIST NCCoE**, *Accelerating the Adoption of Software and AI Agent Identity and
  Authorization* (concept paper, Feb 5 2026). Names auditing and non-repudiation
  of AI agent actions as an open problem and asks how existing identity standards
  should apply to multi-agent delegation, including multi-hop.
  [csrc.nist.gov](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
- **OpenID Foundation**, response to NIST (Mar 2026). Frames the urgent risks as
  failures of *trust*: "Who authorised this agent to act? On whose behalf? Can
  that be verified?"
  [openid.net](https://openid.net/oidf-responds-to-nist-on-ai-agent-security/)
- **Cloud Security Alliance**, *Confused Deputy Attacks on Autonomous AI Agents*
  (Mar 23 2026). Establishes confused-deputy as a high-severity pattern and notes
  that when an action runs under a trusted agent's identity, **audit logs may look
  legitimate and delay detection** — precisely the failure AEGIS-AT measures.
  [labs.cloudsecurityalliance.org](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-confused-deputy-prompt-injection/)

**Real-world incidents:**

- **"Clinejection"** (Feb 2026). A crafted GitHub issue title drove the Cline AI
  tool's triage bot into a supply-chain compromise — an unauthorized npm package
  on ~4,000 developer machines in an 8-hour window.
  [Snyk](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/)
- **Salesloft Drift / UNC6395** (Aug 2025). Stolen OAuth tokens from an AI chat
  integration exfiltrated Salesforce data from 700+ organizations — a production
  demonstration of the **unbound bearer-token** weakness Baseline 3 depends on and
  Baseline 5 (DPoP) closes.
  [Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)

**Closest prior academic work:**

- *The Misattribution Gap* (2026) measures model-vs-memory misattribution —
  adjacent, but a different layer (memory poisoning, not delegation-chain
  attribution). *SentinelAgent / DelegationBench* measures *detection*, not
  *attribution integrity*. See the v3 paper (`Documents/Paper/v3/aegis-at-v3.tex`)
  for the full positioning.

---

## License

This repository is dual-licensed:

- **Code** — everything under `v1/aegis-at/`, `v2/`, `v3/`, and the test/script
  trees — is licensed under the **Apache License 2.0**. See [`LICENSE`](LICENSE).
- **Documentation** — everything under `Documents/` — is licensed under **Creative
  Commons Attribution 4.0 International (CC BY 4.0)**. See
  [`Documents/LICENSE-docs`](Documents/LICENSE-docs).
