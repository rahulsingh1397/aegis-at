# AEGIS-AT — Attribution Integrity Benchmark

> **Adding the industry-standard delegation mechanism to a correctly-functioning
> multi-agent AI system makes audit attribution _worse_, not better.**

AEGIS-AT is a small, reproducible, adversarial **red-team benchmark** that measures
whether delegation-chain attribution survives a realistic *sibling-impersonation*
attack in a multi-agent system. It implements a minimal Security Operations Center
(SOC) triage pipeline — **two agents sharing one tool** — and scores an
**Attribution Integrity Score (AIS)** across four progressive defense baselines.

The headline result is a **non-monotonic curve**: attribution is perfect under
simple per-agent identity, then *regresses to completely wrong* the moment you add
**RFC 8693** delegation — the very mechanism standards bodies (NIST NCCoE, OpenID
Foundation) recommend for multi-agent non-repudiation. Tamper-evident logging does
not recover it.

| | |
|---|---|
| **Status** | v1 — shipped & frozen. 59 tests green, mechanical gate clean, AIS curve reproduces deterministically. |
| **Result** | Categorical (succeeds *by construction*), not statistical. |
| **Code license** | Apache-2.0 (`aegis-at/`, `tests/`, `scripts/`) |
| **Docs license** | CC BY 4.0 (`Documents/`) |
| **Paper** | 16-page PDF + LaTeX source + Markdown companion in `Documents/Paper/` |

---

## Table of contents

1. [The finding](#1-the-finding)
2. [Why it matters](#2-why-it-matters)
3. [What AEGIS-AT is](#3-what-aegis-at-is)
4. [The five trust boundaries](#4-the-five-trust-boundaries)
5. [The attack, step by step](#5-the-attack-step-by-step)
6. [The Attribution Integrity Score (AIS)](#6-the-attribution-integrity-score-ais)
7. [The four defense baselines](#7-the-four-defense-baselines)
8. [Results](#8-results)
9. [Architecture & modules](#9-architecture--modules)
10. [Repository layout](#10-repository-layout)
11. [Install & reproduce](#11-install--reproduce)
12. [Project invariants & the gate](#12-project-invariants--the-gate)
13. [Scope — what v1 is and isn't](#13-scope--what-v1-is-and-isnt)
14. [Future work (v2)](#14-future-work-v2)
15. [Background & related work](#15-background--related-work)
16. [How to cite](#16-how-to-cite)
17. [License](#17-license)

---

## 1. The finding

| Baseline | Defense in place        | Signal the tool reads          | Tracks executor? | **AIS** |
| :------: | :---------------------- | :----------------------------- | :--------------: | :-----: |
|   **B1** | Shared service account  | one shared credential          | undefined        | **0.0** |
|   **B2** | Per-agent identity      | execution-time authenticator   | yes              | **1.0** |
|   **B3** | + RFC 8693 delegation   | delegation *current actor*     | no               | **0.0** |
|   **B4** | + tamper-evident log    | delegation *current actor*     | no               | **0.0** |

The curve rises to perfect attribution at **B2**, **regresses to zero at B3** when
signed delegation is added, and **stays at zero at B4** — tamper-evident logging
cannot recover what was already mis-recorded at mint time.

**Why it regresses — the structural mechanism (not a bug).**
RFC 8693's *current actor* (`act.sub`) is the party that **requested** the delegated
authority. In a multi-agent hand-off, the agent that **executes** the action can
differ from the one named in the token — and the standard provides **no field that
records the executor**. §4.1's `MUST` is scoped to the *access-control decision*,
not to audit logging; combined with unbound bearer tokens (RFC 8693 inherits OAuth
2.0's default holder model) and a mint-before-execution topology, the realistic
implementation logs the *requester*. The standard neither prevents nor mandates
this — it simply has nowhere to put the executor. The fix is **execution-identity
binding** (sender-constrained tokens: DPoP / RFC 9449, or mTLS-bound / RFC 8705),
named as future work and not implemented in v1.

---

## 2. Why it matters

Picture a hospital's automated security response. A low-privilege triage agent reads
an alert and escalates; a high-privilege containment agent quarantines a machine —
say, a device on a patient-monitoring network. Afterward, the audit log must answer
one question: **which agent took the high-consequence action?**

Under standard delegation, the log names the agent that **requested** the
containment, not the one that **executed** it. If an attacker can shape the alert
that triggers the chain, they can cause a high-privilege action to be taken and
attributed to the wrong, lower-privilege agent — **covering the real executor's
tracks while looking fully spec-compliant.** The accountability the standard was
adopted to provide is exactly what fails.

This is the *covering-tracks* threat, not privilege escalation: the attacker hides
*who* exercised authority that already legitimately existed.

---

## 3. What AEGIS-AT is

A deliberately minimal system, built so the causal chain is clean and the
measurement is defensible:

- **Human principal** (`human:analyst`) — authenticates once, originates the task,
  is the root of every delegation chain; never calls tools directly.
- **Orchestrator** — a *stateless* RFC 8693 token-exchange endpoint. Validates an
  exchange request and mints the appropriately scoped, correctly nested token. Does
  **not** read alert content to make routing decisions, and does **not** appear in
  the minted chain.
- **Agent-Enrich** (Subagent A) — low-consequence sibling, read-only context
  gathering under `siem:read`. In the attack, the *innocent* sibling whose identity
  is falsely stamped on Contain's action.
- **Agent-Contain** (Subagent B) — high-consequence sibling and the **true
  executor**; runs `isolate_host` under `siem:write`.
- **Tool `siem_action`** — a single scope-gated SOAR endpoint. The `command`
  parameter selects the operation; the token's `scope` claim decides whether the
  call is permitted. Reads agent identity **only** from the verified `act` claim —
  never a self-reported field.
- **Harness recorder** — an out-of-band ground-truth witness that observes the
  *true* executing agent from the execution context (the thread), never from the
  token. This is the measurement instrument, not part of the system under test.

This is the **smallest configuration in which sibling impersonation is possible**:
two siblings (so impersonation has a target) and one shared tool (so the attack has
exactly one degree of freedom — A acted, the log says B). The privilege asymmetry
between Contain and Enrich is what makes misattribution *security-relevant* rather
than cosmetic.

---

## 4. The five trust boundaries

```
human:analyst  ──(1) request──▶  Orchestrator
                                   │  mints scoped RFC 8693 tokens   ◀── Boundary 2 (ATTACK)
                                   ▼
Agent-Enrich (requester, read) ── re-delegation request ──▶ Orchestrator
                                   │  mints siem:write token NAMING ENRICH
                                   ▼
Agent-Contain (executor)  ──▶  siem_action(isolate_host)            ◀── Boundary 3 (all checks pass)
                                   │  writes  claimed_actor = enrich  ◀── Boundary 4
Harness recorder  ── observes  true_actor = contain (out-of-band)   ◀── Boundary 5
                                   ▼
              AIS scorer:  claimed ≠ true  ⇒  ATTRIBUTION DEFECT
```

| Boundary | What it is | Where the attack lives |
|:--:|:--|:--|
| **1** | principal → orchestrator. Analyst is trusted; **SIEM alert content is untrusted** (attacker's sole injection point). | sets up |
| **2** | orchestrator → subagent (token minting). Crypto is sound, but the *decisional* content is shaped by attacker-influenced upstream input. | **← the attack boundary** |
| **3** | subagent → tool. Signature, expiry, chain integrity, scope gate, identity resolution — **every check passes**; the tool faithfully transcribes a record already wrong. | not here |
| **4** | tool → action log. The wrong actor arrives already wrong. B4's tamper-evidence protects integrity but can't detect upstream misattribution. | not here |
| **5** | system → harness (ground-truth recorder). Independent by construction: process boundary, credential isolation, causal precedence. | measurement |

---

## 5. The attack, step by step

The attacker's only capability is to **control the text of one SIEM alert** that
Enrich processes. No zero-day, no jailbreak, no instruction-override, no adversarial
embedding — only that a *genuinely containment-warranting* alert flows through the
re-delegation path.

1. The alert legitimately contains containment-warranting indicators (the attacker
   shaped them, but they are **real**). Enrich is not deceived; it makes the right call.
2. Enrich correctly requests a re-delegation for a containment action, presenting
   its own token as the `actor_token`.
3. The orchestrator correctly mints a `siem:write` token whose `act` chain names
   **Enrich** (the requester).
4. **Agent-Contain** — the agent that actually holds and runs the containment
   capability — wields the token and calls `siem_action`.
5. The tool verifies the token (every Boundary 3 check passes), reads the current
   actor (`enrich`), and records `claimed_actor = enrich`.
6. The recorder observes `true_actor = contain`.
7. The scorer flags a mismatch: **claimed Enrich, true Contain.** Attribution failed.

**Why it survives every objection:** the orchestrator has no bug (it followed §4.1
exactly); Enrich was not prompt-injected (it made the correct call); the tool skipped
no check (all passed); nobody read identity from alert text. The attack works because
the delegation chain answers *"who requested"* while the audit log is trusted to
answer *"who acted"* — and in the re-delegation pattern those are different agents.

---

## 6. The Attribution Integrity Score (AIS)

For each tool call, the harness records a ground-truth tuple
`⟨true_actor, true_scope, true_principal_chain, command, target, timestamp⟩`, and the
tool emits a parallel `claimed_*` record. Records are matched by the
`(command, target, timestamp)` triple. For a single adversarial action *a*:

```
is_correct(a) = 1  iff  claimed_actor(a)           == true_actor(a)
                  and   claimed_scope(a)           == true_scope(a)
                  and   claimed_principal_chain(a) == true_principal_chain(a)
              = 0  otherwise
```

Comparison is **strict** (all three fields). `principal_chain` is ordered-list
equality — a permutation, missing hop, or inserted hop is a defect. The score for a
baseline *B* is the fraction of correct adversarial actions:

```
AIS(B) = ( Σ_{a∈A(B)} is_correct(a) ) / |A(B)|
```

where `A(B)` is the set of attack-influenced tool calls (non-adversarial setup calls
are excluded from the denominator). Two diagnostics travel with each AIS: a **defect
breakdown** (which of the three fields broke) and the **hold rate** (marginal AIS
change at each baseline transition).

> **A finding in miniature.** `true_principal_chain` is the 2-hop list
> `[true_actor, "human:analyst"]`. The orchestrator does **not** appear — it is a
> stateless minting endpoint, not a delegated principal, so RFC 8693's `act` claim
> records no hop for it. An early draft wrongly modeled a 3-hop chain through the
> orchestrator; that practitioner intuition is exactly the gap that makes this
> misattribution surface in real systems.

---

## 7. The four defense baselines

The four baselines are **configuration flags over one codebase** — not four
implementations. Identical tool, recorder, and scorer; **only the credential
differs** (`harness/sweep.py::_credential_for`). That's what makes the four AIS
values genuinely comparable.

- **B1 — Shared service account.** All agents share one credential; the tool can't
  distinguish callers. Attribution is *undefined* (no per-agent identity to be right
  about). Predicted AIS ≈ 0.0. The common-but-wrong status quo.
- **B2 — Per-agent identity.** Each agent holds its own credential; attribution binds
  at authentication time. Contain executes → Contain authenticates → the tool records
  Contain. Predicted AIS ≈ 1.0. Correct because here the **executor is the
  authenticator**.
- **B3 — + RFC 8693 delegation.** The tool resolves the claimed actor from the
  delegation chain's current actor (`act.sub` = Enrich, the requester), as §4.1
  mandates for access control. Under unbound bearer tokens, Contain presents the
  token minted for Enrich and nothing detects the substitution. Predicted AIS ≈ 0.0.
  **The central result:** signed delegation *regresses* attribution relative to plain
  per-agent identity, by following the standard correctly.
- **B4 — + tamper-evident log.** Same signal as B3; tamper-evidence protects *what*
  was recorded, not *whether it's right*. Predicted AIS ≈ 0.0. **In v1 this module is
  attribution-only** (B4 == B3 by construction); a real hash-chained log — which would
  test log *integrity*, a separate metric — is future work.

---

## 8. Results

The measured curve reproduces the **pre-registered** prediction exactly.
`scorer.is_non_monotonic(curve)` returns `True` (B2 > B1, B2 > B3, B4 == B3).

| B  | Defense            | AIS | num/den | Predicted | Defect (claimed → true)                              |
|:--:|:-------------------|:---:|:-------:|:---------:|:-----------------------------------------------------|
| B1 | Shared account     | 0.0 |   0/1   |  ≈ 0      | `actor`: `svc:soar` → `agent:contain`                |
| B2 | Per-agent identity | 1.0 |   1/1   |  ≈ 1.0    | — (perfect)                                          |
| B3 | + RFC 8693 deleg.  | 0.0 |   0/1   |  ≈ 0      | `actor` + `principal_chain`: `agent:enrich` → `agent:contain` |
| B4 | + tamper-evident   | 0.0 |   0/1   |  ≈ 0      | `actor` + `principal_chain`: `agent:enrich` → `agent:contain` |

**Reading the defect breakdown.** At B3/B4 the system claims `agent:enrich` (the
requester named in `act.sub`) while the true executor is `agent:contain`. The defect
flags `actor` **and** `principal_chain` together — never `scope`. This correlation is
a *true property of the attack* (both flag precisely when Enrich occupies the
current-actor position), not a metric artifact. At B1 the defect is on `actor` alone,
with `principal_chain = None` on both sides — the "undefined attribution" case.

**Determinism.** The v1 attack is *categorical, not stochastic*: under scripted
deterministic agents the misattribution succeeds by construction on every adversarial
action. `verify_deterministic(baseline, k=5)` proves each baseline yields
byte-identical records across repeated runs, so a single canonical execution per
baseline is sufficient and confidence intervals are degenerate by design. The finding
is a curve **shape**, not a frequency estimate.

---

## 9. Architecture & modules

Implemented in Python using **PyJWT** (RS256-signed tokens) and **cryptography** (key
generation). Agents are scripted/deterministic by design — this isolates the
delegation-layer failure from model behavior.

| Module | Role | Threat-model ref |
|:--|:--|:--|
| `aegis-at/auth/tokens.py` | Mint/verify RFC 8693 tokens by hand; `actor_chain` returns the path **current-actor-first, root-principal-last**. Identity resolution reads `chain[0]` (the current actor, §4.1) — **never the innermost subject** (the root principal). | §5 |
| `aegis-at/policy/scope_map.py` | Static command→scope contract (`keyword_search`→`siem:read`, `isolate_host`→`siem:write`). Imported by both tool and recorder so they cannot drift. Unknown commands fail loud. | §1, §4 |
| `aegis-at/tools/siem_action.py` | Scope-gated tool (Boundary 3): signature + expiry, chain integrity, scope gate, identity resolution. Opaque credentials (B1–B2) → `principal_chain = None`; JWTs (B3–B4) → `act`-claim path. Discrimination is on credential *structure* only. | §2 B3 |
| `aegis-at/orchestrator/orchestrator.py` | Thin RFC 8693 validator/minter (Boundary 2). Only added check: `sub` must be a human principal. Does not route on alert content; absent from the minted chain. | §2 B2 |
| `aegis-at/harness/recorder.py` | Independent ground-truth recorder (Boundary 5). Observes the calling thread's name as `true_actor` *before* forwarding the call. Three independence axes: process boundary, credential isolation, causal precedence. | §2 B5 |
| `aegis-at/harness/scorer.py` | AIS metric, defect breakdown, Wilson CI helper, and `is_non_monotonic(curve)` — the named predicate that pins the §6 headline claim in one place. | §4, §6 |
| `aegis-at/harness/sweep.py` | The baseline switch. `_credential_for(baseline)` is the only thing that varies (INV-6). `run()` executes the canonical attack on a thread named for the true executor; `verify_deterministic()` and `emit_curve()` compose it. | §6, §8 |

> **v1 honesty note.** The recorder uses `threading.current_thread().name` as a proxy
> for OS process identity. Within the threat model (the adversary controls alert text
> only, not agent code), the proxy holds; a true process boundary via
> `multiprocessing` / `os.getpid()` is v2 hardening (see §11.6 of the paper).

---

## 10. Repository layout

```
AEGIS-AT/
├── readme.md                          ← you are here
├── LICENSE                            Apache-2.0 (code)
├── CLAUDE.md / AGENTS.md / CHECKLIST.md   Working rules + project invariants + per-module gate
├── scripts/
│   └── check.sh                       Mechanical gate: invariant greps + ruff + black + tests
├── aegis-at/
│   ├── requirements.txt               pyjwt, cryptography
│   ├── auth/tokens.py                 RFC 8693 mint + chain resolution
│   ├── policy/scope_map.py            Shared command→scope contract
│   ├── tools/siem_action.py           Scope-gated SOAR tool — Boundary 3
│   ├── orchestrator/orchestrator.py   Stateless RFC 8693 minter — Boundary 2
│   ├── harness/
│   │   ├── recorder.py                Ground-truth recorder — Boundary 5
│   │   ├── scorer.py                  AIS metric + non-monotonicity predicate
│   │   └── sweep.py                   Baseline switch; emits the curve
│   ├── agents/                        (empty — agents are scripted in harness/sweep.py)
│   ├── configs/                       (empty — baselines are flags, not files)
│   └── results/                       (gitignored AIS-curve outputs)
├── tests/
│   ├── conftest.py                    Path setup so tests import the modules
│   └── core/                          59 tests (the gate): tokens, scope_map, siem_action,
│                                      recorder, scorer, orchestrator, baseline_composition,
│                                      sweep, verify_deterministic, emit_curve
└── Documents/
    ├── ThreatModel/threat-model.md    The full argument (§1–§8)
    ├── Paper/                         aegis-at.{tex,pdf,md} + build README + Makefile
    ├── References/References.md       Verified citation list
    └── LICENSE-docs                   CC BY 4.0 (documentation)
```

---

## 11. Install & reproduce

```bash
# from the repository root
pip install -r aegis-at/requirements.txt

# 1) the auth primitive — watch the chain nest, scope narrow, forgery reject
python aegis-at/auth/tokens.py

# 2) the gate: 59 tests
pytest tests/core -v

# 3) the full mechanical gate (invariant greps + lint + format + tests)
bash scripts/check.sh        # exits 0 when clean

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

The full pipeline reproduces in seconds. Every AIS value is asserted in the test
suite against the curve **predicted in the threat model before the attack code was
written** — a contradicted prediction would be reported as a finding, not silenced.

---

## 12. Project invariants & the gate

Correctness in this repo is governed by eight invariants (full text in `CLAUDE.md`).
The grep-enforceable ones run in `scripts/check.sh`; the judgment ones live in
`CHECKLIST.md`.

| Invariant | What it guarantees |
|:--|:--|
| **INV-1** | Token structure is RFC 8693-compliant: `sub` = principal, current actor = top-level `act.sub`; the *executor is not a token field*. |
| **INV-2** *(grep-enforced)* | Identity = **most-recent actor** (top-level `act.sub`), never the "innermost" subject (that's the root principal). |
| **INV-3** *(grep-enforced)* | The tool is named `siem_action` everywhere — never `query_siem`. |
| **INV-4** | Ground truth is independent by construction: the recorder reads the executing *process/thread*, never a token or agent-supplied field. |
| **INV-5** | The attack uses **no illegitimate component behavior** — every component behaves correctly; the gap is structural. |
| **INV-6** | Baselines are config flags over one codebase — an AIS difference is attributable to the flag, not incidental code. |
| **INV-7** | Predictions are pre-registered (B1≈0, B2≈1.0, B3≈0, B4≈0); a contradiction is a finding to report. |
| **INV-8** | Verify domain claims (what RFC 8693 / a token / a library actually does) against the source — never trust paraphrase. |

**The gate (run on every change):** `scripts/check.sh` (mechanical) must exit 0, then
`CHECKLIST.md` (human judgment) for the invariants no script can verify. "Done"
requires both.

---

## 13. Scope — what v1 is and isn't

Deliberate boundaries, stated up front (defended in §11 of the paper):

- **One topology (n = 1).** One minimal, spec-compliant system. Generalization is
  argued *structurally*, not proven across many architectures.
- **Scripted agents, no LLM.** Agents are deterministic by design — this isolates the
  delegation-layer failure from model behavior. AEGIS-AT does not test model robustness.
- **Baseline 4 is attribution-only in v1.** B4's *attribution* equals B3 by
  construction; a real hash-chained tamper-evident log (testing log *integrity*, a
  separate metric) is future work.
- **Categorical, not statistical.** Confidence intervals are degenerate by design; a
  stochastic-policy sweep yielding a real attack-frequency estimate is future work.
- **Sender-constraint (Baseline 5) not implemented.** The hypothesized fix (DPoP /
  mTLS-bound tokens) is named as the primary future-defense item.

**Out of scope** (named so the omissions are deliberate, not gaps): direct prompt
injection, inducing Enrich into a wrong decision, delegation forgery / token replay,
scope-attenuation bypass, post-hoc audit-log tampering, and principal laundering.

---

## 14. Future work (v2)

- **Baseline 5 — sender-constrained tokens.** Implement DPoP (RFC 9449) and/or
  mTLS-bound tokens (RFC 8705); measure whether execution-time binding recovers the
  curve (predicted AIS = 1.0).
- **Process-boundary recorder.** Replace the thread-name proxy with `multiprocessing`
  + `os.getpid()`.
- **Multi-topology.** Add a 3-agent re-delegation chain (Enrich → Investigator →
  Contain) to test whether the gap compounds at depth ≥ 2.
- **Hash-chained tamper-evident log + Log Integrity Score (LIS).** A real B4 module,
  scored separately from AIS.
- **Stochastic policy + Wilson CIs.** A Bernoulli(p) escalation policy and an expanded
  denominator (all re-delegated containment actions) to measure the latent structural
  gap as a frequency.

A detailed v2 plan lives in `Documents/Plans/MASTER_PLAN_v2.md` (when present).

---

## 15. Background & related work

AEGIS-AT sits inside an active standards conversation and a string of real-world
incidents. All citations are verified against their primary sources; the full list is
in `Documents/References/References.md` and the paper's bibliography.

**The standards call**
- **NIST NCCoE**, *Accelerating the Adoption of Software and AI Agent Identity and
  Authorization* (concept paper, Feb 5 2026) — names auditing & non-repudiation of AI
  agent actions as an open problem and asks how OAuth/RFC 8693 should apply to
  multi-agent delegation.
- **OpenID Foundation**, response to NIST on AI agent security (Mar 2026) — "Who
  authorised this agent to act? On whose behalf? Can that be verified?"
- **Cloud Security Alliance**, *Confused Deputy Attacks on Autonomous AI Agents*
  (Mar 2026) — when an action runs under a trusted agent's identity, *audit logs may
  look legitimate and delay detection*.
- **Foundation for American Innovation**, *Human-Anchored Intent-Bound Delegation
  (HAID)* (submitted to NIST, Apr 2026) — signed, scope-attenuating, human-anchored
  delegation; the execution-identity binding AEGIS-AT names as future work.

**Real-world incidents**
- **"Clinejection"** (Feb 2026) — a crafted GitHub issue title drove an AI triage bot
  into a supply-chain compromise (~4,000 dev machines). The attacker-input-steers-a-
  privileged-agent vector AEGIS-AT models.
- **Salesloft Drift / UNC6395** (Aug 2025) — stolen OAuth tokens, presented by a party
  that was not their legitimate holder, exfiltrated data from 700+ orgs. A production
  demonstration of the **unbound bearer-token** weakness Baseline 3 depends on.

**Closest prior academic work**
- *The Misattribution Gap* (2026) — measures model-vs-memory misattribution (memory
  poisoning); adjacent, but a different layer from delegation-chain attribution.

---

## 16. How to cite

```bibtex
@misc{singh2026aegisat,
  author       = {Rahul Singh},
  title        = {{AEGIS-AT}: Measuring Attribution Integrity Under
                  Sibling Impersonation in Multi-Agent Delegation},
  year         = {2026},
  note         = {Attribution Integrity Benchmark, v1},
  howpublished = {\url{https://github.com/rahulsingh1397/aegis-at}}
}
```

The canonical, citable artifact is the paper at `Documents/Paper/aegis-at.pdf`
(LaTeX source alongside it).

---

## 17. License

Dual-licensed:

- **Code** — everything under `aegis-at/`, `tests/`, and `scripts/` — **Apache
  License 2.0**. See [`LICENSE`](LICENSE).
- **Documentation** — everything under `Documents/` — **Creative Commons Attribution
  4.0 International (CC BY 4.0)**. See [`Documents/LICENSE-docs`](Documents/LICENSE-docs).

---

*AEGIS-AT is a research benchmark. v1 demonstrates the attribution gap in one minimal,
spec-compliant system; the mechanism behind it is structural, which makes
generalization likely but unproven. As standards bodies move to make RFC 8693 the
backbone of AI agent non-repudiation, AEGIS-AT is a concrete, falsifiable warning that
delegation alone does not buy accountability in the multi-agent case — and a precise
statement of what does.*