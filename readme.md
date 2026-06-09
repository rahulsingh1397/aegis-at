# AEGIS-AT — Attribution Integrity Benchmark

**Adding the industry-standard delegation mechanism to a correctly-functioning
multi-agent AI system makes audit attribution *worse*, not better.**

AEGIS-AT is a red-team benchmark that measures whether delegation-chain
attribution survives a realistic sibling-impersonation attack in a multi-agent
system. It implements a minimal Security Operations Center (SOC) pipeline — two
agents sharing one tool — and measures an **Attribution Integrity Score (AIS)**
across four progressive defense baselines.

The headline result is a **non-monotonic curve**: attribution is perfect under
simple per-agent identity, then *regresses to completely wrong* the moment you
add RFC 8693 delegation — the mechanism standards bodies recommend for
multi-agent non-repudiation. Tamper-evident logging does not recover it.

---

## The finding

| Baseline | Defense in place                          | AIS  |
| :------: | :---------------------------------------- | :--: |
|   B1     | Shared service account                    | 0.0  |
|   B2     | Per-agent identity                        | 1.0  |
|   B3     | + RFC 8693 delegation                     | 0.0  |
|   B4     | + tamper-evident log                      | 0.0  |

The curve rises to perfect attribution at **B2**, then **regresses to zero at
B3** when signed delegation is added, and **stays at zero at B4** — tamper-evident
logging cannot recover what was already mis-recorded at mint time. Adding two of
the primitives most emphasized for agent non-repudiation makes attribution worse,
not better.

**Why it regresses — the structural mechanism (not a bug):**
RFC 8693's "current actor" (`act.sub`) is the party that *requested* the
delegated authority. In a multi-agent hand-off, the agent that *executes* the
action can differ from the one named in the token — and the standard provides no
field that records the executor. §4.1's `MUST` is scoped to the **access-control
decision**, not to audit logging; combined with unbound bearer tokens (RFC 8693
inherits OAuth 2.0's default holder model) and a mint-before-execution topology,
the realistic implementation logs the *requester*. The standard neither prevents
nor mandates this — it simply has no place to put the executor. The fix is
execution-identity binding (sender-constrained tokens, **DPoP / RFC 9449** or
**mTLS / RFC 8705**), named as future work and not implemented in v1.

---

## Why it matters

Picture a hospital's automated security response. A low-privilege triage agent
reads an alert and escalates; a high-privilege containment agent quarantines a
machine — say, a device on a patient-monitoring network. Afterward, the audit
log needs to answer one question: *which agent took the high-consequence action?*

Under standard delegation, the log names the agent that **requested** the
containment, not the one that **executed** it. If an attacker can shape the alert
that triggers the chain, they can cause a high-privilege action to be taken and
attributed to the wrong, lower-privilege agent — covering the real executor's
tracks while looking fully spec-compliant. The accountability the standard was
adopted to provide is exactly what fails.

The standards landscape is actively asking for exactly this measurement. NIST's
NCCoE concept paper (*Accelerating the Adoption of Software and AI Agent Identity
and Authorization*, Feb 2026) names auditing and non-repudiation of AI agent
actions as an open problem and asks how existing identity standards — OAuth, RFC
8693 — should apply to multi-agent delegation. The confused-deputy gap has also
shown up in production: the "Clinejection" incident (Feb 2026) used a crafted
GitHub issue title to drive a privileged AI agent into a supply-chain compromise
of ~4,000 developer machines — attacker-controlled input steering a privileged
agent through a confused-deputy chain.

AEGIS-AT doesn't restage Clinejection; it measures the attribution question one
layer down — *when a privileged action is taken through delegation, does the
audit record name the agent that executed it?* No published adversarial benchmark
answers that for the sibling-impersonation case across a structured defense
gradient; this is one. (The closest prior work, *The Misattribution Gap*, measures
model-vs-memory misattribution — adjacent, not the same layer.)

---

## What AEGIS-AT is

A deliberately minimal system, built so the causal chain is clean and the
measurement is defensible:

- **Two agents, one tool.** `Agent-Enrich` (low-privilege, read-only) and
  `Agent-Contain` (high-privilege, can execute `isolate_host`) share a single
  scope-gated SOAR tool, `siem_action`.
- **One attack.** A containment-warranting alert — with attacker-controlled
  text — flows through Enrich; Enrich correctly escalates; the orchestrator
  honestly mints a delegation token naming Enrich (the requester); Contain (the
  executor) wields it. The log names Enrich.
- **Four baselines, one codebase.** Baselines are configuration flags over
  identical tool / recorder / scorer code — only the credential differs. This is
  what makes the four AIS values comparable rather than apples-to-oranges.
- **An independent ground-truth recorder.** A harness component observes the
  *true* executing agent out-of-band (from the execution thread, never from the
  token), so the score compares what the system *claims* against what *actually
  happened*.
- **A strict metric.** AIS is the fraction of adversarial actions whose claimed
  `(actor, scope, principal_chain)` exactly matches ground truth. The scorer also
  reports *which* field broke, so the failure can be diagnosed, not just counted.

---

## Status

| Layer            | Artifacts                                                                 | State |
| :--------------- | :------------------------------------------------------------------------ | :---- |
| Threat model     | 8-section document (system, trust boundaries, adversary, metric, attack, baselines, scope, validity threats) | Locked, internally consistent |
| Foundation       | `auth/tokens.py`, `policy/scope_map.py`, `tools/siem_action.py`, `harness/recorder.py`, `harness/scorer.py`, `orchestrator/orchestrator.py` | 43 unit tests |
| Harness          | `harness/sweep.py` — `run()`, `verify_deterministic()`, `emit_curve()`    | 16 composition/harness tests |
| **Total**        |                                                                           | **59 tests green; gate clean; curve confirmed** |

The AIS curve is produced **deterministically** against the real modules:
`verify_deterministic()` proves each baseline yields byte-identical records
across repeated runs, so a single canonical execution per baseline is sufficient.
The result is **categorical** — the attack succeeds by construction, not with
some probability — so the finding is a curve shape, not a statistical estimate.

### Scope (what v1 is, and isn't)

These are deliberate boundaries, stated up front:

- **One topology (n = 1).** The benchmark demonstrates the mechanism in one
  minimal, spec-compliant system. Generalization is argued *structurally*, not
  proven across many architectures.
- **Scripted agents, no LLM.** Agents are deterministic by design — this isolates
  the delegation-layer failure from model behavior. AEGIS-AT does not test model
  robustness.
- **Baseline 4 is attribution-only in v1.** B4's *attribution* equals B3 by
  construction; a real hash-chained tamper-evident log module (which would test
  log *integrity*, a separate metric) is future work.
- **Categorical, not statistical.** Confidence intervals are degenerate by design;
  a stochastic-policy sweep that would yield a real attack-frequency estimate is
  future work.
- **Sender-constraint (Baseline 5) not implemented.** The hypothesized fix
  (DPoP / mTLS-bound tokens) is named as the primary future-defense item.

---

## Reproduce

```bash
pip install -r aegis-at/requirements.txt
pytest tests/core -v          # 59 tests
bash scripts/check.sh         # lint, format, invariant, and test gate
```

The full pipeline reproduces in seconds. Every AIS value is asserted in the test
suite against the curve predicted in the threat model *before* the attack code
was written — a contradicted prediction would be reported as a finding, not
silenced.

---

## Repository map

```
Documents/
  ThreatModel/threat-model.md          The full argument (§1–§8): system, metric,
                                        attack, baselines, scope, validity threats.
  ImportantQuestions/                   Working notes — the *why* behind each module:
    Harness_Notes/{Recorder,Sweep,scorer}Notes/
    orchestrator_notes/  policy_notes/  toolsDocs/
aegis-at/
  auth/tokens.py                        RFC 8693 token mint + chain resolution.
  policy/scope_map.py                   Shared command→scope contract.
  tools/siem_action.py                  Scope-gated SOAR tool (Boundary 3).
  orchestrator/orchestrator.py          Stateless RFC 8693 token-exchange minter.
  harness/recorder.py                   Independent ground-truth recorder (Boundary 5).
  harness/scorer.py                     AIS metric + non-monotonicity predicate.
  harness/sweep.py                      Baseline-switch harness; emits the curve.
tests/core/                             59 tests across unit + composition layers.
```

Start with `Documents/ThreatModel/threat-model.md` for the argument, or
`harness/sweep.py` + `tests/core/test_emit_curve.py` for the executable result.

---

## Background & related work

AEGIS-AT sits inside an active standards conversation and a string of real-world
incidents. All citations below were checked against their live primary sources.

**The standards call — bodies are explicitly asking for this:**

- **NIST NCCoE**, *Accelerating the Adoption of Software and AI Agent Identity and
  Authorization* (concept paper, Feb 5 2026). Names auditing and non-repudiation
  of AI agent actions as an open problem and asks how existing identity standards
  (OAuth 2.0, OpenID, SPIFFE) should apply to multi-agent delegation — including
  the unresolved case of multi-hop delegation.
  [csrc.nist.gov](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
- **OpenID Foundation**, response to NIST on AI agent security (Mar 2026). Frames
  the most urgent risks as failures of *trust*: "Who authorised this agent to act?
  On whose behalf? Can that be verified?" — and notes today's deployments rely on
  unsigned credentials and no clear chain of accountability.
  [openid.net](https://openid.net/oidf-responds-to-nist-on-ai-agent-security/)
- **Cloud Security Alliance**, *Confused Deputy Attacks on Autonomous AI Agents*
  (Mar 23 2026). Establishes confused-deputy as a high-severity pattern in agent
  deployments and observes that when an action runs under a trusted agent's
  identity, **audit logs may look legitimate and delay detection** — precisely the
  attribution failure AEGIS-AT measures.
  [labs.cloudsecurityalliance.org](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-confused-deputy-prompt-injection/)
- **Foundation for American Innovation**, *Human-Anchored Intent-Bound Delegation
  (HAID)* (submitted to NIST, Apr 2026). A proposed fix: signed, scope-attenuating,
  human-anchored delegation chains — the kind of execution-identity binding
  AEGIS-AT names as future work (Baseline 5).
  [thefai.org](https://www.thefai.org/posts/human-anchored-intent-bound-delegation-for-ai-agents)

**Real-world incidents — the failure modes in production:**

- **"Clinejection"** (Feb 2026). A crafted GitHub issue title drove the Cline AI
  tool's own triage bot into a supply-chain compromise — an unauthorized npm
  package on ~4,000 developer machines in an 8-hour window. Attacker-controlled
  input steering a privileged agent through a confused-deputy chain — the input
  vector AEGIS-AT models.
  [Snyk](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/)
- **Salesloft Drift / UNC6395** (Aug 2025). Stolen OAuth tokens from the Drift AI
  chat integration were used to exfiltrate Salesforce data from 700+ organizations.
  A production demonstration of the **unbound bearer-token** weakness — a token
  presented by a party that was not its legitimate holder — which is the holder-model
  premise AEGIS-AT's Baseline 3 depends on.
  [Google Threat Intelligence](https://cloud.google.com/blog/topics/threat-intelligence/data-theft-salesforce-instances-via-salesloft-drift)

**Closest prior academic work:**

- *The Misattribution Gap* (2026) measures model-vs-memory misattribution in
  agentic systems — adjacent, but a different layer (memory poisoning, not
  delegation-chain attribution). See `Documents/References/References.md` for the
  full citation list.

---

## License

This repository is dual-licensed:

- **Code** — everything under `aegis-at/`, `tests/`, and `scripts/` — is licensed
  under the **Apache License 2.0**. See [`LICENSE`](LICENSE).
- **Documentation** — everything under `Documents/` (threat model, working notes,
  references) — is licensed under **Creative Commons Attribution 4.0 International
  (CC BY 4.0)**. See [`Documents/LICENSE-docs`](Documents/LICENSE-docs).