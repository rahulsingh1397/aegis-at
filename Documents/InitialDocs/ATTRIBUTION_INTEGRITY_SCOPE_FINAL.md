# Attribution Integrity Under Adversarial Pressure
### A red-team benchmark for delegation-chain accountability in multi-agent systems

**Working title:** AEGIS-AT — Attribution Integrity Benchmark
**Scope decision:** Full-stack build (real RFC 8693 token exchange + real agent system), **one failure mode done rigorously**, portfolio-first with paper as byproduct.
**One-line pitch:** When agent identity and delegation defenses are deployed exactly as the 2026 standards bodies recommend, can an adversary still break attribution — and by how much?

---

## Why this scope

The generic "multi-agent security evaluation framework" is saturated (AgentAuditor, AgentLeak, SafeEvalAgent, ShieldAgent, plus a published survey). The defensive primitives are being standardized right now (NIST/NCCoE Feb 2026; OAuth 2.0 Token Exchange RFC 8693 `act` claim; SPIFFE/SPIRE; hardware-attested delegation tokens at RSAC 2026).

The open, measurable gap: nobody has stress-tested whether attribution *survives adversarial pressure* once these defenses are deployed. NIST is openly asking for non-repudiation/auditing evidence and has no benchmark to point at. **That measurement is the contribution.**

Because this is portfolio-first on a September timeline, the system is **real** (that's the engineering credibility) but the attack surface is **deliberately narrow** (one failure mode, fully defensible). A working real-token-exchange system that you broke and *measured* on one attack is a sharper artifact than a big system with thin results.

---

## Problem statement

In a delegation chain (human principal → orchestrator → subagent → tool), every framework now *claims* it can answer "which agent, under whose authority, did this?" That claim is asserted, not tested. This project measures: under adversarial conditions, what fraction of actions can an attacker cause to be **misattributed**, and which defense layer fixes it?

Output: an **Attribution Integrity Score (AIS)** and a reproducible harness that produces it.

---

## The ONE failure mode (v1)

**Sibling impersonation via scope confusion.**
> A prompt-injection payload causes Subagent A to perform an action that the audit trail records under Subagent B's identity/scope. Failure = the attributed actor in the tamper-evident record does not match the agent that actually executed the action.

This is chosen because it is (a) concrete, (b) cleanly scorable against ground truth, (c) directly tied to the non-repudiation question NIST raised, and (d) not dependent on inventing crypto.

*Backlog (explicitly out of v1, named so the paper can cite future work):* delegation-chain forgery/replay, scope-attenuation bypass, audit-log tampering, principal laundering.

---

## Metric design (own this completely — it is the publishable core)

- **Ground truth:** the harness records, for every action, the true `(agent_id, scope, principal_chain)`. You control this; it's what makes scoring valid.
- **Attribution Integrity Score (AIS):** fraction of adversarial actions whose *recorded* attribution exactly matches ground truth on `{actor, scope, principal_chain}`.
- **Report per defense configuration** — the deltas are the finding, not the aggregate.
- **Baselines (must be fair):**
  1. Shared service-account credential (status-quo, wrong-but-common)
  2. Per-agent identity only
  3. Per-agent identity + signed delegation (RFC 8693 `act` claim)
  4. Full: #3 + tamper-evident action log
- **The story is the curve across #1→#4** for the sibling-impersonation attack.

> Rule that separates this from a vuln demo: an attack only counts if it produces a *measured attribution defect* scored against controlled ground truth.

---

## Architecture (what "full stack" means here)

```
Human principal
   │  (OAuth2/OIDC login → initial token)
   ▼
Orchestrator agent ──issues delegated tokens via RFC 8693 token exchange──┐
   │                                                                       │
   ├── Subagent A (scoped token, act-claim chain) ── Tool 1                │
   └── Subagent B (scoped token, act-claim chain) ── Tool 2                │
                                                                           ▼
Authorization Server (real token exchange + act-claim delegation)
Tamper-evident action log  ←── every tool call writes (claimed actor, scope, chain)
Ground-truth recorder      ←── harness writes the TRUE actor/scope/chain
Scorer                     ←── diff claimed vs. true → AIS
Attack injector            ←── sibling-impersonation payloads at the A/B boundary
```

The Authorization Server correctness is load-bearing: if token exchange is mocked, "I broke attribution" reads as "I broke my own toy." Getting `act`-claim delegation genuinely right is the part of the build that earns the result.

---

## Realistic 4-month plan (methodology front-loaded)

| Month | Focus | Exit gate |
|-------|-------|-----------|
| **June** | Threat model + AIS formalized in writing. Ground-truth schema designed. Orchestrator + 2 subagents + 1 tool running with per-agent identity (baseline #2). | Written, defensible threat model + metric spec **before** any attack code. This is the gate — do not skip it. |
| **July** | Real RFC 8693 token exchange working (baselines #3, #4). Sibling-impersonation attack implemented + scored. | AIS produced for all 4 baseline configs on the one attack. |
| **August** | Hardening, sensitivity/sanity checks, ablations, reproducibility (seeds, configs, scripts). Begin writeup. | Complete, reproducible results curve #1→#4. |
| **September** | Writeup, open-source the harness, arXiv if results hold. Fellows reapplication cites it. | Public repo + paper draft. A clean *negative* result (defenses hold) is still publishable. |

**Cut line if behind:** drop baseline #4 before you compromise the rigor of #1–#3, or drop the writeup polish before you compromise the metric. Never thin the ground-truth/scoring integrity.

---

## What you own vs. what you assemble

- **You own (must defend line-by-line):** threat model, AIS definition and why it's valid, ground-truth design, baseline fairness, interpretation of the deltas. This is the authentic core and the part no tooling can produce for you.
- **You assemble (fine to lean on tooling):** agent scaffolding (LangGraph/AutoGen), auth-server + token-exchange plumbing, log infra, attack-injection glue.

The integrity of the measurement is the whole game. System scale is not.

---

## Honest framing note

Build this because the attribution question is real, unclaimed from the red-team side, and squarely in your lane (threat detection + governance). The Fellows strengthening is a *byproduct* of a sound project, not its thesis — and it reads that way to reviewers, which is the point.
