# AEGIS-AT — Consolidated Reference

### Attribution Integrity Under Adversarial Pressure · A red-team benchmark for delegation-chain accountability in multi-agent AI systems

> **What this document is.** A single, self-contained reference that consolidates the three working documents — **Scope & Strategy**, the **Threat Model**, and the **Visual Explainer** — into one source of truth. The separate documents are retained for their individual audiences; this file is the canonical version they should all agree with. Where they ever diverge, this document wins.
>
> **One-line pitch.** When agent identity and delegation defenses are deployed *exactly* as the 2026 standards bodies recommend, can an adversary still break attribution — and by how much?
>
> **Framing lock (read this first).** Every claim in this document uses one consistent framing of the central result: RFC 8693 §4.1's `MUST` is scoped to the **access-control decision**, *not* to audit logging. The standard **neither prevents nor mandates** the misattribution; the **multi-agent topology produces it** (a current-actor claim that names the requester, reused in practice for the audit record, under an unbound-bearer hand-off where the executor differs from the requester). The earlier "spec-*mandates*-the-wrong-record" phrasing has been retired here as an overclaim — it is the objection a reviewer reaches for first, and the project's own validity analysis (§II.8.5) and build-risk notes already concede it.

---

# Part I — Scope & Strategy

## Why this scope

The generic "multi-agent security evaluation framework" space is saturated (AgentAuditor, AgentLeak, SafeEvalAgent, ShieldAgent, plus a published survey). The defensive primitives, by contrast, are being standardized right now: NIST/NCCoE (Feb 2026); OAuth 2.0 Token Exchange (RFC 8693 `act` claim); SPIFFE/SPIRE; hardware-attested delegation tokens (RSAC 2026).

The open, measurable gap: **nobody has stress-tested whether attribution survives adversarial pressure once these defenses are deployed.** NIST is openly asking for non-repudiation / auditing evidence and has no benchmark to point at. That measurement is the contribution.

The sharpest, most defensible version of the finding is not "attribution can be broken" but a stronger, narrower claim: **a standards-compliant delegation system attributes the action to the requester and provides no field for the executor.** A token consumer applying RFC 8693 §4.1 correctly resolves the *current actor* (the requester) for its access-control decision; a realistic implementation reuses that identity for the audit record; and "just read a different field" does not help because the executor is not in the token at all. The standard does not force this audit outcome — but it does not prevent it either, and no compliant field records the executor when it differs from the requester. That is the sentence no prior paper owns.

Because this is portfolio-first on a September timeline, the system is **real** (engineering credibility) but the attack surface is **deliberately narrow** (one failure mode, fully defensible). A working real-token-exchange system that you broke and measured on one attack is a sharper artifact than a big system with thin results.

## Problem statement

In a delegation chain (human principal → orchestrator → subagent → tool), every framework now claims it can answer *"which agent, under whose authority, did this?"* That claim is asserted, not tested. The subtlety it hides: a signed delegation chain records **who requested** authority, while an audit log is trusted to record **who executed**. In single-agent use these coincide; in multi-agent re-delegation they diverge.

This project measures: under adversarial conditions, what fraction of actions can an attacker cause to be misattributed, and which defense layer fixes it? **Output:** an Attribution Integrity Score (AIS) and a reproducible harness that produces it.

## The ONE failure mode (v1)

**Sibling misattribution via re-delegation (Path B).** An attacker shapes the content of a SIEM alert that the low-privilege **Enrich** agent ingests. The alert genuinely warrants a containment action — so Enrich is *not* deceived; it makes the correct escalation and submits an RFC 8693 re-delegation request. The orchestrator honestly mints a correctly-scoped `siem:write` token whose current actor (`act.sub`) is Enrich, the requester. The high-consequence action (`isolate_host`) is executed by **Contain** — the true executor — but the audit record names Enrich. **Failure** = the attributed actor (Enrich) does not match the agent that actually executed (Contain): the high-consequence actor hidden behind the benign sibling — a "covering tracks" outcome.

This mode is chosen because it is (a) concrete, (b) cleanly scorable against ground truth, (c) directly tied to the non-repudiation question NIST raised, (d) not dependent on inventing crypto, and (e) **structural** — every cryptographic check passes and no agent is manipulated into error, so a reviewer cannot dismiss it as a bug or a prompt-injection artifact.

**What the attacker does NOT do** (this is what makes it strong): no token forgery, no skipped check, no jailbreak, and crucially **Enrich is not tricked into a wrong decision**. The attacker's only capability is control of alert content (indirect injection; the Cline 2026 pattern). The misattribution is committed at the orchestrator's minting step (Boundary 2) and faithfully transcribed by the tool (Boundary 3 → 4).

**Backlog** (explicitly out of v1, named so the paper can cite future work): delegation-chain forgery/replay, scope-attenuation bypass, audit-log tampering, principal laundering, analyst-prompt (insider) injection.

## Metric design (the publishable core — own this completely)

- **Ground truth.** The harness records, for every action, the true `(agent_id, scope, principal_chain)`, observed independently of any token or self-reported field. You control this; it is what makes scoring valid.
- **Attribution Integrity Score (AIS).** Fraction of adversarial actions whose recorded attribution exactly matches ground truth on the full triple `{actor, scope, principal_chain}` (strict; `principal_chain` by ordered-list equality). A partial match (right scope, wrong actor) is still a defect.
- **Report per defense configuration** — the deltas are the finding, not the aggregate. Report the defect breakdown (which field failed) and a 95% Wilson CI per baseline.

**Baselines** (must be fair — config flags over one codebase, not four forks):

| # | Configuration | Signal the tool reads | Tracks executor? | Predicted AIS |
|---|---|---|---|---|
| 1 | Shared service-account credential | one shared identity | undefined | ≈ 0.0 |
| 2 | Per-agent identity only | execution-time authenticator | yes | ≈ 1.0 |
| 3 | + RFC 8693 `act` claims | delegation current actor (requester) | no | ≈ 0.0 |
| 4 | + tamper-evident action log | same as #3 | no | ≈ 0.0 |

The story is the **curve across #1 → #4, and it is non-monotonic.** It rises from #1 to #2, then regresses at #3 and stays low at #4. The headline: adding signed delegation (`act` claims) — the primitive NIST/NCCoE emphasize for non-repudiation — makes attribution **worse** than plain per-agent identity, by following RFC 8693 §4.1 correctly *for the access-control decision* and reusing that identity for audit; and tamper-evident logging (#4) cannot recover it, because the wrong actor was committed upstream at minting.

**Rule that separates this from a vuln demo:** an attack only counts if it produces a *measured* attribution defect scored against controlled ground truth. AIS values above are **pre-registered predictions**, to be confirmed or refuted by the measured sweep; a contradicted prediction is itself a reportable finding.

## Architecture (what "full stack" means here)

The Authorization Server / token-exchange correctness is **load-bearing**: if token exchange is mocked, "I broke attribution" reads as "I broke my own toy." Getting `act`-claim delegation genuinely right — verifying signatures, nesting the actor, narrowing scope, and **never** widening it — is the part of the build that earns the result. The system is deliberately **one tool and one atomic action**: that single degree of freedom (A acted, the log says B) is what keeps the measurement clean. The full system is shown in **§II.1** below.

## Realistic 4-month plan (methodology front-loaded)

| Month | Focus | Exit gate |
|---|---|---|
| **June** | Threat model + AIS formalized in writing. Ground-truth schema designed. Orchestrator + Enrich + Contain + one tool running with per-agent identity (baseline #2). | A written, defensible threat model + metric spec **before any attack code**. This is the gate — do not skip it. |
| **July** | Real RFC 8693 token exchange working (baselines #3, #4). Re-delegation misattribution attack implemented + scored. | AIS produced for all 4 baseline configs on the one attack; the non-monotonic curve is measured. |
| **August** | Hardening, sensitivity/sanity checks, ablations, reproducibility (seeds, configs, scripts). Begin writeup. | Complete, reproducible results curve #1→#4 with CIs and defect breakdown. |
| **September** | Writeup, open-source the harness, arXiv if results hold. Fellows reapplication cites it. | Public repo + paper draft. A clean result (even a negative one — defenses hold) is publishable. |

**Cut line if behind:** drop baseline #4 before you compromise the rigor of #1–#3, or drop writeup polish before you compromise the metric. **Never** thin the ground-truth / scoring integrity.

## Known build risks (resolve early)

1. **Baseline 2 chain-shape bug.** The documented Baseline-2 token (root, no `act`) yields a 1-hop `principal_chain` while the recorder hardcodes the 2-hop `[actor, human:analyst]` → the strict comparison sinks B2 to ≈ 0 instead of ≈ 1.0. Fix before the sweep (mint B2 tokens as 2-hop `[executor, analyst]`, or derive the true chain per baseline). **Without a 1.0 anchor at B2, there is no non-monotonic curve.**
2. **Attribution-vs-access-control framing.** §4.1's `MUST` governs access-control decisions; extending it to audit attribution is a *defensible modeling choice, not a forced consequence*. Name it explicitly in §II.6 / §II.8 so a reviewer cannot claim the system could simply log the execution-time authenticator. *(This is the framing locked at the top of this document.)*

## What you own vs. what you assemble

- **You own (defend line-by-line):** the threat model, the AIS definition and why it is valid, the ground-truth design, baseline fairness, interpretation of the deltas, and the structural/topological framing. This is the authentic core no tooling can produce for you.
- **You assemble (fine to lean on tooling):** agent scaffolding, auth-server + token-exchange plumbing, log infra, attack-injection glue, the baseline-sweep harness.

**The integrity of the measurement is the whole game. System scale is not.**

---

# Part II — Threat Model

*The rigorous specification. This is the artifact defended line-by-line at the June gate. Diagrams from the Visual Explainer are placed at the section each illustrates.*

## II.1 System under test

A minimal SOC alert-triage pipeline — the smallest configuration in which sibling impersonation is possible. A human analyst authenticates and issues a request to a triage **orchestrator**. The orchestrator delegates work to two sibling subagents — **Agent-Enrich** and **Agent-Contain** — by minting each a scoped delegation token (RFC 8693 `act` claim); this is the configuration measured at Baselines 3–4, while Baselines 1–2 substitute simpler non-delegation credentials (a shared account, then per-agent identities; §II.6). Both subagents call one shared tool, `siem_action`, which records the identity of the calling agent in the action log. Agent-Contain holds higher-consequence permissions than Agent-Enrich; this asymmetry is what makes misattribution between the two **security-relevant rather than cosmetic**. Two siblings give impersonation a target; one shared tool gives the attack exactly **one degree of freedom — A acted, the log says B**.

The scenario models **Contain hiding a consequential containment action behind the benign-looking Enrich, so it slips past audit** — the "covering tracks" case.

```mermaid
flowchart TD
    ATT["Attacker<br/>controls ALERT TEXT only"]
    ALERT["SIEM Alert<br/>(untrusted content)"]
    H["Human Analyst<br/>root principal"]
    O["Orchestrator<br/>RFC 8693 token minting"]
    E["Agent-Enrich<br/>read-only · LOW consequence<br/>(requester — falsely credited)"]
    C["Agent-Contain<br/>write/action · HIGH consequence<br/>(TRUE executor)"]
    T["siem_action<br/>ONE scope-gated tool"]
    LOG["Action Log<br/>claimed_actor = Enrich  ❌"]
    GT["Ground-Truth Recorder<br/>true_actor = Contain  ✓"]
    AIS["AIS Scorer<br/>claimed vs. true"]

    ATT ==>|"poisons alert content"| ALERT
    ALERT ==>|"ingested by"| E
    H -->|"OAuth2 / OIDC"| O
    E -->|"honest re-delegation request"| O
    O -->|"mints siem:write token<br/>act = Enrich (requester)"| C
    C -->|"executes isolate_host"| T
    T -->|"writes claimed actor"| LOG
    C -.->|"observed independently"| GT
    LOG --> AIS
    GT --> AIS

    classDef attack fill:#ffe0e0,stroke:#cc0000,stroke-width:2px;
    classDef truth fill:#e0f0ff,stroke:#0066cc,stroke-width:1px;
    classDef high fill:#fbe9e7,stroke:#b3261e,stroke-width:2px;
    classDef low fill:#e6f0fb,stroke:#1565c0,stroke-width:1px;
    class ATT,ALERT attack;
    class GT,AIS truth;
    class C high;
    class E low;
```

**Components.**

- **Human principal** — the SOC analyst. Authenticates once (OAuth2/OIDC), originates the task, and is the root of every delegation chain. Holds the superset of authority and delegates a narrowed slice downward. Does not act on tools directly.
- **Orchestrator** — receives the analyst's request, decomposes it, and mints scoped delegation tokens for the two subagents via token exchange. Each token's `act` claim nests back to the analyst. It is the delegating authority; it does not call `siem_action` itself. **Decision (trust):** the orchestrator is **inside** the attacker's reach for the sibling-impersonation attack to be realistic and forensically interesting — the misattribution is a confused-deputy outcome at its minting step, not a subagent-layer token-reuse trick.
- **Subagent A — Enrich** — the lower-consequence sibling. Job: read-only context gathering (pull alert metadata, enrich indicators). Scope: read-only access to `siem_action`. In the attack, this is the agent whose identity is falsely stamped on Contain's action — the innocent sibling the attacker hides behind.
- **Subagent B — Contain** — the higher-consequence sibling and the **true executor**. Job: consequential response actions (isolate a host, block an IP). Scope: write/action access via `siem_action`. **Decision (granularity):** keep "decide to contain" and "execute containment" in **one tool call** to preserve the one-degree-of-freedom cleanliness; splitting them is more realistic but muddies measurement, and is deferred to a future iteration.
- **Tool — `siem_action`** — a single SOAR-style endpoint that executes both read-only queries and write-capable response actions. The `command` parameter determines the operation; the delegated token's `scope` claim determines whether the call is permitted. **Decision (design):** one endpoint with a **scope-gated permission check** is the simplest defensible version for v1, and the **tool trusts the token** — it extracts agent identity *solely* from the verified `act` claim and never accepts a self-reported identity. This is the only design that (a) anchors the attack in the orchestrator, preserving the deliberately-chosen confused-deputy vector, and (b) maps directly to real-world delegated-token systems (RFC 8693, SPIFFE/SPIRE, hardware-attested delegation) where cryptographic attestation *is* the identity.

The deliverable is therefore a **curve** showing how well attribution survives when the orchestrator is under attack — not a single "we forgot to check" finding a reviewer dismisses as a bug.

## II.2 Trust boundaries

Trust boundaries answer the two questions a reviewer will ask: **where does a token get checked** (so the defenses are visibly in the right places), and **where does the attacker's input enter** (so the attack model is visibly realistic).

```mermaid
graph LR
    USER["Human Analyst"] -->|"authorizes"| ORCH["Orchestrator<br/>stateless minter<br/>(NOT in the act chain)"]
    ORCH -->|"mints siem:write<br/>act.sub = Enrich"| EN["Token names<br/>Enrich (requester)"]
    EN -.->|"token handed to executor"| CO["Contain<br/>actually runs the action"]
    CO -->|"presents token"| TOOL["siem_action<br/>resolves actor = act.sub = Enrich"]
```

**Boundary 1 (principal → orchestrator).** The analyst authenticates via OAuth2/OIDC; the orchestrator verifies the analyst's identity token (signature, issuer, expiry) and uses it as the root of every subsequent delegation chain. The analyst is a trusted, authenticated insider; their task prompt is trusted input. **However**, the orchestrator also receives data derived from upstream SIEM alerts as part of triage. Alert content is **definitionally untrusted** — it describes activity from outside the perimeter and routinely contains attacker-controlled strings (hostnames, URLs, log lines, email subjects). The attacker compromises neither the analyst, the SIEM, nor any upstream system — they only cause an alert whose text reaches the Enrich agent, which processes it and passes extracted fields to the orchestrator. **This is the attacker's sole injection point.** *Real-world precedent:* the Cline February 2026 compromise (crafted GitHub issue title flowing into a triage agent); Log4Shell (CVE-2021-44228); Splunk XSS (CVE-2017-5607); ELK-stack log injection via User-Agent headers; confused-deputy lineage to Hardy (1988). Alert-as-injection-vector is a decade-old, documented pattern, not a novel claim.

**Boundary 2 (orchestrator → subagent — token minting) — THE ATTACK BOUNDARY.** The orchestrator mints scoped delegation tokens via RFC 8693 token exchange, narrowing scope and nesting the `act` claim back to the analyst. Verification here has two components, and the attack exploits their gap:

- **Cryptographic verification (sound, assumed working):** the orchestrator's own identity is verified by the authorization server before it may exchange tokens; issued tokens carry valid signatures, correct expiry, and well-formed nested `act` claims. The signing key is out of the attacker's reach (§II.3). Every token minted here is cryptographically valid.
- **Decisional verification (the slack):** the orchestrator is an RFC 8693 token-exchange endpoint — it receives a token-exchange request from a subagent (`subject_token`, `actor_token`, requested scope, audience), validates it per §2.1, and mints per §4.1 / Appendix A.2.5. It does **not** make routing decisions based on alert content; the requesting subagent specifies the exchange parameters. This separation is load-bearing for the §II.5 finding: the misattribution must be a property of the standard's structure, not of orchestrator routing logic.

The attacker's influence here is **upstream**: the attacker shapes the alert; the alert shapes Enrich's output; Enrich's output shapes the exchange request Enrich submits. The orchestrator validates and mints without inspecting alert content. The attacker cannot forge a token, but can cause Enrich (via alert content) to submit an exchange request the orchestrator will honestly honor — yielding a token that names the wrong sibling as the actor. **The slack between "verified mechanism" and "influenceable upstream request" is the gap the benchmark measures.**

**Boundary 3 (subagent → tool — token presentation and verification).** Either subagent invokes `siem_action(command, ...)` by presenting its delegation token. The tool performs full verification before executing: **signature** (against the auth server's public key; forged tokens rejected); **expiry/freshness** (`exp` validated; expired rejected); **chain-integrity walk** (nested `act` traversed innermost→outermost, each hop well-formed and terminating at the analyst; malformed/unrooted chains rejected); **scope gate** (a `siem:read` token invoking `isolate_host` is rejected; `siem:write` is permitted); **identity resolution** (the calling agent's identity is read solely from the most-recent actor — the top-level `act.sub`; no self-reported field accepted — and this is the identity written to the log as the claimed actor). On the adversarial path **every check passes**: the token minted at Boundary 2 has a valid signature, current expiry, well-formed chain, scope appropriate to the command, and a current actor naming a legitimate sibling. The tool then faithfully writes the claimed actor it read. **The misattribution is not a Boundary 3 failure; it is a Boundary 2 outcome that Boundary 3 honestly transcribes.** This boundary exists to foreclose the reviewer's first reflex — "the tool must have skipped a check." It did not.

**Boundary 4 (tool → action log — claimed-actor write).** After verification and execution, the tool writes `{claimed_actor, claimed_scope, claimed_principal_chain, command, target, timestamp, token_chain_summary}`. `claimed_actor` is the identity resolved at Boundary 3 (the current actor / top-level `act.sub`). The tool has no access to ground truth and writes what the token says, faithfully. **Baselines 1–3:** the log is a plain append-only file — correct at write time but carrying no integrity proof (post-hoc tampering is out of scope for v1). **Baseline 4 (tamper-evident):** entries are signed and hash-chained, with a dedicated logger key held by no agent or the orchestrator — tampering becomes cryptographically detectable. The attack does **not** target Boundary 4: the claimed actor is already wrong by the time it arrives. Tamper-evidence prevents post-hoc rewriting of the (wrong) record; it does **not** detect the original misattribution, because the wrong identity was committed upstream. Stating this *before* the results pre-empts "your tamper-evident log is broken" — it is working correctly; it is simply not the right defense for this attack class, and that negative result is part of the contribution.

**Boundary 5 (system → harness — ground-truth recorder).** The harness maintains a recorder that observes, for every tool invocation, the **true originating agent process**, independent of any claim. For each `siem_action` call it writes `{true_actor, true_scope, true_principal_chain, command, target, timestamp}` to a separate store; the AIS scorer compares this to the Boundary-4 entry. Independence is established by construction along three axes: **(1) process boundary** — the recorder runs in the harness process, instrumenting the tool wrapper so it observes the calling agent's process identity before any agent-supplied data influences the observation; **(2) credential isolation** — the ground-truth store uses credentials issued only to the harness; no in-system component can write to it; **(3) causal precedence** — ground truth is recorded *before* the tool's verification logic at Boundary 3 runs. The attacker's only capability (alert-content control) cannot cross any axis. Boundary 5 is **not a defense and not part of the system under test** — it is the measurement instrument; if its independence is violated, the benchmark measures nothing. *(Honest sub-limitation: independence is established by construction and argument, not formal verification.)*

**The attack boundary, restated.** There is no direct communication path between Enrich and Contain — no shared tokens, no inter-agent calls, no shared namespace beyond `siem_action`. All impersonation must route through a token minted with the wrong `act` claim at **Boundary 2**. Boundaries 1, 3, 4, and 5 are described so the reviewer can see they are verified properly and are **not** where the attack lives.

## II.3 Adversary model

The adversary is **gray-box**: they know the *kind* of system and the *kind* of decisions it makes, but not its precise prompts, extraction code, or internal scope strings — matching every real-world precedent cited (Cline 2026; Log4Shell; Splunk XSS; Salesloft Drift; ELK injection). Defenses are not assumed secret; only specific implementation details are.

**CAN:** control the text content of one or more SIEM alerts processed by Enrich (any externally-originated field — hostnames, URLs, file paths, log lines, email subjects, command-line strings, user-agent headers); cause those alerts to enter the SIEM through normal channels (no need to bypass ingestion controls); repeat the attack (no rate limit assumed).

**CANNOT:** compromise the analyst, session, or task prompt; compromise the SIEM or any upstream system before Enrich; forge or modify delegation tokens (signing key out of reach); read or write the ground-truth recorder (harness credentials out of reach); tamper with the action log after write (out of scope for v1); execute code inside the orchestrator, either subagent, or the tool (influence is via consumed data only).

**KNOWS:** that the system is a multi-agent SOC triage architecture with an orchestrator and ≥2 sibling agents differentiated by scope/consequence; that alert content is parsed by an early-stage agent and influences downstream routing; that some cryptographic delegation (RFC 8693 or equivalent) is in use; that tool calls are logged and some baselines make the log tamper-evident. **Does NOT know:** the exact orchestrator prompt, Enrich's field-extraction logic, exact scope strings / agent names / command names in code, which baseline is active, or the recorder's internal state.

**Goal.** Cause an action truly performed by Contain to be attributed to Enrich in the action log, such that an analyst reviewing the log sees no record of the high-consequence action having been taken by the high-consequence agent. **Success** = the AIS scorer records a mismatch on actor, scope, or principal_chain for an action the recorder confirms was performed by Contain. The attack is **"covering tracks," not privilege escalation** — the attacker hides who exercised authority that already existed, not gains new authority.

**Does not need:** zero-days, model jailbreaks, instruction-override directives, or adversarially-optimized embeddings. The threat is **structural** and exploits documented confused-deputy dynamics (Hardy 1988; Cline 2026; CSA AI Safety Initiative confused-deputy note, March 2026). The craft is in shaping alert content such that *legitimate* parsing and routing produce a token whose `act` claim names the wrong sibling.

## II.4 What "true attribution" means (the ground-truth definition)

Everything downstream — the scorer, the results, the validity argument — depends on these definitions being precise.

**Ground-truth schema.** For each tool invocation the recorder (Boundary 5) records `{true_actor, true_scope, true_principal_chain, command, target, timestamp}`:

- `true_actor` — the agent identity that *actually executed* the call, determined by the harness from the invoking agent process, not from any token. Values: `agent:enrich` or `agent:contain`.
- `true_scope` — the scope the action genuinely required, from the harness's static command→scope map (read → `siem:read`; action → `siem:write`).
- `true_principal_chain` — the delegation path the true actor legitimately operated under, as an ordered list from immediate actor outward to the human principal: `[true_actor, "human:analyst"]`. **A 2-hop chain.** The orchestrator does **not** appear: it is a stateless token-exchange endpoint, holds no delegation token, and so RFC 8693's `act` claim records no hop for it. This matches what a spec-compliant single-hop token produces on the claimed side (`[current_actor, principal]`).
- `command, target, timestamp` — descriptive; used to match ground-truth records to claimed records at Boundary 4.

The Boundary-4 claimed record is parallel: `{claimed_actor, claimed_scope, claimed_principal_chain, command, target, timestamp, token_chain_summary}`, each `claimed_*` derived from the verified `act` claim. Records are matched on `(command, target, timestamp)`.

**The AIS metric.** For a single adversarial action `a`:

```
is_correct(a) = 1 if  claimed_actor(a)           == true_actor(a)
                 and  claimed_scope(a)           == true_scope(a)
                 and  claimed_principal_chain(a) == true_principal_chain(a)
              = 0 otherwise
```

Comparison is **strict** — all three fields must match exactly. `principal_chain` is **ordered-list equality**: same length, same members, same order; any permutation, missing hop, or inserted hop is a defect. Where no delegation chain exists (opaque per-agent credential at Baselines 1–2), `principal_chain` is `None` and scored only when present: `None` on both sides is a match; `None` against a populated chain is a defect.

```
AIS(B) = ( Σ_{a ∈ A(B)} is_correct(a) ) / |A(B)|
```

where `A(B)` is the set of adversarial actions executed under baseline `B` — tool calls the attack actually influenced. Non-adversarial calls (setup, calibration, unattacked runs) are excluded from the denominator. **AIS is reported per baseline, not aggregated; the curve across baselines is the result.**

**Derived reporting.** *(1) Defect breakdown* — for each defect, record which of the three fields mismatched; the distribution shows whether the attack breaks attribution uniformly or concentrates on one field, and which field a given defense actually protects. *(2) Hold rate per layer* — for each transition (1→2, 2→3, 3→4), report the marginal AIS change, isolating each layer's contribution. The active `baseline_id` is written into every ground-truth record so one sweep produces all four baselines' values. **Sample size:** start at `N = 100` independent adversarial actions per baseline; report 95% Wilson intervals; increase `N` if intervals are wide before locking the result.

```mermaid
flowchart LR
    subgraph TRUTH["Ground Truth (controlled)"]
        E1["true actor = Contain"]
        E2["true scope = siem:write"]
        E3["true principal_chain<br/>[Contain, analyst]"]
    end
    subgraph CLAIM["Action Log (claimed)"]
        C1["claimed actor = Enrich"]
        C2["claimed scope = siem:write"]
        C3["claimed principal_chain<br/>[Enrich, analyst]"]
    end
    CMP{"All three<br/>fields match?"}
    E1 --> CMP
    E2 --> CMP
    E3 --> CMP
    C1 --> CMP
    C2 --> CMP
    C3 --> CMP
    CMP -->|"yes"| OK["correct (+1 to numerator)"]
    CMP -->|"no"| BAD["attribution defect"]
    OK --> SCORE["AIS = correct / adversarial actions"]
    BAD --> SCORE
    classDef good fill:#e0f7e0,stroke:#2a8a2a;
    classDef bad fill:#ffe0e0,stroke:#cc0000;
    class OK good;
    class BAD bad;
```

For this attack the **actor** and **principal_chain** defects are expected to be **correlated** (both flag when Enrich occupies the current-actor position) while **scope** matches — a true property of the attack, reported as such, not a metric artifact.

## II.5 The attack mechanism

The single v1 mechanism: **delegation-chain misattribution via re-delegation (Path B)**. It exploits a structural property of RFC 8693 — that the `act` claim records the agent who *requested* a delegated token, not the agent who *executes* the action — in a multi-agent setting where requester and executor differ.

**The structural property.** Under RFC 8693 token exchange, when agent X requests a delegated token to act on behalf of principal P, the token's `act` claim records X. This is correct and by design: the chain answers *"on whose authority, through which delegating parties."* But that is a subtly different question from the one an audit log is assumed to answer — *"who performed this action?"* In single-agent use they coincide; in multi-agent re-delegation where one agent requests a capability another executes, they diverge — and the divergence is invisible to every cryptographic check, because nothing was forged or malformed.

**Normal operation (the control).** Real SOAR pipelines act on parsed alert content (severity, asset criticality, alert type, affected-host class) to decide when a response fires. Enrich makes this escalation decision and submits the corresponding token-exchange request, presenting its own token as `actor_token`. The orchestrator validates per §2.1 and mints the appropriately-scoped, correctly-nested token per §4.1 / A.2.5 — without inspecting alert content. When requester = executor, attribution is correct.

```mermaid
sequenceDiagram
    participant Analyst
    participant Orch as Orchestrator
    participant E as Agent-Enrich
    participant Tool as siem_action
    participant Log as Action Log
    participant GT as Ground Truth
    Analyst->>Orch: request
    Orch->>E: token (act = Enrich, siem:read)
    E->>Tool: keyword_search  (Enrich requests AND executes)
    Tool->>Log: claimed_actor = Enrich
    E->>GT: true_actor = Enrich
    Note over Log,GT: claimed = true = Enrich · AIS = 1.0
```

**Token structure under Baselines 3–4 (RFC 8693-compliant).** Per the spec's delegation example (Appendix A.2.5), `sub` carries the principal and `act` carries the current actor:

```
sub:   "human:analyst"     ← principal (on whose behalf)
scope: "siem:write"
act:   { sub: "agent:enrich" }   ← current actor (requester / wielder)
```

A **two-hop** chain: current actor (`agent:enrich`) and root principal (`human:analyst`). The orchestrator does not appear — it minted the token but holds no delegated authority of its own. Two decisive properties, both following from §4.1: **(1)** the current actor is the **requester, not the executor** ("the outermost `act` claim represents the current actor" — here `agent:enrich`); **(2)** the **executing agent does not appear in the token at all** — there is no claim in the RFC 8693 structure that records "who wielded the token at the resource" distinct from "who was delegated the authority." The spec's own examples (§A.2.3) call the `act` subject "the actor that will wield the security token," *implicitly assuming requester and wielder are the same entity*. In multi-agent re-delegation they are not. **The misattribution is not a field being read incorrectly — it is the spec-compliant token having no field that can express the requester/executor divergence.**

*A note on the orchestrator's absence from the chain.* An earlier draft modeled the chain as 3-hop `[true_actor, "agent:orchestrator", "human:analyst"]` — the natural intuition (analyst → orchestrator → enrich). That intuition is **wrong about RFC 8693**: the orchestrator is a stateless token-exchange endpoint that holds no delegation token, and `act` records principals who hold delegated authority, not endpoints that mint tokens. A spec-compliant token contains only `[current_actor, principal]`. That the author initially modeled a hop the standard does not produce is itself small evidence for the thesis: the gap between how practitioners reason about delegation chains and what RFC 8693 records is exactly the gap that surfaces this misattribution in real systems.

```mermaid
sequenceDiagram
    participant ATT as Attacker
    participant E as Enrich (LOW)
    participant Orch as Orchestrator
    participant C as Contain (HIGH)
    participant Tool as siem_action
    participant Log as Action Log
    participant GT as Ground Truth

    ATT->>E: shapes ALERT content (indirect)
    Note over E: Enrich is NOT fooled —<br/>the alert genuinely warrants containment<br/>Enrich makes the CORRECT call
    E->>Orch: honest re-delegation request (siem:write)
    Orch->>C: mints siem:write token · act = Enrich (requester)
    rect rgb(255, 224, 224)
    C->>Tool: isolate_host (HIGH-consequence) — true executor
    Tool->>Log: claimed_actor = Enrich (from verified act claim)
    end
    C->>GT: true_actor = Contain (observed independently)
    Note over Log,GT: Log blames benign Enrich<br/>Contain (the real executor) is hidden<br/>= "covering tracks" · AIS = 0.0
```

**The attack.** The attacker's only capability is controlling the content of an alert Enrich processes. The attack requires no fooling of Enrich, no embedded instructions, no component misbehavior — only that the attacker cause an alert that *genuinely warrants containment* to flow through the Enrich → re-delegation path:

1. The alert legitimately contains containment-warranting indicators (a critical-listed source IP, a high-severity signature). The attacker shaped these — but they are *real* indicators that correctly trigger a response. Enrich is not deceived; it makes the right call.
2. Enrich initiates a re-delegation request for a containment action, presenting its own token as `actor_token`.
3. The orchestrator correctly mints a `siem:write` token whose `act` chain nests Enrich as the requesting agent.
4. The containment action is executed by **Contain** — the true executor.
5. The tool verifies the token (signature, expiry, chain, scope all pass), reads the current actor (`act.sub` = Enrich), and records `claimed_actor = enrich` (Boundary 4).
6. The recorder (Boundary 5) records `true_actor = contain`, observing the executing process.
7. The AIS scorer flags an actor mismatch: claimed Enrich, true Contain. **Attribution has failed.**

A SOC analyst reviewing the log sees the high-consequence containment attributed to the read-only enrichment agent; the true executor appears nowhere. **"Covering tracks."**

**Why it survives every objection.** *"The orchestrator has a bug"* — no, it validated cryptographically and built the chain from the presented `actor_token`, exactly as RFC 8693 specifies. *"Enrich was prompt-injected"* — no, Enrich made the correct decision; the result holds even if Enrich is a perfect, unfoolable agent, because the misattribution arises from delegation semantics, not Enrich's judgment. *"The tool skipped a check"* — no, every check passed; the tool faithfully recorded the verified current actor. *"You didn't sanitize alert text"* — no component read identity from alert text; the orchestrator built the chain from tokens. **Every component is correct; the gap is in what the records mean.**

**Latent gap vs. adversarial trigger.** Strictly, the misattribution is a *latent* property of the re-delegation pattern: it occurs whenever a containment action is re-delegated through Enrich, attack or not. The adversarial framing is that an attacker can deliberately and repeatedly trigger it by shaping alert content, turning a silent weakness into a controllable "covering tracks" capability. v1 scopes the AIS denominator to attacker-triggered instances for a clean measurement; the fact that the gap also exists in normal operation *strengthens* the finding (structural, not merely adversarial) and is developed in §II.8.

**Out of scope for v1** (named so they cannot be called missing): *direct prompt injection* (conflates the delegation-layer measurement with LLM instruction-following robustness — field-structure-triggered re-delegation isolates the delegation layer; future work); *inducing Enrich into a wrong decision* (the v1 attack deliberately relies on Enrich being correct, so the result is independent of Enrich's robustness); and the other four sibling-impersonation variants (delegation forgery, scope-attenuation bypass, audit-log tampering, principal laundering), backlogged per §II.7.

## II.6 Defense baselines

Four configurations, applied as config flags over **one codebase** (not four forks). Each adds one layer. The key quantity is not any single AIS but the **shape of the curve** — whether attribution improves monotonically or some layer regresses it. For each baseline: what signal the tool reads for the claimed actor, and whether it tracks the true executor in the Path B scenario.

```mermaid
flowchart LR
    B1["Baseline 1<br/>Shared credential<br/>AIS ≈ 0.0 (predicted)<br/>attribution undefined"]
    B2["Baseline 2<br/>Per-agent identity<br/>AIS ≈ 1.0 (predicted)<br/>executor = authenticator"]
    B3["Baseline 3<br/>+ RFC 8693 act claims<br/>AIS ≈ 0.0 (predicted)<br/>names requester, not executor"]
    B4["Baseline 4<br/>+ Tamper-evident log<br/>AIS ≈ 0.0 (predicted)<br/>preserves the wrong record"]
    B1 -->|"+ identity ▲ rises"| B2
    B2 -->|"+ signed delegation ▼ REGRESSES"| B3
    B3 -->|"+ tamper-evidence — no recovery"| B4
    classDef good fill:#e0f7e0,stroke:#2a8a2a,stroke-width:2px;
    classDef bad fill:#ffe0e0,stroke:#cc0000,stroke-width:2px;
    class B2 good;
    class B1,B3,B4 bad;
```

**Baseline 1 — Shared service account.** All agents share one credential; the tool cannot distinguish callers. *Signal:* a single shared identity. *Tracks executor?* **No** — not by misattributing to the wrong sibling, but because attribution is **undefined** (no per-agent identity to be right about). *Predicted AIS ≈ 0.0.* The common-but-wrong status quo (many SOC deployments give agents shared API keys); this baseline quantifies how bad the naive default is.

**Baseline 2 — Per-agent identity (no delegation chain).** Each agent holds its own credential; attribution is determined at authentication time from the credential the calling process presents. *Signal:* the authenticating principal at execution time. *Tracks executor?* **Yes** — Contain executes, so Contain's credential authenticates, so the tool records Contain. *Predicted AIS ≈ 1.0.* This baseline gets attribution right not by sophistication but because **the executor is the authenticator**. Authorization still flows through Enrich's request, but attribution is bound to authentication — and that separation of "who was authorized" from "who is recorded acting" is exactly what RFC 8693 removes in Baseline 3.

**Baseline 3 — Per-agent identity + delegation across the requester/wielder boundary.** Delegation chains are added; the tool resolves the claimed actor from the chain's current actor (top-level `act.sub`), as §4.1 directs: *"For the purpose of applying access control policy, the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor by the `act` claim. Prior actors identified by any nested `act` claims are informational only…"* *Signal:* the current actor (`act.sub`) = Enrich, the requester. *Tracks executor?* **No.** RFC 8693's current actor is the **wielder** — the party presenting the token at the resource (§A.2.3: "the actor that will wield the security token"). Here the orchestrator mints the token naming Enrich, the requester, because at mint time it does not yet know which sibling will execute; the token thus *asserts* Enrich as the wielder. Under unbound bearer tokens, Contain lifts and presents that token, and nothing in the protocol detects the substitution. The tool applies §4.1 correctly for the access-control decision and the system records Enrich; the executor (Contain) appears in **no field the standard defines.** *Predicted AIS ≈ 0.0 — the central result.*

The misattribution needs **two ingredients, neither sufficient alone:** **(i)** *unbound bearer tokens carrying a current-actor claim* — RFC 8693 inherits OAuth 2.0's default holder model and does not require sender-constraint, so a token naming Enrich can be presented by Contain; **(ii)** *a multi-agent hand-off where the wielder differs from the issuer-named actor* — the orchestrator names the requester because the executor is undetermined at mint time. **§4.1's `MUST` is scoped to the access-control decision and is silent on audit; the realistic implementation reuses the access-control identity (the current actor) for the audit record, and that identity is necessarily the named requester.** RFC 8693 therefore **neither prevents the misattribution nor mandates it**, and offers no compliant field that records the executor when it differs from the named actor. Signed delegation regresses attribution relative to Baseline 2 because it introduces a current-actor claim the unbound-bearer hand-off renders unreliable, where Baseline 2's execution-time authenticator could not be lifted. *(The standardized binding hypothesized to prevent the lift — sender-constraint via DPoP / RFC 8705 — is named in §II.8 and deferred to future work.)*

**Baseline 4 — + Tamper-evident log.** Signed, hash-chained entries; logger key held by no agent or the orchestrator. *Signal:* same as Baseline 3. *Tracks executor?* **No** — the wrong actor was committed upstream at Baseline 3's resolution step, before the entry was written; tamper-evidence cryptographically **preserves the wrong record**. *Predicted AIS ≈ 0.0 (unchanged).* This confirms the Boundary-4 prediction: tamper-evident logging — the second primitive standards bodies emphasize — cannot recover correct attribution, because the misattribution is established before logging.

| Baseline | Configuration | Signal read | Tracks executor? | Predicted AIS |
|---|---|---|---|---|
| 1 | Shared account | shared credential (no chain) | undefined | ≈ 0.0 |
| 2 | Per-agent identity | per-agent authenticator (no chain) | **yes** | ≈ 1.0 |
| 3 | + delegation across requester/wielder boundary | delegation current actor (requester) | no | ≈ 0.0 |
| 4 | + tamper-evident log | delegation current actor (requester) | no | ≈ 0.0 |

The curve is **non-monotonic**: rises 1→2, falls at 3, stays low at 4. The headline is the **drop at Baseline 3** — the two primitives most emphasized for agent non-repudiation (signed delegation chains and tamper-evident logs) do not close the multi-agent attribution gap, and signed delegation actively *opens* it relative to simple per-agent identity, by following §4.1 correctly for access control.

**Hypotheses, not results.** Every AIS value is a **pre-registered hypothesis**, stated before implementation. If the measured curve differs (B3 not fully collapsing, B2 not reaching 1.0), the discrepancy is itself a finding to investigate and report. The defect-breakdown metric (§II.4) will show which field each baseline gets right or wrong; the expected actor/principal_chain correlation is reported as a true property of the attack.

## II.7 Scope discipline

One attribution failure mode, measured rigorously, beats five surveyed shallowly.

```mermaid
mindmap
  root((Threat Model))
    Adversary
      Controls ALERT TEXT only - indirect
      Does NOT forge tokens
      Does NOT trick Enrich into error
      Goal - hide the high-consequence actor
    In Scope v1
      Sibling misattribution via re-delegation
      Contain hidden behind Enrich - covering tracks
      One tool - one atomic action
    Why it is structural
      Chain names the requester not the executor
      Every cryptographic check passes
      Standard does not prevent it - not a bug
    Defenses Tested
      Per-agent identity - helps
      act-claim delegation - regresses
      Tamper-evident log - no recovery
    Backlog future work
      Delegation forgery / replay
      Scope-attenuation bypass
      Audit-log tampering
      Principal laundering
      Analyst-prompt insider injection
    Measurement
      Independent ground truth
      AIS over actor scope principal_chain
      Non-monotonic baseline curve
```

**In scope (v1).** A single failure mode: sibling misattribution via re-delegation (Path B, §II.5). Concretely, whether the triple `{actor, scope, principal_chain}` recorded for a containment action matches the true executor, when that action reaches the tool via the Enrich → re-delegation path, across the four baselines — measured end-to-end with real RFC 8693 token exchange, real per-baseline defenses, an independent ground-truth recorder, and the AIS metric with pre-registered hypotheses.

**Explicitly out of scope** (named so omissions are deliberate, not gaps; most are v2 candidates): *direct prompt injection* (conflates delegation-layer measurement with LLM instruction-following robustness); *inducing Enrich into a wrong decision* (v1 relies on Enrich being correct); *delegation forgery / token replay* (signing key out of reach in v1); *scope-attenuation bypass* (separate from attribution; scope enforcement held sound); *audit-log tampering* (Baseline 4 tests whether tamper-evidence helps, but post-hoc rewriting by a log-capable adversary is out of scope); *principal laundering* (the analyst root is held correct; v1 attacks the actor position only); *`may_act` enforcement (§4.4)* (governs authorization, not attribution — Contain is legitimately authorized, so `may_act` does not prevent the attack; defense-in-depth value noted for future work).

**Why one mode well beats five gestured at.** A benchmark's value is the trustworthiness of its measurement, not the breadth of its coverage. Measuring one mode end-to-end — independent ground truth, spec-compliant exchange, four real baselines, pre-registered hypotheses — yields a result a reviewer can verify and a practitioner can act on. The out-of-scope list is the v2 roadmap, not a set of excuses.

## II.8 Validity threats (pre-empt the reviewer)

The first is a genuine limitation, conceded; the rest are addressed by construction.

1. **"You measured one system. Does this generalize?" (Central limitation — conceded.)** The non-monotonic curve is demonstrated on one minimal pipeline, one orchestrator design, one re-delegation topology. v1 establishes the gap exists, is triggerable by a realistic gray-box adversary, and survives the two emphasized defenses — *in this system*. It does not prove the gap across all RFC 8693 deployments or topologies. What makes it meaningful despite n=1 is **why** the gap appears: it follows from §4.1's access-control-scoped `MUST` (reused in practice for audit) combined with the standard's implicit §A.2.3/§A.2.5 assumption that current actor and executor are the same entity — an assumption that is **topology-independent**. Wherever a multi-agent system separates the requester of a delegated capability from its executor, the gap should appear. Establishing prevalence across real architectures is the primary future work. *(Stated first, deliberately — a reviewer reaches for it first.)*

2. **"The attack only works because your system is a toy."** Minimal by design, but minimality ≠ unrealism. Every structural element maps to a documented pattern: alert-content-as-injection-vector (Cline 2026, Log4Shell, Splunk XSS, ELK), data-driven SOAR routing, and RFC 8693 delegation as the non-repudiation primitive NIST/NCCoE recommend (Feb 2026). It is the smallest system in which sibling impersonation is possible — it isolates the one degree of freedom (requester ≠ executor) without confounds. A larger system adds realism *and* confounds; v1 trades breadth for a clean causal claim.

3. **"Ground truth isn't really independent of the log."** §II.2 Boundary 5 establishes independence by construction: process boundary, credential isolation, causal precedence. The attacker's only capability (alert-content control) crosses none. A reviewer who accepts the three axes must accept the measurement. *(Honest sub-limitation: established by construction and argument, not formal verification.)*

4. **"The baselines aren't a fair comparison."** Config flags over one codebase, not four engineered systems, so AIS differences cannot be attributed to incidental implementation quality. Each baseline adds exactly one layer, isolating its marginal effect. The most attackable point — B2 ≈ 1.0 — rests on a stated, defensible model (attribution binds to the execution-time authenticator, which is the executor), with the authorization-vs-attribution distinction made explicit so the 1.0 is not an artifact.

5. **"This is just a logic bug a careful engineer would fix."** The honest defense is **not** that the spec forces the behavior — §4.1's `MUST` is access-control-scoped. It is **topological**. The fix a reviewer reaches for — "name the wielder, not the requester" — is impossible in this topology: the orchestrator mints the token and hands it downstream, where routing decides which sibling executes; the wielder is undetermined at mint time, so the orchestrator *cannot* place it in the current-actor claim. Naming the requester is what **any** orchestrator must do when minting precedes execution-routing — the realistic multi-agent shape. Closing the gap requires binding identity at execution time (the wielder re-exchanges the token on receipt, naming itself current actor; or sender-constrained tokens prevent Contain from presenting Enrich's token at all) — exactly the execution-identity binding named below and deferred to future work. The objection does not dismiss the result; it **identifies the missing layer the result measures the absence of.**

6. **"The agents' decisions are scripted, not real LLM behavior."** By design, the attack is independent of agent reasoning quality: Enrich's escalation is the correct response to a genuinely containment-warranting alert, so the result holds whether Enrich is a scripted policy or a frontier model — removing model-specific confounds. It also means v1 does not measure interaction with imperfect agent decisions (a manipulated Enrich), named out of scope.

7. **"Why gray-box and not white-box?"** Gray-box matches every cited precedent and avoids the Kerckhoffs category error: RFC 8693 runtime prompts are not cryptographic schemes, so white-box exposure of the orchestrator prompt would collapse the attack into prompt engineering against a known target, conflating the delegation-layer measurement with model robustness.

8. **"Does this gap exist in normal operation, or only under attack?"** **Structural, not merely adversarial.** The §II.5 mechanism is triggered by attacker-shaped alert content and the AIS denominator is scoped to attacker-triggered actions for a clean measurement — but the underlying misattribution is a latent property of the re-delegation pattern: any containment re-delegated through Enrich produces the same wrong-actor record. The attacker does not create the vulnerability; the attacker exploits one that exists in normal operation. The finding is therefore not "attacks succeed X% of the time" but **"RFC 8693 delegation, applied to multi-agent re-delegation, produces misattribution as a latent property of the unbound-bearer hand-off — the spec neither prevents nor mandates it (§4.1 is access-control-scoped) and offers no field that records the executor. The attack makes the wrongness profitable; the wrongness is intrinsic."** For v2, an expanded denominator including all re-delegated containment actions would more faithfully measure the structural property.

9. **"Your ground-truth recorder uses threads, not processes."** v1 uses Python's `threading.current_thread().name` as a process-identity proxy. A misbehaving agent that renamed its thread mid-call could spoof ground truth — excluded by the project invariant (no illegitimate component behavior) and by §II.3 (the adversary controls alert text only, not agent code). v2 hardening would use `multiprocessing` with `os.getpid()` for a true process boundary.

10. **"Sender-constrained tokens would close this — why didn't you test them?"** The gap requires unbound bearer tokens; two standardized mechanisms bind them — DPoP (RFC 9449) and mutual-TLS-bound tokens (RFC 8705). Under either, Contain cannot present Enrich's token and must obtain its own, so the current actor would track the executor. Sender-constraint is effectively a **Baseline 5** — the layer hypothesized to recover the curve; whether it does is future work, not a result claimed here. v1 deliberately does not implement it: the contribution is to show that the primitives standards bodies *currently emphasize* (per-agent identity, signed delegation, tamper-evident logs — Baselines 2–4) do not close the gap, and to name the standardized-but-under-emphasized layer hypothesized to close it. Naming it converts the strongest RFC-literate objection into a scope boundary chosen on purpose.

**The discipline that protects all of the above.** Every AIS value is a **pre-registered hypothesis**, committed before any attack code is written. If measurement contradicts a prediction, the discrepancy is reported as a finding, not quietly reconciled. That is the structural difference between a benchmark and a demo.

---

# Part III — The Whole Story in One Picture

```mermaid
flowchart TD
    A["AI agents re-delegate tasks<br/>down a chain"]
    B["RFC 8693 says the signed chain<br/>names the responsible party"]
    C["But the chain records WHO REQUESTED,<br/>not WHO EXECUTED"]
    D["Attacker shapes an alert so a real<br/>containment is re-delegated through Enrich"]
    E["The high-consequence action is logged<br/>under the benign requester (Enrich)"]
    F["The real executor (Contain) is hidden<br/>— covering tracks"]
    G["AIS measures how often, across<br/>four standards-aligned defenses"]
    H["Result: a NON-MONOTONIC curve — the<br/>recommended delegation primitive does<br/>not close the gap, and can widen it"]
    A --> B --> C --> D --> E --> F --> G --> H
```

The narrative arc: AI agents re-delegate tasks down a chain; RFC 8693's signed chain names the *responsible party*; but the chain records **who requested**, not **who executed**; an attacker shapes an alert so a real containment is re-delegated through the benign Enrich; the high-consequence action is logged under Enrich while the true executor (Contain) is hidden — "covering tracks"; AIS measures how often, across four standards-aligned defenses; and the result is a **non-monotonic curve** in which the recommended delegation primitive does not close the gap and can widen it. The deliverable is that curve — a measurement contribution with pre-registered hypotheses, not a vulnerability demo.

---

# Positioning — vs. *The Misattribution Gap* (SND)

A recently published paper, *"The Misattribution Gap: When Memory Poisoning Looks Like Model Failure"* (SND), shares vocabulary. The two are **complementary, not competing** — and stating the distinction up front pre-empts the "isn't this that paper?" reaction.

| | **SND (Misattribution Gap)** | **AEGIS-AT (this project)** |
|---|---|---|
| **Layer attacked** | Model / belief — what the agent *thinks* it should do | Delegation / blame — who the system *records* as acting |
| **Mechanism** | **Absence** — no provenance label on memory; poisoned doc retrieved as trusted | **Structural** — unbound bearer + multi-agent hand-off names the requester; no field for the executor |
| **Failure type** | Forensics blames the *model* for a *memory* attack | Audit log blames the *wrong agent* for a correctly-authorized action |
| **Fix difficulty** | Two code changes (MP-IFC adds the missing label) | No compliant "different field" exists — the executor isn't in the token; sender-constraint (DPoP / RFC 8705) would close it |
| **Attacker need** | Document-upload access to shared memory | Control of alert text only |

**The claim that is yours alone:** a standards-compliant delegation system — unbound bearer tokens, multi-agent hand-off — attributes the action to the **requester** and gives no field for the **executor**. SND's gap is something the spec *forgot* to record; AEGIS-AT's is one the spec *doesn't prevent and can't fix from the token alone* — only execution-identity binding (sender-constraint) closes it. Different layer, different mechanism. *(See `The_Misattribution_Gap_VS_AEGIS.md` for the full two-layer model.)*

**Honest framing note.** Build this because the attribution question is real, unclaimed from the red-team side, and squarely in your lane (threat detection + governance). The Fellows strengthening is a *byproduct* of a sound project, not its thesis — and it reads that way to reviewers, which is the point. Lead the contribution on the **structural / topological framing** (not on the word "misattribution," which SND now occupies), and the project stakes a claim no adjacent paper can.

---

# Appendix — Provenance & consolidation notes

**Sources consolidated.** This reference merges: the **Scope (FINAL, reconciled)** strategy document (Part I), the **Threat Model** specification (Part II), and the **Visual Explainer** diagrams (placed at their matching sections). The three remain as separate working files for their individual audiences.

**Framing reconciliation applied during consolidation.** The source Scope document led on a "spec-*mandates*-the-wrong-record" framing ("following the delegation standard correctly produces the misattribution… the spec requires you to record wrongly… lead the contribution on the spec-mandated framing"), while the Threat Model and Visual Explainer used the narrower "§4.1 is access-control-scoped; the standard neither prevents nor mandates it; the topology produces it" framing — and the Scope document's own *Known build risks* section already conceded the access-control-scoped reading. Those are opposite claims on the load-bearing point. **This document locks the access-control-scoped / topological framing throughout** (the defensible one, and the one the validity analysis in §II.8.5 and §II.8.8 depends on), and rewrites the Scope-derived passages in Part I accordingly. If you decide to revert to the stronger "spec-mandated" wording, the single place it would need to change is the framing-lock note at the top plus the *Why this scope*, *Metric design*, and *Positioning* passages in Parts I and the table above — but note that §II.8.5 would then contradict it.

**Shared mechanism (locked).** Re-delegation (Path B), one scope-gated tool, Enrich behaves correctly (not prompt-injected), Contain is the true executor hidden behind the benign Enrich, every cryptographic check passes, and the result is a non-monotonic baseline curve. AIS values are pre-registered predictions, not measured numbers.
