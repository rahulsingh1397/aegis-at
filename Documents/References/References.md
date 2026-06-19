# References

A curated list of primary and supplementary references related to AI agent security, attribution, and non-repudiation.

---

## Primary References

### 1. "The Misattribution Gap"

- **Status:** Verified
- **Authors:** Tanzim Ahad, Ismail Hossain, Md Jahangir Alam, Sai Puppala, Syed Bahauddin Alam, Sajedul Talukder
- **Full Title:** *The Misattribution Gap: When Memory Poisoning Looks Like Model Failure in Agentic AI Systems*
- **Publication Date:** May 2026
- **arXiv:** [https://arxiv.org/abs/2605.22842](https://arxiv.org/abs/2605.22842)

**Core Finding:** Across 64 documented failures, attribution systems consistently blamed the model, not the memory layer. Four safety classifiers produced zero detections across 510 checkpoints. In 59 of 65 valid cases, agents explicitly cited the injected document as normative authority before complying.

**Mechanism:** Semantic Norm Drift (SND), where a policy-formatted document enters a shared vector store and re-emerges as trusted system context after provenance is lost through a Trust Laundering Chain.

**Relevance:** Directly describes the dynamic where adversarial actions are systematically misattributed to the model, not the attacker.

---

### 2. Cline MCP Compromise (February 2026)

- **Status:** Verified
- **Type:** Supply Chain Attack / Real Incident
- **Disclosure Date:** February 9, 2026, by security researcher Adnan Khan (dubbed "Clinejection")
- **Exploit Date:** February 17, 2026

**Details:** An unauthorized package `cline@2.3.0` was published to npm, distributing the OpenClaw AI agent onto approximately 4,000 developer machines during an 8-hour window.

**Mechanism:** Indirect prompt injection via a crafted GitHub issue title, exploiting a GitHub Actions workflow where an AI agent (Claude) with excessive permissions was tricked into executing arbitrary code.

**Sources:**
- [Primary technical analysis (grith.ai, archived)](https://web.archive.org/web/20260410192247/https://grith.ai/blog/clinejection-when-your-ai-tool-installs-another)
- [Snyk writeup ("Clinejection")](https://snyk.io/blog/clinejection-ai-bot-supply-chain-attack/)
- [CSA Research Note](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-confused-deputy-prompt-injection/)

> The CSA's research note explicitly characterizes this as "the supply chain equivalent of confused deputy" and confirms that the security firm grith.ai published the primary incident analysis.

---

### 3. NIST NCCoE February 2026 Concept Paper

- **Status:** Verified
- **Publication Date:** February 5, 2026
- **Title:** *Accelerating the Adoption of Software and Artificial Intelligence Agent Identity and Authorization*
- **Authors:** Harold Booth, William Fisher, Ryan Galluzzo, Joshua Roberts (all NIST)
- **Source:** [NIST CSRC](https://csrc.nist.gov/pubs/other/2026/02/05/accelerating-the-adoption-of-software-and-ai-agent/ipd)
- **Public Comment Deadline:** April 2, 2026 (now closed)

**Core Focus:** Explicitly addresses "auditing and non-repudiation of AI agents, as well as controls to prevent and mitigate prompt injection techniques." The four control areas were surfaced in this concept paper.

**Analyst Commentary:**
- A dev.to analysis (May 2, 2026) explicitly states: "Most agents generate logs. Few generate evidence" — confirming the gap targeted by related benchmarks.
- The CyberNative.AI analysis (March 25, 2026) describes the current audit gap as: "No tamper-proof logging linking agent actions to human authorization | Non-repudiation fails; blame games after incidents."

---

### 4. HAID (Human-Anchored Intent-Bound Delegation)

- **Status:** Verified
- **Type:** Real Proposal
- **Submitted:** April 2, 2026, by the Foundation for American Innovation, in response to NIST's NCCoE concept paper
- **Source:** [Foundation for American Innovation](https://www.thefai.org/posts/human-anchored-intent-bound-delegation-for-ai-agents)

**Core Claim:** "HAID requires that every agent is tied to a verifiably real and unique human individual—without disclosing any of the principal's attributes."

**Delegation Chain:** "Each attestation is signed, scope-attenuating, and traceable to a human pseudonym" — providing the cryptographic infrastructure for non-repudiation.

**Companion IETF Drafts:**
- [Problem Statement](https://www.ietf.org/archive/id/draft-beyer-agent-identity-problem-00.html)
- [Architecture](https://www.ietf.org/archive/id/draft-beyer-agent-identity-architecture-00.html)

An independent IETF draft defines a compatible architectural model for human-anchored agent identity with explicit delegation semantics and provenance structures.

---

### 5. OpenID Foundation NIST Response (March 2026)

- **Status:** Verified
- **Published:** March 11, 2026
- **Source:** [openid.net](https://openid.net/oidf-responds-to-nist-on-ai-agent-security/)

**Core Argument:** "The most urgent AI agent security risks are not technical failures, but failures of trust. Who authorised this agent to act? On whose behalf?"

**Current State:** "Today, most deployments rely on makeshift workarounds: manually managed access lists, unsigned credentials, and no clear chain of accountability."

**Relevance:** This is the precise gap addressed by related benchmarks: measuring whether attribution actually survives adversarial pressure once recommended defenses are deployed.

---

### 6. Salesloft Drift Breach

- **Status:** Verified
- **Type:** Real Incident
- **Timeline:** August 8–17, 2025

**Details:** Attackers used stolen OAuth tokens to access over 700 organizations. The Drift AI Chat agent's OAuth integration was compromised; attackers inherited access across more than 700 independent trust domains including Google Workspace, Cloudflare, and Heap.

**Impact:** Attackers "systematically exfiltrated Salesforce case data across affected organizations."

**Sources:**
- [Oasis Security postmortem](https://www.oasis.security/blog/the-salesloft-oauth-compromise-what-it-changed-and-what-to-do-next)
- [FINRA Alert](https://www.finra.org/rules-guidance/guidance/cybersecurity-alert-salesloft-drift-ai-supply-chain-attack)
- [Anomali analysis](https://www.anomali.com/blog/reviewing-the-salesforce-salesloft-drift-oauth-supply-chain-breach)

> The Okta analysis (February 18, 2026) notes: "OAuth tokens sat active for months after workflows ended, compromising 700+ organizations."

---

### 7. Confused Deputy Attacks — Documented Threat Pattern

- **Status:** Verified

**Details:** The CSA AI Safety Initiative published a formal research note on March 23, 2026, establishing that confused deputy attacks are "a high-severity threat pattern in AI agent deployments." It specifically warns that "multi-agent architectures create propagation paths for confused deputy attacks that can traverse organizational boundaries without human oversight at each step."

**Source:** [Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-confused-deputy-prompt-injection/)

**Additional Context:** The Promptfoo documentation (January 2026) specifically describes multi-agent confused deputy privilege escalation, noting it "bypasses existing specific-agent isolation mechanisms by routing attacks through trusted internal peers."

---

### 8. SentinelAgent / DelegationBench v4 — *closest adjacent framework*

- **Status:** Verified (local source read: `Documents/ResearchPapers/SentinalAgentarXiv-2604.02767v1/`)
- **Author:** KrishnaSaiReddy Patil
- **Full Title:** *SentinelAgent: Intent-Verified Delegation Chains for Securing Federal Multi-Agent AI Systems*
- **Publication Date:** April 2026
- **arXiv:** [https://arxiv.org/abs/2604.02767](https://arxiv.org/abs/2604.02767)

**Core Contribution:** A *Delegation Chain Calculus* (DCC) with seven properties (P1 authority narrowing, P2 intent preservation, P3 policy preservation, **P4 forensic reconstructibility**, P5 cascade containment, P6 scope-action conformance, P7 output schema conformance); a non-LLM *Delegation Authority Service* (DAS) runtime; and the *DelegationBench v4* benchmark — **516 scenarios (150 attacks across seven attack categories A,B,C,D,F,G,H; 366 benign across E,I,J)** — reporting **100% TPR at 0% FPR** with TLA+ model checking of the deterministic properties (P1, P3–P7) across **2.7M states**.

**Token model (decisive for the AEGIS-AT comparison):** delegation tokens are **HMAC-signed bearer credentials** (τ = id, src, **dst**, scope, intent, policy, parent-hash, expiry, sig). **No proof-of-possession / mTLS binding** is described — the token is not bound to the agent that presents it.

**Relevance to AEGIS-AT:** This is the framework a reviewer will point at first. It measures *detection* (TPR/FPR) and *asserts* P4 reconstructibility as a deterministic, TLA+-verified property. It does **not** measure whether the agent that *presented* the token equals the agent that *executed* the action — i.e., it does not measure executor-vs-claimed attribution under transferable bearer tokens, on actions that violate no policy. P4 reconstructs the lineage of the *token presented at the proxy* (who was authorized), not the *holder that wielded it* (who acted). AEGIS-AT therefore **bounds the audit-attribution interpretation of P4** — it does not refute reconstructibility. Note also that SentinelAgent's adversary model includes a **compromised-agent (A2)**; the AEGIS-AT attack succeeds under a *weaker* adversary (alert-text control only, no process compromise), which strengthens the finding.

> **Framing rule (reviewer-safe):** say "AEGIS-AT bounds the audit-attribution interpretation of P4 under transferable, non-sender-constrained bearer tokens." Do **not** say "AEGIS-AT falsifies P4."

---

### 9. Agentic JWT (Dual-Faceted Intent Token Binding)

- **Status:** Verified (local source read: `Documents/ResearchPapers/Agentic_JWT_SecureDelegationarXiv-2509.13597v1/`)
- **Author:** A. Goswami
- **Full Title:** *Agentic JWT: Secure Delegation for Agentic AI* (dual-faceted intent/delegation token)
- **Publication Date:** September 2025
- **arXiv:** [https://arxiv.org/abs/2509.13597](https://arxiv.org/abs/2509.13597)

**Core Contribution:** A JWT extension binding each agent action to a cryptographically verifiable **user intent** and an optional **workflow step**, using **per-agent proof-of-possession (PoP) keys** to prevent replay and in-process impersonation, plus a checksum-based client shim. The introduction explicitly names the structural insight AEGIS-AT measures: *"a separation between the actual user (generator of the intent) and the executing agent (executor of the API call)."*

**Status of evaluation (important caveat):** a proof-of-concept "blocks 100% of threat requests," but the paper states a *"comprehensive performance and security evaluation … will appear in our forthcoming journal submission."* Treat it as a **solution proposal / prototype**, not a completed adversarial measurement.

**Relevance to AEGIS-AT:** This is closest to AEGIS-AT's *fix*, not its *finding*. Per-agent PoP keys are exactly the sender-constraint named as **Baseline 5** (threat-model §8.10; paper §12). Agentic JWT *proposes* the binding but does **not** measure the attribution-integrity regression that motivates it — AEGIS-AT supplies the missing measurement. Complementary, not rival.

---

### 10. Red Hat — "Zero Trust for AI Agents: Why Delegation Beats Impersonation"

- **Status:** Verified (industry narrative)
- **Type:** Vendor engineering blog (Red Hat Emerging Tech)
- **Publication Date:** May 21, 2026
- **Source:** [https://next.redhat.com/2026/05/21/zero-trust-for-ai-agents-why-delegation-beats-impersonation/](https://next.redhat.com/2026/05/21/zero-trust-for-ai-agents-why-delegation-beats-impersonation/)

**Core Narrative:** Delegation beats impersonation; agent identity stays separate from the human's; every delegation hop is traceable; delegation delivers auditability and permission narrowing.

**Relevance to AEGIS-AT:** Narrative foil. AEGIS-AT *qualifies, does not reject* this: delegation does beat shared service accounts (B1) on lineage and least privilege, but its **audit-attribution advantage is conditional** — without sender-constraint, B3 attributes *worse* than per-agent identity (B2). The counterexample targets the auditability claim, not least-privilege.

---

### 11. Okta — "Agent Security: Securing the Delegation Chain"

- **Status:** Verified (industry narrative)
- **Type:** Vendor blog (Okta, AI security)
- **Source:** [https://www.okta.com/blog/ai/agent-security-delegation-chain/](https://www.okta.com/blog/ai/agent-security-delegation-chain/)

**Core Narrative:** Secure delegation framed around scope attenuation, token-level lineage verification, persistent context, and audit-trail / oversight.

**Relevance to AEGIS-AT:** Same conditional-auditability foil as Red Hat. *(Distinct from the Okta Salesloft post cited under Reference 6 — that is a different Okta item.)*

> **Caution — CSA:** Do **not** group "Red Hat / Okta / CSA" as a single pro-delegation-auditability narrative. The CSA source on file (Reference 7) is a *confused-deputy* research note, not delegation-auditability advocacy. Cite Red Hat and Okta for the narrative; cite CSA only for confused deputy.

---

## v3 Sources (2026 completion-block landscape)

> **Authoritative for v3:** the *Verified* entries below are pinned with verbatim
> quotes in the **locked** `Documents/ThreatModel/ThreatModelv3/source-lock-v3.md`
> (§A) — that file, not this list, is the citation of record for the v3
> pre-registration. *Pending* entries are **not yet read at primary source**
> (INV-8) and must not be cited as fact until verified (`source-lock-v3.md` §B).

### v3-1. AIP — Agent Identity Protocol · **the v3 headline anchor**
- **Status:** Verified (`source-lock-v3.md` §A1)
- **Docs:** S. Prakash — IETF `draft-prakash-aip-00` (citation of record) · arXiv:2603.24775
- **Core (verified):** completion block signed by the executing agent (§6.1);
  **Level 1 "Self-Reported … Default for trusted environments"** (§6.2); claims the
  artifact is "tamper-evident, non-repudiable" (§6.3); the §7.1 threat model does
  **not** cover a dishonest authorized executor.
- **Relevance:** the spec that makes self-attestation the default — v3's B8 and the
  convergence thesis rest on it.

### v3-2. PEDIGREE — Verifiable Delegation Identity for Agentic AI
- **Status:** Verified (`source-lock-v3.md` §A2)
- **Docs:** K. Rampalli — IETF `draft-rampalli-pedigree-00` (Apr 2026)
- **Core (verified):** §8 completion blocks; `verification_status` MUST be one of
  **four** tiers — `self_reported`, `tool_verified`, `peer_verified`,
  `human_verified` (§8.2.3); **no default specified**, no adequacy guidance.
- **Relevance:** the tier vocabulary; B9 instantiates its `tool_verified` tier.
  (NOT the source for a "self-report default" — that is AIP.)

### v3-3. HDP — Human Delegation Provenance
- **Status:** Verified (`source-lock-v3.md` §A3)
- **Docs:** A. Dalugoda — arXiv:2604.04522 · IETF `draft-helixar-hdp-agentic-delegation-00`
- **Core (verified):** append-only chain of self-supplied action summaries;
  **v0.1 signs every hop with the issuer's key, not the agent's** (§7.1 — a hop is
  not even bound to the executor); §5.4 admits a genuine-but-misrepresenting hop is
  "not detectable by the protocol alone."
- **Relevance:** third convergence example; the issuer-signing detail makes the gap
  *worse* than AIP's (analysis point for the P5 paper).

### v3-4. MCP authorization spec · **the v3 transport boundary**
- **Status:** Verified (`source-lock-v3.md` §A4)
- **Docs:** modelcontextprotocol.io — Authorization, revision 2025-06-18
- **Core (verified):** server **MUST NOT** pass the client's token through to
  upstream; OAuth 2.1 bearer + RFC 8707 audience binding; **no** act claim /
  delegation chain / attribution mechanism; authorization is **OPTIONAL**.
- **Relevance:** grounds v3 in a shipped 2026 protocol; the token-passthrough rule is
  why executor identity must ride in a completion record (B8/B9).

### Standards (RFCs / drafts) used across v2–v3
RFC 8693 (Token Exchange) · RFC 9449 (DPoP) · RFC 7800 (PoP key semantics) ·
RFC 7638 (JWK Thumbprint) · RFC 8705 (mTLS / certificate-bound tokens — v3 B6) ·
RFC 8707 (Resource Indicators) · OAuth 2.1 `draft-ietf-oauth-v2-1` (bearer default;
sender-constraint only a SHOULD).

### Pending source verification (do NOT cite as fact — `source-lock-v3.md` §B)
- **Otsuka et al.** — arXiv:2604.23280 ("recursive delegation accountability" as a
  structural gap). *Pending.*
- **PAuth** — arXiv:2603.17170 (task-scoped authorization). *Pending.*
- **A-JWT arXiv-ID reconciliation** — Ref 9 above lists arXiv:2509.13597; HDP cites
  Goswami arXiv:2601.05293. Resolve which is canonical and add
  `draft-goswami-agentic-jwt` (v3 B7). *Pending (P3).*
- **OWASP Top 10 for Agentic Applications 2026** (ASI03 Identity & Privilege Abuse)
  — raised in review; not yet read at source. *Pending.*
- **AgentLeak** — arXiv:2602.11510 (multi-agent privacy benchmark; adjacent genre,
  cited in the v2 paper). *Re-verify before v3 reuse.*

---

## Addressing the Two Cautions

### Caution One: Verify References Before Adopting Framing

The "Misattribution Gap" paper is real — authors, findings, and mechanism are confirmed. The HAID proposal is real — submitted to NIST, with a companion IETF draft. The NIST concept paper is real — published on csrc.nist.gov.

However, before adopting the term "Misattribution Gap" or "HAID" as named concepts in a threat model, verify them directly. Open the papers, read them, and confirm that their definitions align with the target framework. Don't let a borrowed framing become your framing without your own review.

### Caution Two: Don't Claim "Nobody Has Measured This"

The stronger claim "Nobody has measured this yet" is inaccurate. The correct framing is **"defensibly underexplored"** or **"no published benchmark exists for this specific measurement."**

- The "Misattribution Gap" paper measured misattribution rates across 64 failures, but it measured model-vs-memory misattribution, not agent-vs-agent sibling impersonation. It's adjacent work, not identical work.
- NIST is asking for non-repudiation mechanisms; nobody has published a reproducible benchmark that measures AIS across the four baseline configurations typically scoped. But the problem space is not "pristine" — it's active and contested.
- The Cline incident is a real-world example of attribution failure, but it's a case study, not a measurement framework.

> The contribution is building the first controlled, reproducible, adversarial benchmark that answers NIST's specific question by scoring the sibling-impersonation attack across a structured defense gradient.

---

## Summary: What You Can Confidently Cite

| Reference | Status | Source |
|-----------|--------|--------|
| "Misattribution Gap" paper (May 2026) | Verified | Authors: Ahad, Hossain, Alam et al.; 64 documented failures |
| Cline MCP compromise (Feb 2026) | Verified | CSA Research Note, Snyk, KrebsOnSecurity, adnanthekhan.com |
| NIST NCCoE Concept Paper (Feb 5, 2026) | Verified | csrc.nist.gov; 4 control areas including auditing & non-repudiation |
| HAID proposal (Apr 2, 2026) | Verified | Foundation for American Innovation + IETF draft |
| Salesloft Drift breach (Aug 2025) | Verified | CSA, Okta, FINRA, Cloudflare incident response |
| OpenID Foundation NIST response (Mar 2026) | Verified | openid.net |
| CSA Confused Deputy research note (Mar 2026) | Verified | CSA AI Safety Initiative |
| SentinelAgent / DelegationBench v4 (Apr 2026) | Verified | arXiv:2604.02767; closest adjacent framework (P4 forensic reconstructibility) |
| Agentic JWT (Sep 2025) | Verified | arXiv:2509.13597; per-agent PoP keys = candidate Baseline 5 |
| Red Hat "delegation beats impersonation" (May 2026) | Verified | next.redhat.com; narrative foil (conditional auditability) |
| Okta "delegation chain" (2026) | Verified | okta.com/blog/ai; narrative foil (conditional auditability) |

**Note:** For the Misattribution Gap paper and HAID proposal, verify them directly before citing them as named concepts. For the "nobody has measured this" language, replace it with "defensibly underexplored" or "no published adversarial benchmark exists for this specific measurement."

---

## Supplementary References

| Source | Link |
|--------|------|
| dev.to — "Most agents generate logs. Few generate evidence" (analysis of NIST concept paper) | [Link](https://dev.to/stephan222/nist-nccoe-ai-agent-identity-authorization-what-developers-need-to-build-2d3e) |
| CyberNative.AI — "No tamper-proof logging" (analysis of NIST deadline) | [Link](https://cybernative.ai/blog/nist-ai-agent-deadline) |
| dev.to — Agentic AI changing the security model | [Link](https://dev.to/docligroup/agentic-ai-is-changing-the-security-model-for-enterprise-systems-what-cisos-need-to-fix-now-4p27) |
| HackerNoon — "The Kernel Is Where Sovereignty Lives" (confused deputy + AI agents) | [Link](https://hackernoon.com/the-kernel-is-where-sovereignty-lives-and-ai-agents-just-broke-the-model) |
| IETF — Architecture for Human-Anchored Agent Identity | [Link](https://datatracker.ietf.org/doc/draft-beyer-agent-identity-architecture/) |
| Promptfoo — Multi-agent confused deputy privilege escalation | [Link](https://www.promptfoo.dev/docs/guides/multi-agent-confused-deputy/) |
| Okta — "OAuth tokens sat active for months" (Salesloft analysis) | [Link](https://www.okta.com/blog/2026/02/oauth-tokens-sat-active-for-months/) |


https://datatracker.ietf.org/doc/html/rfc8693
https://dev.to/kanywst/rfc-8693-deep-dive-token-exchange-310i
