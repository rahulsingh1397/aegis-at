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
