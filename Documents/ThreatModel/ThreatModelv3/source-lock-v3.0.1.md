# AEGIS-AT v3.0.1 — Source Lock (primary-source receipts for B6 / B7)

**Status:** PRE-REGISTERED AND LOCKED — hash-locked by `source-lock-v3.0.1.sha256`
and the CI test `v3/tests/test_threat_model_v3_locked.py`; any edit fails the
build. Companion to `threat-model-v3.0.1.md` (the B6/B7 amendment); both lock
together. To amend, add `source-lock-v3.0.2.md` with its own lock — never edit
this file.
**Verification date:** 2026-06-21 (each row read at its cited source on this date).
**Discipline:** This file exists because of INV-8 (verify every domain/spec claim
against the primary source; never trust paraphrase — including the v3 session
handoff brief, prior session notes, or external reviews). It **moves B6 (RFC 8705)
and B7 (A-JWT) from `source-lock-v3.md` §B ("cited but NOT read at source — DO NOT
LOCK") into §A (read at source, quotes pinned)**, which is the precondition v3.0
§9 L11 / §7.1 set before either prediction could be locked. It resolves only those
two items; the remaining `source-lock-v3.md` §B entries stay pending (§B below).

Classification legend (as in `source-lock-v3.md`):
- **NORMATIVE** — stated with RFC 2119 force (MUST / MUST NOT / SHOULD).
- **DESCRIPTIVE** — plain prose / definition / default, without RFC 2119 force.
- **INFERRED** — not stated; deduced from what the source does/omits.

---

## §A. Verified at primary source (2026-06-21)

> Continues the numbering of `source-lock-v3.md` §A (A1 AIP, A2 PEDIGREE, A3 HDP,
> A4 MCP). A5 and A6 below are the B6/B7 receipts.

### A5 — RFC 8705 (mTLS / certificate-bound access tokens) — baseline B6
- **Spec:** RFC 8705, "OAuth 2.0 Mutual-TLS Client Authentication and
  Certificate-Bound Access Tokens" (B. Campbell et al.), February 2020.
- **URL read:** https://www.rfc-editor.org/rfc/rfc8705 (verified 2026-06-21).
- **Resolves the `source-lock-v3.md` §B question for B6** — "verify the
  executor-attribution assumption before claiming predicted equivalence to DPoP."
  Answer: RFC 8705 §3 **mandates verification of the bound certificate at the
  protected resource at access time**, so the at-access possession check is the
  same shape as DPoP's (B5) — the equivalence holds, stated below.
- **Claim B6 uses #1 — binding defeats stolen/replayed tokens (rationale):** §1 —
  "Binding an access token to the client's certificate prevents the use of stolen
  access tokens or replay of access tokens by unauthorized parties." —
  **DESCRIPTIVE** (Introduction rationale).
- **Claim B6 uses #2 — same certificate, mutually authenticated TLS, at the
  resource:** §3 — "those requests MUST be made over a mutually authenticated TLS
  connection using the same certificate that was used for mutual TLS at the token
  endpoint." — **NORMATIVE (MUST).**
- **Claim B6 uses #3 — the resource MUST obtain and verify the cert against the
  token (the at-access check):** §3 — "The protected resource MUST obtain, from
  its TLS implementation layer, the client certificate used for mutual TLS and
  MUST verify that the certificate matches the certificate associated with the
  access token." — **NORMATIVE (MUST).** *This is the load-bearing sentence: the
  executor identity is checked at the resource at access, not self-reported.*
- **Claim B6 uses #4 — the binding member:** §3.1 — the `cnf` claim's `x5t#S256`
  member carries the "base64url-encoded SHA-256 hash (a.k.a., thumbprint,
  fingerprint, or digest) of the DER encoding of the X.509 certificate." —
  **NORMATIVE/DESCRIPTIVE** (member definition).
- **Reading for the B6 prediction (`threat-model-v3.0.1.md` §A1 → 1.0 / 1.0):**
  a cert-bound token whose certificate is verified at the resource at access is a
  **sender-constraint identical in shape to B5 (DPoP, RFC 9449)** — possession
  proven at execution, lifted token useless without the bound cert. The §4.2
  colluder cannot present **another agent's** certificate (key/credential forgery,
  out of scope), so the capability is inert; honest = colluding = 1.0.
  **Caveats:** (i) the benchmark assumes a **per-executor (per-agent)** certificate
  and that the resource derives the recorded executor identity from the verified
  cert (RFC 8705 §3 mandates the verification; the benchmark instantiates the
  cert→identity mapping; a shared client-app cert would identify only the app);
  (ii) executor cert/key compromise is outside the v3 collusion model (§4.2).

### A6 — Agentic JWT (A-JWT) — baseline B7
- **IETF I-D:** `draft-goswami-agentic-jwt-00`, "Secure Intent Protocol: JWT
  Compatible Agentic Identity and Workflow Management," Abhishek Goswami (Ed.),
  published 2025-12-31 (expires 2026-07-04). URL confirmed:
  https://datatracker.ietf.org/doc/html/draft-goswami-agentic-jwt-00.
- **Companion paper (the source actually read for the receipts below):**
  arXiv:2509.13597v1, "Agentic JWT: A Secure Delegation Protocol for Autonomous AI
  Agents," A. Goswami, 16 Sep 2025. **Read at the local LaTeX source**
  `Documents/ResearchPapers/Agentic_JWT_SecureDelegationarXiv-2509.13597v1/`
  (`abstract.tex`, `introduction.tex`, `architecture.tex`, `security_anchors.tex`,
  `threat_model.tex`, `experimental_framework.tex`), verified 2026-06-21. The I-D
  and the arXiv paper are the same work by the same author under different titles
  (I-D vs. paper), confirmed via the §C arXiv-ID reconciliation.
- **Resolves the `source-lock-v3.md` §B question for B7** — "does it bind/verify
  the execution assertion **at execution time**, or only gate who MAY execute?"
  Answer: **both.** A-JWT verifies the per-agent proof-of-possession signature at
  the Resource Server at request (execution) time, and additionally gates minting
  via an IDP runtime checksum check + in-process anti-impersonation anchor. The
  asserted executor is verified, not a bare self-report.
- **Claim B7 uses #1 — per-agent PoP against replay and in-process
  impersonation:** abstract — "The design also uses per-agent proof-of-possession
  keys to prevent replay and in-process impersonation." — **DESCRIPTIVE.**
- **Claim B7 uses #2 — PoP key in `cnf`, signature verified at the RS at
  execution (Anchor A6):** §5 — "During registration each agent generates
  ephemeral key pair and includes the public key in IDP registration request. The
  IDP stores it with this agent's registration record and sends in the cnf claim
  of the issued token"; "Client performs Ed25519 signature with http request to
  the Resource Server. The Resource Server uses agent specific public key in the
  token and verifies this signature"; guarantee: "Intercepted or stolen tokens
  cannot be replayed without access to the agent specific private key." —
  **DESCRIPTIVE (design proposal).** *This is the at-execution verification.*
- **Claim B7 uses #3 — no in-process cross-agent impersonation (Anchor A3, which
  "Mitigates: T1"):** §5 — "Agents cannot impersonate other agents within the same
  process space," enforced by "Stack inspection and object identity verification at
  token request time." A-JWT's threat model **admits the checksum-copy attack A3
  defends against** — §4, T1 Agent Identity Spoofing: "A malicious agent
  impersonates a legitimate agent by replicating its code structure, prompts, and
  tool configurations to compute identical checksums" — so B7's recovery rests on
  **A3 (at mint) + A6 (at execution), not the checksum.** — **DESCRIPTIVE (design
  proposal + admitted threat).**
- **Claim B7 uses #4 — IDP checksum check gates minting:** §3 (minting flow) —
  the IDP performs "Compare the provided checksum against the registered checksum
  of the agent which amounts to runtime cryptographic check on agent's identity."
  — **DESCRIPTIVE.** The PoP JWK thumbprint binds to the token: §3 — "The JWK's
  thumb-print (`jkt`) is embedded in the `cnf` claim of the Intent Token." The
  intent token carries an `executed_by` field (§3 token example). — **DESCRIPTIVE.**
- **Claim B7 uses #5 — the threat model targets the v3 attribution gap:** §4
  threat enumeration — **T7 Cross-Agent Privilege Escalation** (Elevation of
  Privilege), **T10 Intent Origin Forgery** (Repudiation), **T11 Delegation Chain
  Manipulation** (Repudiation). Framing (introduction): "This causes a separation
  between the actual user (generator of the intent) and the executing agent
  (executor of the API call)." — **DESCRIPTIVE.**
- **Reading for the B7 prediction (`threat-model-v3.0.1.md` §A2 → 1.0 / 1.0):**
  the execution assertion (`executed_by` + PoP `cnf`) is verified at execution
  (RS, Anchor A6) and at mint (IDP checksum + Anchor A3), so it is **not** a bare
  self-report — the **opposite of B8**. The §4.2 colluder cannot sign with another
  agent's PoP key (out of scope) nor impersonate another agent in-process (A3), so
  it cannot attribute its action to a different agent; honest = colluding = 1.0.
- **Caveats (load-bearing; mirror `threat-model-v3.0.1.md` L21):**
  1. **PoC, not a validated measurement.** A-JWT reports "A reference
     implementation evaluated on a multi-agent micro-service, blocking 100 % of
     threat requests," but states "A comprehensive performance and security
     evaluation with experimental results will appear in our forthcoming journal
     submission." The B7 = 1.0/1.0 prediction is for the **mechanism as specified,
     graded by AEGIS-AT's own recorder** — not an endorsement of A-JWT's 100 %.
  2. **Native anchor weaker than v3's.** A-JWT's identity check runs **in-process**
     (Shim checksum + A3 stack/object inspection), whereas v3's INV-4 recorder is
     independent by **OS-process boundary**. A-JWT offers an "optional TEE
     attestation … profile that detect in-process impersonation" to strengthen it.
     AEGIS-AT grades B7 with its own OS-process recorder regardless, so the
     measurement's independence is v3's, not A-JWT's.

---

## §B. Still pending from `source-lock-v3.md` §B — NOT resolved by this amendment

This amendment closes only the B6/B7 (RFC 8705 / A-JWT) items. The following
remain "cited but NOT read at primary source — DO NOT cite as fact / DO NOT LOCK"
until moved to §A in a later source-lock:
- **PAuth** (arXiv:2603.17170) — task-scoped authorization; positioning only.
- **Otsuka et al.** (arXiv:2604.23280) — "recursive delegation accountability."
- **NIST NCCoE concept paper** (2026-02-05) — re-verify the "link agent actions to
  human authority" wording for v3 reuse.
- **OWASP Top 10 for Agentic Applications 2026** (ASI03 Identity & Privilege
  Abuse) — raised in review; not yet read at source.
- **Completion-record field semantics** — whether any source physically separates
  the signer/attester identity from the asserted executor/outcome fields. v3 still
  uses a benchmark abstraction only (`threat-model-v3.md` §5.1, L14).

---

## §C. arXiv-ID reconciliation for A-JWT (resolved, P3 — 2026-06-21)

`References.md` flagged a conflict in its "Pending source verification" list:
AEGIS-AT cites A-JWT as arXiv:2509.13597 (Ref 9), while that note recorded the HDP
paper as citing "Goswami arXiv:2601.05293." The two arXiv IDs were resolved at
source:
- **Canonical A-JWT = `draft-goswami-agentic-jwt-00` (IETF I-D) + arXiv:2509.13597**
  ("Agentic JWT: A Secure Delegation Protocol for Autonomous AI Agents," A.
  Goswami) — confirmed the same work by the same author (datatracker entry +
  local arXiv source); this is the citation of record for B7.
- **arXiv:2601.05293 is an UNRELATED paper** (verified at
  https://arxiv.org/abs/2601.05293): "A Survey of Agentic AI and Cybersecurity:
  Challenges, Opportunities and Use-case Prototypes" (S. J. Lazer, K. Aryal, M.
  Gupta, E. Bertino) — a survey, not Goswami, not A-JWT. It is **dropped as an
  A-JWT reference.**
- The conflated ID does not affect any A-JWT receipt in §A6 (all read from
  arXiv:2509.13597 / the local LaTeX source / the I-D). **Loose end (not
  blocking):** HDP's own bibliography was **not** re-read this session, so whether
  the mis-citation originated in the HDP paper or in its transcription into
  `References.md` is unconfirmed (INV-8); either way `2601.05293` is not an A-JWT
  source. `References.md` §"Pending source verification" is corrected accordingly.
