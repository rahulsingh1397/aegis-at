# AEGIS-AT v3 — Source Lock (primary-source receipts)

**Status:** DRAFT — not yet SHA-256-locked. Pending author review before it is
hashed alongside `threat-model-v3.md`.
**Verification date:** 2026-06-15 (re-verify before any prediction is locked; IETF
drafts churn and several expire late 2026).
**Discipline:** This file exists because of INV-8 (verify every domain/spec claim
against the primary source; never trust paraphrase — including the v3 kickoff
brief, prior session notes, or external reviews). Every row below was read at the
cited URL on the verification date. Claims NOT yet read at source are listed in
§B and must NOT be cited in any locked prediction until moved to §A.

Why this artifact: three external reviews of the v3 direction all leaned on a
claim that **PEDIGREE defaults to `self_reported`**. Reading the actual draft
showed that is **false** (PEDIGREE specifies no default). One review additionally
quoted a verbatim AIP sentence ("...does not prevent a dishonest agent from
misrepresenting results") that **does not exist** in the AIP draft. This file is
the guard against building a locked prediction on a paraphrase or a hallucinated
quote.

Classification legend:
- **NORMATIVE** — the spec states it with RFC 2119 force (MUST / MUST NOT / SHOULD).
- **DESCRIPTIVE** — the spec states it as plain prose / a definition / a default,
  without RFC 2119 force.
- **INFERRED** — not stated; deduced from what the spec does/omits. Flagged as
  inference in the paper; never presented as a quote.

---

## §A. Verified at primary source (2026-06-15)

### A1 — AIP (Agent Identity Protocol) — the v3 headline anchor
- **Draft:** draft-prakash-aip-00 (S. Prakash). Also arXiv:2603.24775.
- **URL read:** https://www.ietf.org/archive/id/draft-prakash-aip-00.html
- **arXiv-ID flag (re-verify before lock):** the HDP paper (A3) cites the SAME
  arXiv:2603.24775 under a DIFFERENT title — "Authorization Provenance in Agentic
  AI Systems" — suggesting the arXiv paper was retitled across versions. The IETF
  draft draft-prakash-aip-00 is the citation of record for the §6 completion-block
  facts below; confirm the arXiv version/title pin separately before locking.
- **Claim v3 uses #1 — completion blocks are self-attested:** §6.1 — a completion
  block is "the final block in a chained token, **signed by the executing
  agent**"; `verification_status` is REQUIRED. — **DESCRIPTIVE / NORMATIVE (the
  REQUIRED field).**
- **Claim v3 uses #2 — self-report is the DEFAULT:** §6.2 — "**Level 1
  (Self-Reported): Agent reports its own results with no independent verification.
  Default for trusted environments.**" Levels 2 (delegator counter-signs) and 3
  (third-party attested) are the independent-verification escalations. —
  **DESCRIPTIVE.** *This is the anchor for the v3 "self-attestation by default"
  claim — AIP, not PEDIGREE, is the source that states it.*
- **Claim v3 uses #3 — the spec claims non-repudiation:** §6.3 — a completed
  token with its completion block is a "self-contained audit artifact" that is
  "tamper-evident, non-repudiable, and verifiable offline." — **DESCRIPTIVE.**
  *The foil for v3, stated precisely: this is non-repudiable evidence that the
  signer MADE the completion assertion — NOT independent evidence that the
  asserted outcome or executor attribution is true. Under a colluding executor
  the two diverge.*
- **Claim v3 uses #4 — the threat model omits the dishonest authorized executor:**
  §7.1 addresses signature forgery, token forgery, and scope violations, and
  **does not contain** a "fraudulent completion block" / dishonest-authorized-
  executor entry. Stated precisely: the threat model does not specify a
  dishonest-authorized-executor case or controls for false self-attested
  completion. — **INFERRED (a documented absence, not a statement).**
  *This is the gap v3 measures. State it as an omission, never as a spec
  admission. Do NOT use the fabricated "does not prevent a dishonest agent..."
  quote that appeared in an external review — it is not in the draft.*

### A2 — PEDIGREE — tier vocabulary + permissive-silence finding (NOT the anchor)
- **Draft:** draft-rampalli-pedigree-00 (K. Rampalli), 25 Apr 2026 (expires ~27
  Oct 2026).
- **URL read:** https://www.ietf.org/archive/id/draft-rampalli-pedigree-00.html
- **Claim v3 uses #1 — four verification tiers:** §8 completion blocks; §8.2.3 —
  "The `verification_status` field MUST be one of: 'self_reported',
  'tool_verified', 'peer_verified', or 'human_verified'." — **NORMATIVE.**
  *Note: FOUR tiers (the kickoff brief said three — it omitted `human_verified`).*
- **Claim v3 uses #2 — NO default, NO adequacy guidance:** searched the whole
  draft incl. §10 (Security Considerations). The spec specifies **no** default
  value for `verification_status`, gives **no** recommendation of a tier, and
  contains **no** warning that `self_reported` is weak or insufficient. §10
  covers parent-swap and scope-escalation but is silent on completion-block
  verification strength. — **INFERRED (a documented absence).**
  *Corrects the brief's keystone error ("defaults to self_reported"). The real,
  defensible PEDIGREE finding is permissive silence: it enumerates `self_reported`
  as a valid completion attestation with zero guidance that it is inadequate for
  attribution.*

### A3 — HDP (Human Delegation Provenance) — third example, with an explicit self-admission
- **Paper:** arXiv:2604.04522 (A. Dalugoda, Mar 2026). IETF I-D:
  draft-helixar-hdp-agentic-delegation-00 (RATS WG, individual submission).
  **Read at the full PDF** (sections below), not just the abstract.
- **Claim v3 uses #1 — append-only chain of agent-extended, self-recorded hops:**
  §4.2.4 — the chain is append-only; each hop records a self-supplied
  "action summary" plus a hop_signature; "Agents must not remove or modify
  existing entries." §6.2 — each agent "extends the chain with its intended
  action summary." — **DESCRIPTIVE.**
- **Claim v3 uses #2 (CORRECTION to my earlier abstract reading) — v0.1 signs
  every hop with the ISSUER's key, not the agent's:** §7.1 — "HDP v0.1 uses the
  issuer's key for all hop signatures, meaning **agents do not sign with their
  own keys.** ... hop signatures attest that a hop was recorded at the issuer,
  not that the specific agent produced it." Per-agent key binding is deferred to
  v0.2 (§4.3.2, §7.1). — **DESCRIPTIVE/NORMATIVE.** *Correction: the abstract's
  "each agent's delegation action as a signed hop" does NOT mean per-agent
  signing in v0.1; HDP v0.1 does not cryptographically bind a hop to the executor
  at all. Do not claim "each agent signs its own hop" for HDP.*
- **Claim v3 uses #3 — HDP explicitly ADMITS the self-recorded-content gap:**
  §5.4 — "a sophisticated injected instruction that causes a legitimate agent to
  record a genuine hop with an action_summary misrepresenting the actual intent
  is **not detectable by the protocol alone.** This semantic validation boundary
  is an application-layer responsibility." §3.2 — HDP "does not protect: ...
  semantic correctness of actions relative to declared scope." — **DESCRIPTIVE
  (explicit limitation).** *Stronger than AIP for v3: where AIP OMITS the
  dishonest-executor case (A1#4), HDP states on the record that a
  genuine-but-false self-recorded hop is undetectable by the protocol — a
  primary-source admission of exactly the gap v3 measures.*

### A4 — MCP authorization spec — the v3 transport boundary
- **Spec:** Model Context Protocol, Authorization, revision 2025-06-18.
- **URL read:** https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- **Claim v3 uses #1 — token passthrough is forbidden:** "If the MCP server makes
  requests to upstream APIs... The MCP server **MUST NOT** pass through the token
  it received from the MCP client." Also: "MCP servers **MUST NOT** accept or
  transit any other tokens." — **NORMATIVE.**
  *Grounds the v3 transport, stated precisely: MCP does not carry originating-agent
  attribution across the upstream hop by default (the upstream sees the MCP
  server's own token, not the originating agent's). Recovering executor
  attribution requires an explicit executor field/record; the exact observation
  point is defined by the v3 experiment, not asserted here.*
- **Claim v3 uses #2 — no attribution mechanism:** the spec is OAuth 2.1 bearer +
  RFC 8707 audience binding (`resource` parameter MUST be sent/validated). It
  defines **no** RFC 8693 act claim, **no** delegation chain, and **no**
  attribution/audit mechanism for which agent executed an action. — **INFERRED
  (absence) + NORMATIVE (the audience-binding requirements it does state).**
- **Claim v3 uses #3 — authorization is OPTIONAL:** "Authorization is
  **OPTIONAL** for MCP implementations." — **NORMATIVE.**
- **Note:** MCP §"Confused Deputy Problem" exists but is scoped to OAuth
  authorization-code / audience misuse, NOT executor attribution — distinct from
  the AEGIS-AT confused-deputy framing.

---

## §B. Cited in the brief/reviews but NOT yet read at source — DO NOT LOCK

These must be moved to §A (read at primary source, quote pinned) before they can
appear in any locked v3 prediction or be claimed as fact in the paper.

- **A-JWT** (draft-goswami-agentic-jwt / arXiv:2509.13597) — needed for baseline
  B7. Specifically verify: does it bind/verify the execution assertion at
  execution time, or only gate who MAY execute? (Determines B7's predicted
  honest/colluding values.)
- **RFC 8705 (mTLS-bound tokens)** — needed for baseline B6. Verify the executor-
  attribution assumption before claiming "predicted equivalence to DPoP." Do NOT
  call B6/B7 done deals (per external review caution).
- **PAuth** (arXiv:2603.17170) — task-scoped authorization; positioning only
  (authorization ≠ attribution). Verify the one-line characterization.
- **Otsuka et al.** (arXiv:2604.23280) — "recursive delegation accountability" as
  one of five structural gaps; motivation. Verify the exact framing/quote.
- **NIST NCCoE concept paper** (2026-02-05) — non-repudiation focus area; already
  cited in v1/v2 but re-verify the "link agent actions to human authority"
  wording for v3 reuse.
- **Completion-record field semantics** — verify exact field names and whether any
  source physically separates the signer/attester identity from the asserted
  executor/outcome fields. Until verified, v3 uses a benchmark abstraction only
  (`threat-model-v3.md` §5.1, L14). *(Surfaced by external review of the v3
  threat-model draft; the B8 mechanism rests on the verified `self_reported` =
  no-independent-verification property, not on this field layout.)*

---

## §C. Corrections this file makes to the v3 kickoff brief
1. **Anchor flip:** the "self-attestation by default" claim is sourced from **AIP
   §6.2**, not PEDIGREE. PEDIGREE specifies no default (A2).
2. **PEDIGREE tier count:** four tiers incl. `human_verified`, not three (A2).
3. **No spec self-admission:** AIP does not admit the colluding-executor flaw; its
   §7.1 omits it. v3 frames it as an omission v3 measures, not a confession (A1#4).
   The external-review quote asserting otherwise is fabricated.
4. **INV-4 framing (per external review, adopted):** a self-reported completion
   block is **agent-supplied evidence**, not an INV-4 violation in itself. It
   becomes an INV-4 problem only if a measurement system treats it as ground
   truth. v3's recorder must never read the completion-block executor field. The
   v3 finding: self-report closes the honest gap but fails under collusion because
   the attester and the accountable party are the same entity.

---

## §D. The "convergence" claim, stated precisely (for the paper)

The three specs do NOT converge on the *same cryptographic shape*; they converge
on **trusting executor-supplied completion/provenance content without independent
verification by default.** State it at this altitude, never as "they all
self-sign":
- **AIP** — the executing agent signs its own completion block; Level 1
  (Self-Reported) is the default (A1).
- **PEDIGREE** — enumerates `self_reported` as a valid `verification_status` with
  no default and no adequacy guidance (A2).
- **HDP** — records an agent-supplied `action_summary` per hop (issuer-signed in
  v0.1, so not even executor-bound) and explicitly admits a genuine-but-
  misrepresenting hop is undetectable by the protocol (A3).

The defensible convergence sentence: *"2026 completion/provenance proposals bind
an action record to a delegation chain but, by default, accept the executing
agent's own account of what it did without independent verification — AIP makes
self-report the default level, PEDIGREE permits it with no adequacy guidance, and
HDP records self-supplied action summaries and concedes they may misrepresent."*
This is portable across draft churn: it describes a design pattern, not a single
draft.
