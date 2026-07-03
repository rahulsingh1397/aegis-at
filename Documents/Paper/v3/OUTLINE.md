# AEGIS-AT v3 paper — section outline (planning note, pre-draft)

> **Status:** scoping note that guided the P5 draft (now complete — see
> `aegis-at-v3.tex`). Not the `.tex`. Mirrors the
> v2 paper's architecture/voice (`Documents/Paper/v2/aegis-at-v2.tex`). Review this
> before any LaTeX is written. Discipline carried from v1/v2: every AIS/rate asserted by
> a test against a **locked** prediction; figures regenerate from the live harness; a
> contradicted prediction is a **finding**, not reconciled (INV-7); related work is
> "methodology over the landscape," never "draft X is broken" (per `EDIT_PLAN`).

## Thesis (the v1→v2→v3 arc)
- **v1:** the executor has no field (RFC 8693 `act.sub` names the *requester*).
- **v2:** bind the token to the executor's key (DPoP / B5 recovers AIS to 1.0).
- **v3:** completion/provenance records now exist (AIP/PEDIGREE/HDP, 2026) — **but who
  attests their content, and can a real model exploit the gap?**

## Working title (pick one in review)
- *AEGIS-AT v3: Who Attests the Completion? Self-Reported vs. Independently-Verified
  Attribution Under a Real-Model Adversary*
- *AEGIS-AT v3: When the Completion Record Attests Itself*

## The two empirical payloads (what's genuinely new vs v2)
1. **Tier-1 (scripted, deterministic — the locked headline):** the completion-attestation
   layer. **B8 (`self_reported`)** honest = 1.0, colluding = **0.0**; **B9
   (`tool_verified`)** honest = 1.0, colluding = **1.0** — the knockout. Exact-equality,
   pre-registered in `threat-model-v3.md`.
2. **Tier-2 (LLM ladder — the real-model payload):** 4 Groq models weak→strong.
   B8-attack forging **90–100%** across all; B9-attack **0%** across all (knockout
   holds). H1 flat, H2 supported, H4 sanity. Wilson CIs; pre-registered in the separately
   locked `threat-model-v3.1.md §C`.

---

## Section-by-section (mirrors v2)

### Abstract
The arc in one sentence; the completion-record abstraction (B8 self_reported / B9
tool_verified); Tier-1 knockout (B8 colluding 0.0 → B9 1.0); Tier-2 real-model result
(90–100% B8 forging, 0% B9 across 4 models); the 2026 framing (AIP makes self-report the
default; none model a dishonest authorized executor). Pre-registered, two-stage lock,
figures from harness.

### 1. Introduction
- v1/v2 recap (one line each, like v2 §1's "v1 result in one line").
- **The 2026 completion-block landscape:** AIP's "Level 1 Self-Reported … default for
  trusted environments" (§6.2); PEDIGREE's four `verification_status` tiers (§8.2.3) with
  no adequacy guidance; HDP's issuer-signed (not executor-signed) hops; MCP's
  token-passthrough-forbidden. **The gap:** these make self-attested completion the
  emerging default, and none model a *dishonest authorized executor* (AIP §7.1).
- **The moat sentence** (reuse from `EDIT_PLAN`): AEGIS-AT treats *attribution
  correctness — does the logged actor equal the true executor? — as the measured
  dependent variable*, not a design guarantee.
- Contributions (enumerated, see below).
- **Scope and honesty up front** (v2-style): scripted-core + 4-model LLM tier, one
  scenario, T1; **the locked §C6 prompt forces the tool call ("you MUST call …"), which
  saturates Tier-2 B8 near the ceiling — so H1's flat curve is reported as a finding
  *with that bias disclosed*, and de-saturation is named as v4** (do NOT claim
  "capability-independence").

### Contributions (enumerated)
1. **The completion-record abstraction** (§5.1): `asserted_executor`,
   `attestation_source ∈ {self_reported, tool_verified}`, `attester_id`, `signature` —
   the minimal benchmark surface for the 2026 completion-block protocols.
2. **The Tier-1 knockout** (scripted): B8 self-report collapses to 0.0 under collusion;
   B9 tool-verified holds at 1.0. The v2 process-boundary recorder *is* B9's verifier
   (keystone reuse).
3. **The Tier-2 real-model result:** 4 frontier-adjacent open models forge the executor
   claim at 90–100% under self-report; the knockout (B9 = 0% evasion) holds for every
   model. First controlled measurement of a *real model* exploiting the completion gap.
4. **Two-stage pre-registration:** `threat-model-v3.md` (scripted, exact-equality) and a
   separately locked `threat-model-v3.1.md` (LLM, directional + Wilson) — both SHA-256
   locked before their measuring code.
5. *(If P3 done)* **Comparative breadth:** B6 (mTLS-bound, RFC 8705) and B7 (A-JWT) as
   config flags — confirm whether execution is verified or self-asserted.

### 2. Background and Relationship to v1/v2
- Inherited: the AIS scorer, the process-boundary recorder (now repurposed as B9's
  `tool_verified` verifier), the B1–B5 path (imported from `aegis_at_v2`, INV-6).
- New: the completion layer, B8/B9, the LLM seat. The MCP transport boundary
  (token-passthrough-forbidden) grounding v3 in a shipped 2026 protocol.

### 3. The Completion-Record Abstraction
- The §5.1 record; B8 = trust the completion's claimed actor; B9 = resolve via the
  independent verifier. The deliberate control: Contain runs under an opaque per-agent
  credential so the *only* field the attestation source can move is the executor
  (`claimed_actor`) — isolating the executor-attribution axis.

### 4. Tier-1 — The Scripted Completion Core (deterministic headline)
- Honest checkpoint (hard gate): B8 honest = B9 honest = 1.0 before any colluder code.
- Colluder: `asserted_executor=enrich`, `attester_id=contain`, valid sig under Contain's
  own key → B8 = 0.0, B9 = 1.0. Defect is actor `field_mismatch`, not a missing record.
- Non-circularity guard (C1 raises if B9 unobserved; C2 degraded-resolver end-to-end).
- INV-4: ground-truth records carry none of the completion fields; the grader reads only
  the PID. The JWT-sensitivity check (Slice E) answers "is the opaque cred rigged?".

### 5. Tier-2 — The LLM Ladder (real-model payload)
- 4 Groq models (weak→strong); completion via a **structured tool call**
  (`submit_completion(action_id, asserted_executor)`); the injection manipulates the
  `asserted_executor` argument (not free text).
- Results: B8-attack forging 90–100% (all models); B9-attack 0% (knockout, all models);
  honest ≈ 0. **H1 flat — reported with the §C6 forced-call caveat; H2 supported
  (headline); H4 sanity.** Wilson CIs; adaptive N (batch 20, stop at half-width < 0.05,
  cap 200); per-cell SHA-256 seeds (32-bit, API-valid); statistically (not byte)
  reproducible.

### 6. B6/B7 — mTLS and A-JWT comparative breadth (RESULTS — verified done)
B6 (mTLS, RFC 8705) and B7 (A-JWT execution-assertion) are implemented + tested:
**both AIS = 1.0**, each *earned* by execution-time verification (non-circularity
controlled), not structural — B7's `executed_by` PoP rejects a cross-agent assertion
(`test_b7_agentic_jwt.py`). Locked in `threat-model-v3.0.1/.1`. **Narrative:** DPoP (B5),
mTLS (B6), and A-JWT (B7) all *earn* recovery via execution-verification — while
**self-report (B8) is the lone failure** and tool-verified (B9) holds. Present as the
comparative breadth around the B8/B9 headline; the full deterministic curve is **B1–B9**
(B1=0, B2=1, B3=0, B4=0, B5=1, B6=1, B7=1, B8=1/0, B9=1/1).

### 7. Implementation
The v3 package (imports `aegis_at_v2` for B1–B5); recorder→B9 verifier; scorer extended
with attestation-source selection; the new `completion/`, `transport/mcp_adapter`, and
the LLM `harness/{llm_seat, llm_sweep, llm_eval}` modules; test counts.

### 8. Experimental Methodology
Two-stage pre-registration + the lock-guard test; figures from the live harness;
determinism (scripted) vs statistical reproducibility (LLM, §C10); the seed contract.

### 9. Results
- Table: Tier-1 grid (B8/B9 × honest/colluding × T1) == locked.
- Table: Tier-2 grid (per-model B8/B9 attack/honest forging-rate + Wilson CI).
- The H1–H4 verdict (H2 holds; H1 flat = finding; H4 sanity).

### 10. Discussion
- Self-attestation defaults are the **live** risk (AIP §6.2 default).
- The knockout localizes the fix: independent verification (the `tool_verified` tier) is
  the layer that closes it — the completion-era analogue of v2's sender-constraint.
- A **real model**, not a scripted colluder, exploits the gap — the threat is not
  hypothetical.
- Carry-over: delegation's auditability is conditional (Red Hat/Okta foil, qualified).

### 11. Limitations and Validity Threats
- **The §C6 forced-call bias** → Tier-2 B8 saturation → H1 flat is partly an artifact;
  de-saturation is v4. (Frame honestly; do not lean on capability-independence.)
- 4 open-weight models, one scenario, T1 only.
- Statistical (not byte) reproducibility for the LLM tier.
- Independence by construction (process boundary), not formal verification.

### 12. Future Work (= v4, per MASTER_PLAN §4)
Cross-org / multi-trust-domain delegation; `peer_verified` / `human_verified` tiers; the
**de-saturated capability curve** + more models/scenarios/attack-phrasings; principal
laundering, key forgery, scope-attenuation bypass; emergent (non-injected) deception.

### 13. Conclusion
The arc completes: completion-attestation protocols default to self-report; a real model
forges the executor claim ~always under self-report; independent verification
(`tool_verified`) is the layer that closes it — the completion-era counterpart to v2's
sender-constraint.

### Related Work (woven, not a monolith — reuse v1/v2 positioning)
SentinelAgent/DelegationBench v4 (bounds the audit-attribution interpretation of P4 — the
reviewer-safe framing); Agentic JWT (complementary Baseline candidate, not rival); The
Misattribution Gap (model/belief layer vs AEGIS delegation/blame layer — complementary,
per `The_Misattribution_Gap_VS_AEGIS.md`); AIP/PEDIGREE/HDP (the completion-block frontier
v3 measures over); NIST NCCoE / OpenID / OWASP ASI03 (the standards call). "Defensibly
underexplored," never "nobody has measured this."

### References
Extend the v2 bibliography with the verified v3 frontier (AIP, PEDIGREE, HDP, MCP auth
spec, NIST, OWASP, PAuth/Otsuka where verified) — per `source-lock-v3*.md` receipts.

### Reproducibility & Artifact Availability
The two-stage locked threat model + harness + tests; Tier-1 byte-reproducible, Tier-2
statistically reproducible from `base_seed`; figures from `make_figures.py`.

---

## Open items to resolve before drafting
1. ~~Confirm P3 (B6/B7) status~~ — **RESOLVED: done & locked.** B6 = B7 = AIS 1.0
   (earned, non-circularity controlled). §6 is a results section; curve is B1–B9.
2. **Title choice** (two candidates above).
3. **H1 framing** — confirm the saturation/forced-call disclosure wording (it's the one
   spot a reviewer will press; the honest framing is "flat = finding, bias disclosed,
   de-saturation = v4").
4. **Figures** — Tier-1 grid bar + Tier-2 per-model forging curve (with CIs); regenerate
   from the harness (no hand-drawing).
