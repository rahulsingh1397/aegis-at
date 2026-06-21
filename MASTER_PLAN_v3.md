# AEGIS-AT v3 — Master Plan

> **Status: LIVING DOCUMENT (not hash-locked).** Predictions are pre-registered
> and locked in `Documents/ThreatModel/ThreatModelv3/threat-model-v3.md`
> (+ `source-lock-v3.md`); this plan is *execution*, not prediction, so it is
> updated as phases complete. It never restates a prediction — it points to the
> locked threat model for those.
>
> **The thesis (one line):** v1 = "the executor has no field"; v2 = "bind the
> token to the executor's key"; v3 = "completion/provenance records now exist —
> but who attests their content, and can a real model exploit the gap?"
> See `threat-model-v3.md` §1–§2 for the full framing.

---

## 0. The merged design in one picture

One grid, one deterministic grader (the v2 process-boundary recorder), a
swappable attacker in the executor seat:

| Defense ↓ \ Seat → | script-honest | script-colluding | LLM small … frontier |
|---|---|---|---|
| **B8 self-reported** | 1.0 | **0.0** | evasion-rate curve (v3.1) |
| **B9 independently-verified** | 1.0 | 1.0 | ≤ ε for all (v3.1) |

- **v3.0** locks the deterministic scripted core (Tier 1: the two left/middle
  columns), asserted by exact equality.
- **v3.1** locks the LLM ladder (Tier 2: the right column), asserted as
  directional hypotheses + Wilson CIs, once parameters are pinned and
  source-verified.

This deviates *intentionally* from the original kickoff brief, which scoped the
LLM as an off-core appendix demo. External review (4 rounds) endorsed promoting
it to a Tier-2/v3.1 measurement **provided** the grader stays deterministic and
the LLM parameters are pre-registered separately. See `threat-model-v3.md` §3.3,
§7.2.

---

## 1. Phases

Each phase lists deliverables, the success gate, and status. Phases lock-step
with the staged pre-registration (v3.0 scripted core → v3.1 LLM ladder).

### P0 — Pre-registration & scaffold  ·  **STATUS: substantially done (pending commit)**
- [x] v2 frozen (tag `v2.0.1`, DOI).
- [x] `threat-model-v3.md` — merged design, pre-registered, **SHA-256 locked**.
- [x] `source-lock-v3.md` — primary-source receipts (§A verified; §B pending),
      **locked**.
- [x] `v3/tests/test_threat_model_v3_locked.py` — lock guard (mirrors v2; 4 tests green).
- [x] `Documents/README.md` — v3 rows added.
- [ ] **Commit** the above (manual; commands in the session / below).
- **Gate:** lock test green; both `.sha256` present. ✅

### P1 — v3 package scaffold + transport + completion-record module
- [ ] `v3/aegis_at_v3/` package mirroring `v2/aegis_at_v2/` layout (see §3).
- [ ] `transport/mcp_adapter.py` — **thin** MCP-shaped wrapper enforcing
      token-passthrough-forbidden + RFC 8707 audience binding. Transport only;
      B1–B5 credential/verification path stays byte-identical (`threat-model-v3.md`
      §6.2, §1.2).
- [ ] `completion/completion_record.py` — the minimal benchmark abstraction
      (`asserted_executor`, `attestation_source ∈ {self_reported, tool_verified}`,
      `attester_id`, `signature`); `threat-model-v3.md` §5.1.
- [ ] `v3/scripts/check_v3.sh` (mirror `check_v2.sh`): INV greps (INV-2/INV-3),
      lint, format, lock test, core tests.
- [ ] `v3/tests/conftest.py` (mirror v2) — adds **both** `v3` and `v2` roots to
      `sys.path` so `aegis_at_v3` can import `aegis_at_v2` (**settled: import v2,
      do not vendor** — strongest INV-6; a root `pyproject.toml` is the cleaner
      alternative if sibling-import proves fragile).
- [ ] Minimal B1–B5 regression harness over the MCP-shaped boundary (just enough
      wiring to run the inherited v1/v2 curve through the adapter) — gives the gate's
      regression check a home in P1 (review: P1 gate vs. deliverables).
- [ ] **Tracked follow-up (review #4):** update `CHECKLIST.md` to make the spec
      version-specific (v3 spec governs v3 modules).
- **Gate:** `check_v3.sh` exits 0; transport adapter has a test proving a passed-through
  token is rejected; B1–B5 reproduce the v2 curve under the MCP-shaped boundary
  (regression gate, mirrors `threat-model-v2.md` §3.1).

### P2 — B8/B9 scripted core (Tier 1 — THE headline)

> **Design reviewed by 4 external agents (2026-06-20); all confirmed it — no
> locked prediction challenged.** Deltas folded into the slices below. One dissent
> (add `asserted_principal_chain`/`asserted_scope` to the §5.1 record) was
> **rejected**: it edits the locked schema (§10) and widens the adversary past the
> declared-scoped executor-attribution finding (§3.1, §9 L13). Its legitimate
> concern — "is the opaque-credential isolation rigged?" — is answered by the
> non-locked JWT sensitivity check (Slice E), not a schema change.

**Design (settled).** Contain executes under a B2-shaped **opaque per-agent
credential**, so ground truth carries `principal_chain = None` and `scope` is
observed — the **only** field the attestation source can move is the executor
(`claimed_actor`). This is a deliberate experimental control isolating the
executor-attribution axis; a JWT variant (where chain/scope could also be
misreported) is Slice E / future work. The completion is injected **parent-side**
(scripted, deterministic — the v2 token-lift pattern, §4.2a) under a **fixed**
Contain Ed25519 key (§8.6). `score_ais` is reused byte-for-byte; the audit builder
mirrors the GT record shape exactly. **MCP: MIN** — P2 cells do **not** re-route
through `MCPBoundary`; P1 already proved the transport transparent and
executor-free (§6.2/§6.3). Separation of concerns is stated in the paper.

**Slices** (each: code → `ImportantQuestions` note → tests → review → commit):
- [x] **A — honest checkpoint (HARD GATE, §7.5).** Honest seat only, **no colluder
      code**. Audit builder mirrors GT exactly (`claimed_scope =
      scope_for_command(command)`, `claimed_principal_chain = None`). Assert
      **B8 honest = 1.0 AND B9 honest = 1.0** (T1+T2) before proceeding; if either
      ≠ 1.0, halt and triage — the harness is wrong, not the finding.
- [x] **B — colluder + grid + determinism.** `script-colluding` body
      (`asserted_executor=enrich`, `attester_id=contain`, valid sig under Contain's
      own key). Assert B8 = 0.0 / B9 = 1.0; full grid == locked on T1+T2; scorer
      defect is **actor `field_mismatch`** (not a missing record); B8 does **not**
      cross-check `attester_id==asserted_executor`. Fixed key + fixed clock →
      byte-identical `(audit, truth)` records across runs (§8.6). **action_id
      binding**: completion bound to the executed action; wrong-`action_id` → fail
      loud (negative test).
- [x] **C — non-circularity (SEPARATE file, review #5, §8.4).** **C1:** production
      B9 with no verifier observation **raises** (fail loud — never silently
      degrade to B8; Rule 12). **C2:** a test-only degraded resolver that falls back
      to `asserted_executor`, run through the **full** colluding sweep → AIS < 1.0
      with `mismatched_fields==["actor"]`, `claimed_actor==enrich`,
      `true_actor==contain`, `denominator==1`. End-to-end, not a unit test.
- [ ] **D — INV-4 (end-to-end, §8.5).** Under collusion: `true_actor==contain`; GT
      records carry **none** of `{asserted_executor, attester_id,
      attestation_source, signature}`; recorder input path unchanged;
      `claimed_actor==enrich` only on the audit side.
- [ ] **E — JWT sensitivity (NON-LOCKED).** Re-run B8/B9 colluding over a JWT base
      credential; assert the actor finding survives (B8 → AIS < 1.0, B9 → 1.0); if
      chain/scope also move, report separately so actor stays the load-bearing
      field. Answers the "opaque-cred is rigged" objection with data.
- **Gate:** measured Tier-1 grid == locked prediction exactly
      (`threat-model-v3.md` §7.1: B8 = 1.0/0.0, B9 = 1.0/1.0 on T1 and T2). A
      contradiction is a **finding** (INV-7), not coded around.

### P3 — §B source verification → B6/B7 (comparative breadth)
- [ ] Source-verify (INV-8) the `source-lock-v3.md` §B items: **RFC 8705**
      (mTLS executor-attribution semantics) and **A-JWT**
      (`draft-goswami-agentic-jwt` — is the execution assertion verified at
      execution, or self-asserted?), plus completion-record field semantics.
- [ ] Add the verified facts to a `source-lock-v3.1.md` (its own lock).
- [ ] Pre-register B6/B7 predictions in `threat-model-v3.1.md` (only after
      verification — they carry **no** locked value today, `threat-model-v3.md`
      §7.1/§9 L11).
- [ ] Implement B6 (mTLS-bound) and B7 (A-JWT) as config flags.
- **Gate:** B6/B7 measured == their newly-locked predictions; inertness holds
      (§7.4) or the deviation is reported as a finding.

### P4 — v3.1 LLM ladder (Tier 2 — the capability curve)
- [ ] Pin + source-verify the model list (provider/version/date, training cutoffs
      preceding the scenario), N, ε, prompts (system/honest/attack), and
      refusal/malformed/retry/availability policy — `threat-model-v3.md` §7.2.
- [ ] Lock `threat-model-v3.1.md` (Tier-2 parameters) **before** any LLM run.
- [ ] LLM adapter in the executor seat; completion submitted via a **structured
      tool call** (injection must manipulate the `asserted_executor` argument).
- [ ] Run the ladder under B8 and B9; report evasion rate + Wilson CIs; evaluate
      H1–H4 (`threat-model-v3.md` §7.2).
- [ ] Optional, off-by-default: real-time detectability monitor (§7.2.1).
- **Gate:** H2 holds (B9 ≤ ε for every model — the knockout); H1/H3 reported
      honestly (a flat curve is a finding, not a failure). LLM cells statistically
      (not byte-) reproducible (§8.6).

### P5 — Paper v3
- [ ] `Documents/Paper/v3/aegis-at-v3.tex`, arXiv-ready, figures from the live
      harness (v1/v2 discipline: "a plotted number cannot diverge from the code").
- [ ] Cite the 2026 frontier (AIP/PEDIGREE/HDP/MCP + NIST/OWASP/Otsuka) per the
      verified receipts; frame as methodology over the landscape, never "draft X
      is broken."
- **Gate:** every AIS/rate in the paper asserted by a test against the locked
      prediction/hypothesis.

---

## 2. Reuse map (INV-6 — config flags over one codebase, not a fork)

**Recommended approach (P1 decision):** `aegis_at_v3` *depends on / imports*
`aegis_at_v2` for the B1–B5 path, so that path stays **byte-for-byte** v1/v2
(strongest INV-6); v3 adds only the new layer. (Alternative — vendoring — is a
weaker INV-6 story; flagged for the P1 decision.)

| v2 module | v3 treatment |
|---|---|
| `auth/tokens.py`, `auth/dpop.py` | **reuse as-is** (B1–B5 path) |
| `harness/recorder.py` | **reuse as-is** → becomes B9's `tool_verified` verifier (the keystone reuse) |
| `harness/scorer.py` | **extend** — AIS unchanged; add attestation-source selection (read claimed actor from completion (B8) vs verifier (B9)) |
| `harness/sweep.py` | **extend** — add B8/B9 + the adversary adapter |
| `harness/agent_proc.py`, `agent_bodies.py` | **extend** — scripted colluder body (P2); LLM seat (P4) |
| `harness/stochastic.py` | **reuse** — Wilson CIs / adaptive N for the v3.1 LLM rates |
| `harness/tamper_log.py` | reuse (B4) |
| `orchestrator/`, `policy/scope_map.py`, `tools/siem_action.py` | reuse (INV-3: tool stays `siem_action`) |
| `topologies/` | reuse (T1, T2) |
| — | **NEW:** `transport/mcp_adapter.py`, `completion/completion_record.py`, adversary adapter |

---

## 3. Proposed v3 directory layout (mirror v2)

```
v3/
├── aegis_at_v3/
│   ├── __init__.py
│   ├── completion/completion_record.py   # NEW (§5.1)
│   ├── transport/mcp_adapter.py          # NEW (§6)
│   ├── harness/                          # extends v2: sweep, scorer, adversary adapter
│   └── (auth/orchestrator/policy/tools/topologies via import from aegis_at_v2)
├── scripts/check_v3.sh
└── tests/
    ├── conftest.py
    ├── test_threat_model_v3_locked.py    # DONE
    ├── test_mcp_transport.py             # P1
    ├── test_completion_record.py         # P1
    ├── test_b8_b9_scripted.py            # P2
    └── test_b9_non_circularity.py        # P2 (separate test, review #5)
```

---

## 4. Deferred to v4 (named, not dropped)
- Cross-org / multi-trust-domain delegation.
- `peer_verified` / `human_verified` tiers (PEDIGREE §8.2.3) — v3 measures only
  `self_reported` (B8) and `tool_verified` (B9).
- Other adversary variants as their own studies: principal laundering, key
  forgery, scope-attenuation bypass.
- Real-telemetry attack frequencies; formal verification of recorder independence;
  emergent (non-injected) deception.

## 5. Open verification debt (blocks P3/P4, tracked in `source-lock-v3.md` §B)
- RFC 8705 (mTLS) executor-attribution semantics → B6.
- A-JWT execution-assertion verification model → B7.
- Completion-record field semantics (signer ↔ asserted-executor decoupling) → firms
  up the B8 abstraction beyond the verified `self_reported` property.
- PAuth / Otsuka / NIST wording for the paper's positioning.

## 6. Tracked follow-ups from review
- **P1:** `CHECKLIST.md` → make the spec reference version-specific (review #4).
- **P2:** B9 non-circularity guard as a **separate** test (review #5, §8.4).

---

## 7. Conventions (inherited; binding)
- Commits are **manual** (the user runs all git). Claude prepares and provides commands.
- INV-1..8 (CLAUDE.md) are binding; the mechanical gate (`check_v3.sh`) enforces
  INV-2/INV-3 by grep, plus lint/format/tests.
- Pre-register before measuring (INV-7); a contradiction is a finding (INV-7), never
  coded around. Verify domain claims at primary source (INV-8), never paraphrase.