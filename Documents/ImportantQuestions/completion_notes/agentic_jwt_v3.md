# Agentic JWT Notes (B7) — v3/aegis_at_v3/completion/execution_assertion.py

Working notes for the B7 A-JWT execution-assertion baseline — the **verified
execution-attribution axis**. B7 is P3 comparative-breadth slice 2, built on the
same verified-evidence scaffold as B6 (`mtls_v3.md`).

- **Module:** `v3/aegis_at_v3/completion/execution_assertion.py` (+ the B7 branch in
  `v3/aegis_at_v3/harness/completion_sweep.py`).
- **Spec:** `threat-model-v3.0.1.md` §A2 (prediction + caveats L21), §A5 (grid).
- **Sources (read at source, INV-8):** `source-lock-v3.0.1.md` §A6 — A-JWT
  (`draft-goswami-agentic-jwt-00` / arXiv:2509.13597) abstract, §5 Anchors A3/A6,
  §3 `executed_by`/`cnf`, §4 threats T7/T10/T11.
- **Tests:** `v3/tests/test_b7_agentic_jwt.py`.
- **Status:** implemented; measured grid **== the locked 1.0 / 1.0** on T1+T2.

> **The load-bearing question (INV-7).** v3.0.1 pre-registered **B7 AIS = 1.0 /
> 1.0**. This code measures it; if it were not 1.0/1.0 that is the finding, reported
> not patched. It measures 1.0/1.0.

---

## What B7 is and why it recovers

A-JWT binds each action to an execution assertion: the executing agent signs
`executed_by` with a **per-agent proof-of-possession key**, and the Resource Server
verifies that signature **at execution** (Anchor A6). v3 models exactly that: the
verifier checks the assertion's signature against the PoP key **registered for the
named agent**. So a colluder (Contain) can only mint a *verifiable* assertion naming
**itself** — to name Enrich it would have to sign with Enrich's key, which it does
not hold (§4.2). Therefore `executed_by` is **verified, not self-asserted**, and B7
recovers.

B7 is **inert under the colluder** (§A4): the colluder still self-reports a false
completion (Enrich) exactly as in B8, but B7 reads the verified assertion, not the
completion, so the lie never reaches the audit. Honest = colluding = 1.0.

**Recovery does NOT rest on the (copyable) checksum** — A-JWT's own threat model
admits T1 (impersonation by replicating code for an identical checksum). The
load-bearing anchors are **A6 (PoP, here)** and **A3 (no in-process impersonation,
provided by the OS process boundary)** — exactly the §A2 reading.

---

## Locked / deliberate decisions (the 4-agent P3 review)

### Separate `ExecutionAssertion` object — the locked completion schema is untouched
B7 does **not** add a field to `CompletionRecord` (which is locked, v3.0). The
review was unanimous: a separate object. The colluder emits the SAME `self_reported`
completion lie as B8; B7 resolves identity from an independent, verified
`ExecutionAssertion`. (Mirrors B6's "separate verified-evidence axis" decision.)

### The resolver reads the VERIFIED ASSERTION, never ground truth (the "decorative" trap)
B7's `claimed_actor` comes from `verify_execution_assertion(...)` (the A6 signature
check returning `executed_by`), **not** from the recorder's `true_actor`. If it read
ground truth it would collapse into B9 and the PoP check would be decorative. The
assertion observation is an independent path that *happens* to agree with the
recorder — not copied from it. (Reuses `resolve_via_verified_evidence`, shared with
B6.)

### A3 ("no in-process impersonation") = the OS process boundary (review, Agent 2)
A-JWT's A3 is an *in-process* stack/object shim. AEGIS-AT runs agents as separate OS
processes (the v2 kernel), so cross-agent impersonation is structurally blocked by
the **PID registry (INV-4)** — the assertion is produced inside the executor's own
process. This is a **stronger** independence anchor than A-JWT's software shim
(`threat-model-v3.0.1.md` §A2 caveat 2). Documented, not silently assumed.

### Minimal model, honest about fidelity (Q1, L21)
No live A-JWT shim/TEE and no endorsement of A-JWT's unvalidated PoC "100%". Ed25519
PoP (matches `dpop.py` and A-JWT's per-agent keys), deterministic (RFC 8032). The
per-agent PoP key seeds are DISTINCT from B6's cert keys and the completion key (an
agent holds several keys for several purposes).

### Don't edit v2 (Q4, INV-6)
B7 lives entirely in v3, reusing v2 by import. The B7 branch in `run_cell` leaves the
B8/B9 **and** B6 paths byte-identical (`test_b7_addition_leaves_locked_grids_byte_identical`).

---

## Non-circularity — B7's 1.0 is EARNED (review Q6, mirrors B9 §8.4)

1. **Verification disabled → fail loud.** `run_cell("B7", verifier_enabled=False)`
   raises `VerifiedEvidenceUnavailableError` — never a silent fallback.
2. **Degraded fallback → 0.0.** An *injected* degraded resolver that falls back to
   the self-report yields **AIS 0.0** (Enrich wins) — so removing the assertion
   verification breaks B7. Its 1.0 is earned.
3. **Active rejection (A6).** `verify_execution_assertion` of an assertion naming
   Enrich but signed by Contain **raises** `AssertionVerificationError` — the
   colluder's cross-agent attribution attempt is rejected. This is the load-bearing
   fidelity test (`test_cross_agent_assertion_is_rejected`).

---

## INV walkthrough

- **INV-4:** ✓ — the assertion is the AUDIT's attribution source; ground truth is
  still the recorder's PID-registry observation. The assertion verification never
  feeds `true_actor`.
- **INV-5:** ✓ — the colluding completion is a valid self-report under Contain's own
  key; B7 does not read it. No miscoded component.
- **INV-6:** ✓ — B7 is a `run_cell` branch + one new v3 module reusing v2 by import;
  B8/B9 and B6 byte-identical; v2 untouched.
- **INV-7:** ✓ — 1.0/1.0 locked in v3.0.1 §A2/§A5 before this code; the grid test
  asserts equality.
- **INV-8:** ✓ — A-JWT A3/A6/`executed_by`/threats read at source
  (`source-lock-v3.0.1.md` §A6); the PoP model avoids overclaiming (no PoC "100%").

---

## Test map (Rule 9 — tests encode the WHY)

| Test | Property it pins |
|---|---|
| `test_assertion_is_deterministic` | §8.6: byte-identical signature run-to-run |
| `test_honest_assertion_verifies_to_its_executor` | A6: signed-by-self verifies → executor |
| `test_cross_agent_assertion_is_rejected` | **A6 active rejection: colluder cannot assert Enrich** |
| `test_enrich_pop_key_is_distinct_from_contain` | §4.2 basis: Contain lacks Enrich's PoP key |
| `test_unknown_agent_fails_loud` | no silent default |
| `test_b7_is_one_on_both_seats` | §A2: B7 = 1.0 honest AND colluding, T1+T2 |
| `test_b7_grid_matches_locked_prediction` | §A5: measured grid == locked 1.0/1.0 (INV-7) |
| `test_b7_colluding_completion_is_a_valid_lie_but_inert` | INV-5 + §A4: valid lie, B7 records Contain |
| `test_b7_fails_loud_when_verification_disabled` | non-circularity: no silent fallback |
| `test_b7_degraded_fallback_to_self_report_is_zero` | non-circularity: 1.0 is EARNED |
| `test_b7_is_byte_identical_across_runs` | §8.6 determinism end-to-end |
| `test_b7_addition_leaves_locked_grids_byte_identical` | additive: B8/B9 AND B6 grids unchanged |

---

## Cross-references

- `threat-model-v3.0.1.md` §A2 (prediction + L21 caveats), §A5 (grid).
- `source-lock-v3.0.1.md` §A6 — A-JWT receipts.
- `mtls_v3.md` — B6, the sibling verified-evidence axis (same scaffold).
- `dpop_v2.md` — B5 DPoP, the PoP sender-constraint B7's A6 parallels.
- `completion_sweep_v3.md` — the sweep B7 extends (the B7 branch + `emit_b7_grid`).
- `completion_record_v3.md` — the self-report B7 is inert to.
- **A-JWT:** `draft-goswami-agentic-jwt-00` / arXiv:2509.13597 (local source under
  `Documents/ResearchPapers/Agentic_JWT_SecureDelegationarXiv-2509.13597v1/`).
- Recover-cluster now complete in code: {B5 DPoP, B6 mTLS, B7 A-JWT, B9 verifier};
  failure isolated to B8.
