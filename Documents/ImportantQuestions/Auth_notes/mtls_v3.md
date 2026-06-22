# mTLS Notes (B6) — v3/aegis_at_v3/auth/mtls.py

Working notes for the B6 mTLS certificate-bound baseline — the **cert-layer
analog of B5 DPoP** (`dpop_v2.md`). B6 is P3 comparative-breadth slice 1.

- **Module:** `v3/aegis_at_v3/auth/mtls.py` (+ the B6 branch in
  `v3/aegis_at_v3/harness/completion_sweep.py`).
- **Spec:** `threat-model-v3.0.1.md` §A1 (prediction + caveats L20), §A5 (grid).
- **Sources (read at source, INV-8):** `source-lock-v3.0.1.md` §A5 — RFC 8705 §1,
  §3, §3.1.
- **Tests:** `v3/tests/test_b6_mtls.py`.
- **Status:** implemented; measured grid **== the locked 1.0 / 1.0** on T1+T2.

> **The load-bearing question (INV-7).** v3.0.1 pre-registered **B6 AIS = 1.0 /
> 1.0** (honest / colluding). This code measures it. If it were not 1.0/1.0, that
> is the finding — reported, not patched (INV-7). It measures 1.0/1.0.

---

## What B6 is and why it recovers

RFC 8705 binds an access token to an X.509 client certificate: the token carries
`cnf.x5t#S256` (the cert thumbprint), and **the resource MUST verify that the
presented client cert matches the cert associated with the token** (§3, NORMATIVE,
quoted in `source-lock-v3.0.1.md` §A5). Identity is then the verified cert's
subject. This is a sender-constraint **verified at access** — the same shape as
B5 DPoP (key possession verified at access). A colluding executor cannot present
**another agent's** certificate (cross-credential forgery is out of scope, §4.2),
so the cert-verified identity tracks the true executor → **B6 recovers**.

B6 is therefore **inert under the colluder** (§A4): the colluder still self-reports
a false completion (Enrich) exactly as in B8, but B6 reads the cert, not the
completion, so the lie never reaches the audit. Honest = colluding = 1.0.

---

## Locked / deliberate decisions (the 4-agent P3 review)

### Minimal model, but a REAL DER certificate (Q1 fidelity, review-decided)
No live TLS stack — the prediction is for the *mechanism* graded by AEGIS-AT's
recorder (L20). BUT the thumbprint is computed over the **actual DER X.509 cert
bytes**, exactly as RFC 8705 §3.1 defines — **not** a JWK surrogate. The 4-agent
review split here; the chosen path (real `cryptography.x509` cert) keeps the
`x5t#S256` claim honest (INV-8: don't overclaim). `agent_certificate_der` builds a
deterministic minimal self-signed cert; `x5t_s256` hashes its DER.

### B6 is a SEPARATE verified-evidence axis — the completion schema is untouched
The locked `CompletionRecord` and its `VALID_SOURCES = {self_reported,
tool_verified}` are **not** changed (review #1). B6 does **not** add a `cert_bound`
attestation_source to the completion. Instead the colluder emits the SAME
`self_reported` lie as B8, and B6 resolves identity from a **separate** verified
cert observation (`resolve_via_verified_evidence`). Editing the locked schema was
rejected (it would mutate the v3.0 abstraction).

### The resolver reads the VERIFIED CERT, never ground truth (the "decorative" trap)
B6's `claimed_actor` comes from `mtls.verify_cert_binding(...)` (the §3 match +
subject), **not** from the recorder's `true_actor` (review #1/#3/#4). If it read
ground truth it would collapse into B9 and the crypto would be decorative. The
cert observation is an independent path that *happens* to agree with the recorder
— it is not copied from it.

### Don't edit v2 (Q4, INV-6)
v2 is the published, locked artifact. B6 lives entirely in v3 and reuses v2 by
**import** (the recorder, scorer, kernel via `completion_sweep`). Nothing in
`v2/` changed. The B6 branch in `run_cell` leaves the B8/B9 path byte-identical;
`test_b6_addition_leaves_b8_b9_grid_byte_identical` guards this.

### Determinism (§8.6)
Fixed per-agent key seed (Contain's MATCHES `adversary._CONTAIN_KEY_SEED` — one
identity, two key uses), fixed cert serial + validity, Ed25519 (RFC 8032
deterministic) → byte-identical DER and thumbprint run-to-run.

### Fail loud (Rule 12)
`CertBindingError` on a cert/token mismatch; `UnknownAgentError` on an unregistered
agent; `VerifiedEvidenceUnavailableError` if B6 is asked to resolve with the
verification disabled (it never silently falls back to the self-report);
`run_cell` raises on an unknown baseline.

---

## Non-circularity — B6's 1.0 is EARNED, not structural (review Q6, mirrors B9 §8.4)

Two controls prove the cert verification is load-bearing:
1. **Verification disabled → fail loud.** `run_cell("B6", verifier_enabled=False)`
   raises `VerifiedEvidenceUnavailableError`. Production never degrades silently.
2. **Degraded fallback → 0.0.** An *injected* degraded resolver that falls back to
   the self-report when the cert observation is absent yields **AIS 0.0** (the
   colluder's Enrich wins). So removing/bypassing the cert verification breaks B6
   — its 1.0 is earned by the verification.

And **active rejection**: `verify_cert_binding(enrich_cert, contain_token_cnf)`
raises `CertBindingError` — a token bound to Contain's cert cannot be wielded with
another cert (the cert-layer analog of B5's DPoP lift rejection).

---

## INV walkthrough

- **INV-4 (ground-truth independence):** ✓ — the cert observation is the AUDIT's
  attribution source; ground truth is still the recorder's PID-registry
  observation. The cert verification never feeds `true_actor`. (B6's claimed actor
  derives from the cert; the recorder is wholly separate.)
- **INV-5 (no component misbehaves):** ✓ — the colluding completion is a valid
  self-report under Contain's own key; B6 simply does not read it. No miscoded
  component.
- **INV-6 (config flag over ONE codebase):** ✓ — B6 is a `run_cell` branch + one
  new v3 module reusing v2 by import; B8/B9 byte-identical; v2 untouched.
- **INV-7 (pre-registered):** ✓ — 1.0/1.0 locked in v3.0.1 §A1/§A5 before this
  code; the grid test asserts equality.
- **INV-8 (verify against source):** ✓ — RFC 8705 §1/§3/§3.1 read at source
  (`source-lock-v3.0.1.md` §A5); the real-DER thumbprint avoids overclaiming.

---

## Test map (Rule 9 — tests encode the WHY)

| Test | Property it pins |
|---|---|
| `test_certificate_is_deterministic` | §8.6: byte-identical DER run-to-run |
| `test_certificates_are_per_agent` | the binding distinguishes executors (not vacuous) |
| `test_x5t_s256_is_the_real_der_thumbprint` | RFC 8705 §3.1: thumbprint over real DER, not a JWK |
| `test_cert_subject_is_the_agent_identity` | L20: verified cert → executor identity |
| `test_verify_cert_binding_accepts_matching_cert` | §3 match passes for the bound cert |
| `test_verify_cert_binding_rejects_mismatched_cert` | active rejection: wrong cert → CertBindingError |
| `test_unknown_agent_fails_loud` | no silent default |
| `test_b6_is_one_on_both_seats` | §A1: B6 = 1.0 honest AND colluding, T1+T2 |
| `test_b6_grid_matches_locked_prediction` | §A5: measured grid == locked 1.0/1.0 (INV-7) |
| `test_b6_colluding_completion_is_a_valid_lie_but_inert` | INV-5 + §A4: valid lie, B6 records Contain |
| `test_b6_fails_loud_when_verification_disabled` | non-circularity: no silent fallback |
| `test_b6_degraded_fallback_to_self_report_is_zero` | non-circularity: 1.0 is EARNED (fallback → 0.0) |
| `test_b6_is_byte_identical_across_runs` | §8.6 determinism end-to-end |
| `test_b6_addition_leaves_b8_b9_grid_byte_identical` | additive: locked B8/B9 grid unchanged |
| `test_unknown_baseline_fails_loud` | Rule 12: unknown baseline raises |

---

## Cross-references

- `threat-model-v3.0.1.md` §A1 (prediction + L20 caveats), §A5 (grid).
- `source-lock-v3.0.1.md` §A5 — RFC 8705 receipts.
- `dpop_v2.md` — B5, the access-time sender-constraint B6 parallels.
- `completion_sweep_v3.md` — the sweep B6 extends (the B6 branch + `emit_b6_grid`).
- `completion_record_v3.md` — the self-report B6 is inert to.
- **RFC 8705** (mTLS / certificate-bound tokens).
- Next: B7 (A-JWT) — P3 slice 2, the execution-assertion verified-evidence axis.
