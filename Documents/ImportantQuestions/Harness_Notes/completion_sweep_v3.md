# B8/B9 completion-attestation sweep (v3) — why it's shaped this way

- **Module:** `v3/aegis_at_v3/harness/completion_sweep.py`
- **Spec:** `threat-model-v3.md` §5, §7.1 (LOCKED) · §5.3/§8.4 (non-circularity) · §7.5 (checkpoint)
- **Tests:** `v3/tests/test_b8_b9_scripted.py` (Slice A) · `test_b9_non_circularity.py` (Slice C, pending)
- **Status:** Slices A–C (honest checkpoint + colluder, locked grid, determinism, action binding, B9 non-circularity). INV-4 end-to-end (D), JWT sensitivity (E) pending.

## What it is
The headline measurement. EXTENDS the v2 sweep by **import** (INV-6): reuses v2's
process kernel, recorder, `siem_action`, and `score_ais` byte-for-byte, adding
**only** the completion-record audit layer. One action, two defenses (B8/B9), a
swappable adversary seat:

```
EXECUTE  Contain runs the action (opaque per-agent cred) -> recorder writes GT
         from the OS PID registry (INV-4).
ATTEST   adversary.py emits a signed completion (honest, or colluding: a false
         asserted_executor=Enrich within Contain's own key — valid sig, false claim).
RESOLVE  audit claimed_actor by attestation source:
           B8 self_reported -> completion.asserted_executor
           B9 tool_verified -> the verifier's observation (the recorder)
SCORE    score_ais(audit, ground_truth)   # v2 scorer, unchanged
```

## Four design decisions the 4-agent review validated

### 1. Opaque per-agent credential = the isolation control (review #3)
Contain executes under a B2-shaped apikey, so ground truth carries
`principal_chain = None` and `scope` is derived from the *observed* command. The
audit record mirrors that shape, so the **only field the attestation source can
move is the executor (`claimed_actor`)**. B8-colluding therefore fails *purely* on
executor attribution — the sharpest possible isolation, and the most conservative
claim (AIS = 0.0 even when one field can move). A reviewer's "you rigged it by
suppressing chain/scope" is answered with **data**, not a schema change, by the
non-locked **JWT sensitivity check (Slice E)**. The dissent to add
`asserted_principal_chain`/`asserted_scope` to the §5.1 record was **rejected**:
it edits the locked schema (§10) and widens the adversary past the
declared-scoped executor-attribution finding (§3.1, §9 L13).

### 2. B9 fails loud — never a silent fallback (review #1; Rule 12)
`resolve_claimed_actor` for B9 (`tool_verified`) RAISES `VerifierUnavailableError`
if there is no verifier observation. It does **not** silently return
`asserted_executor`. A silent fallback would degrade B9 into B8 and make B9's 1.0
**vacuous** (the exact §5.3 risk). Production B9 cannot do this; the **Slice C
control** constructs the degraded fallback *deliberately* (a test-only path) to
prove B9's 1.0 is **earned** by the verifier, not structural.

### 3. The audit builder mirrors ground truth EXACTLY
`_build_audit_record` sets `claimed_scope = scope_for_command(command)` (the
verifier's own observation, not an agent field) and `claimed_principal_chain =
None` (opaque-cred audits carry no chain — matches the recorder). If it invented a
chain or a different scope, **honest B8/B9 would fail for the wrong reason** and
the §7.5 checkpoint would mis-fire. `test_audit_record_mirrors_ground_truth_shape`
pins this.

### 4. The non-circularity seam (realized in Slice C)
`run_cell` exposes two test seams — `verifier_enabled` (disable the verifier) and
`audit_resolver` (inject a degraded resolver that falls back to
`asserted_executor`). `tests/test_b9_non_circularity.py` drives both END-TO-END
through the full sweep: real verifier → 1.0; verifier disabled → fails loud; audit
falls back to the self-report → 0.0. B9's verifier observation and ground truth
share the process-boundary observation point (§5.3) — legitimate *because* this
control shows that removing/bypassing the verifier breaks B9.

## Fail-loud guards (no silent defaults — Rule 12)
- **`action_id` binding** (`CompletionBindingError`): the completion must attest
  THE executed action; a completion for another action must never be paired in by
  timestamp. Slice B adds the wrong-`action_id` negative test.
- **Signature check** (`InvalidCompletionSignatureError`): the audit verifies the
  completion under Contain's own key. Every scripted seat signs validly (§4.2
  forbids cross-key forgery), so a failure here is a *harness bug*. This makes
  INV-5 concrete: the crypto check **passes**, yet B8 still records the wrong actor.
- **unknown `attestation_source`** (`ValueError`, B+C review): `resolve_claimed_actor`
  raises on any source that isn't `self_reported`/`tool_verified` — never silently
  defaults to the self-report.
- **unknown `topology`** (`ValueError`, B+C review): `run_cell` rejects an
  unregistered topology, so the inert label still names a real T1/T2 (§7.1).
- The test seams (`completion_action_id`, `audit_resolver`, `verifier_enabled`) are
  **keyword-only**, so a degraded path can't be reached by a positional argument.

## INV-4 (the instrument's credibility)
Ground truth is written by the v2 recorder from the kernel PID registry. The
completion record is built **parent-side, after execution**, and is **never**
passed into the recorder's input path. The false `asserted_executor` cannot reach
`true_actor`. Slice D asserts this end-to-end (GT carries none of
`{asserted_executor, attester_id, attestation_source, signature}`).

## Topology
`topology` is a **label only**: the opaque-cred audit path has no re-delegation
chain, so B8/B9 are topology-independent by construction (like B5). The grid test
asserts identical results on T1 and T2 (§7.1) — a divergence would be a finding.

## Scope discipline
- Audit/attestation layer only; B1–B5 credential semantics unchanged (INV-6).
- **MCP: MIN** — P2 cells do not re-route through `MCPBoundary`; P1 already proved
  the transport transparent and executor-free (§6.2/§6.3). Separation of concerns,
  not an omission.

## Test map (Rule 9 — tests encode the WHY)
| Test (Slice) | Property it pins |
|---|---|
| `test_honest_checkpoint_is_one` (A) | §7.5/§8.1: honest B8 **and** B9 = 1.0 on T1+T2 |
| `test_audit_record_mirrors_ground_truth_shape` (A) | actor is the only movable field (#3) |
| `test_honest_completion_signature_is_valid` (A) | crypto path sound before the colluder |
| `test_grid_matches_locked_prediction` (B) | §7.1: grid == locked (B8=1.0/0.0, B9=1.0/1.0) on T1+T2 |
| `test_b8_colluding_defect_is_actor_only` (B) | B8=0.0 is one actor field_mismatch, not a missing record |
| `test_b9_recovers_under_collusion` (B) | §8.4: B9 reads the verifier → 1.0 under the same lie |
| `test_scripted_cell_is_byte_identical_across_runs` (B) | §8.6: determinism (fixed key + clock) |
| `test_wrong_action_id_fails_loud` (B) | action binding: an unbound completion fails loud |
| `test_b9_earns_its_one_via_the_verifier` (C) | positive control: real verifier → 1.0 (claimed = true executor) |
| `test_b9_fails_loud_when_verifier_disabled` (C) | §8.4: no verifier → raises (no silent degrade to B8) |
| `test_b9_fails_if_audit_falls_back_to_self_report` (C) | §8.4: fallback to self-report → 0.0 (B9's 1.0 is earned) |
| INV-4 end-to-end (D) | §8.5: no completion field reaches ground truth |
| JWT sensitivity (E, non-locked) | the actor finding survives a JWT base credential |
