# B8/B9 completion-attestation sweep (v3) — why it's shaped this way

- **Module:** `v3/aegis_at_v3/harness/completion_sweep.py`
- **Spec:** `threat-model-v3.md` §5, §7.1 (LOCKED) · §5.3/§8.4 (non-circularity) · §7.5 (checkpoint)
- **Tests:** `v3/tests/test_b8_b9_scripted.py` (Slice A) · `test_b9_non_circularity.py` (Slice C, pending)
- **Status:** Slice A (honest checkpoint). Colluder/grid/determinism (B), non-circularity (C), INV-4 (D), JWT sensitivity (E) pending.

## What it is
The headline measurement. EXTENDS the v2 sweep by **import** (INV-6): reuses v2's
process kernel, recorder, `siem_action`, and `score_ais` byte-for-byte, adding
**only** the completion-record audit layer. One action, two defenses (B8/B9), a
swappable adversary seat:

```
EXECUTE  Contain runs the action (opaque per-agent cred) -> recorder writes GT
         from the OS PID registry (INV-4).
ATTEST   adversary.py emits a signed completion (honest now; colluding in B).
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

### 4. The non-circularity seam is built in from Slice A
`verifier_enabled` exists now (default `True`) so Slice C can disable the verifier
end-to-end through the **full sweep** (not a unit test of the `if`). B9's verifier
observation and ground truth share the independent process-boundary observation
point (§5.3) — legitimate, *because* the Slice C control shows removing the
verifier breaks B9.

## Fail-loud guards (Agent-review: action binding)
- **`action_id` binding** (`CompletionBindingError`): the completion must attest
  THE executed action; a completion for another action must never be paired in by
  timestamp. Slice B adds the wrong-`action_id` negative test.
- **Signature check** (`InvalidCompletionSignatureError`): the audit verifies the
  completion under Contain's own key. Every scripted seat signs validly (§4.2
  forbids cross-key forgery), so a failure here is a *harness bug*. This makes
  INV-5 concrete: the crypto check **passes**, yet B8 still records the wrong actor.

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
| colluder grid / determinism / action_id (B) | B8=0.0/B9=1.0; byte-identical; binding fail-loud |
| B9 non-circularity (C) | §8.4: B9 fails loud (C1) + earns its 1.0 (C2) |
| INV-4 end-to-end (D) | §8.5: no completion field reaches ground truth |
| JWT sensitivity (E, non-locked) | the actor finding survives a JWT base credential |
