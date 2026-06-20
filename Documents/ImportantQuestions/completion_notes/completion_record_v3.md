# Completion Record (v3) — why it's shaped this way

- **Module:** `v3/aegis_at_v3/completion/completion_record.py`
- **Spec:** `threat-model-v3.md` §5.1–§5.3 (LOCKED) · `source-lock-v3.md` §A1/§A2/§D
- **Tests:** `v3/tests/test_completion_record.py`

## What it is
The minimal signed "completion block" the 2026 proposals attach to an action
("here's what I did"). v3 reduces it to five fields: `action_id`,
`asserted_executor`, `attestation_source` (`self_reported` | `tool_verified`),
`attester_id`, `signature`.

## Why a benchmark abstraction, not a literal AIP/PEDIGREE schema (L14)
The receipts lock the *trust tiers*, not exact field names — and we explicitly
did NOT verify whether any draft physically separates signer from a named-executor
field (`source-lock-v3.md` §B pending). So v3 rests only on the **verified**
property: `self_reported` performs *no independent verification of the asserted
executor*. Inventing a literal schema would over-claim past the receipts (INV-8).

## Why `asserted_executor` is decoupled from `attester_id`
This decoupling is the whole mechanism. A colluding executor (Contain) can sign a
record **with its own legitimate key** whose `asserted_executor` names a
*different* agent (Enrich); every cryptographic check passes. So:
- **B8 (self_reported):** audit trusts `asserted_executor` → records Enrich →
  wrong actor, AIS = 0 under collusion.
- **B9 (tool_verified):** audit reads the executor from the independent
  process-boundary recorder, ignoring `asserted_executor` → records Contain →
  AIS = 1.

## Why `verify_signature` does NOT enforce asserted_executor == attester_id
Enforcing that equality would itself be *independent verification* — exactly what
`self_reported` omits by definition. The primitive stays neutral: it proves only
that `attester_id` signed the record. The *baseline* (B8 vs B9) decides whether to
trust the self-report or consult the recorder. The "why not just check the signer?"
objection is therefore not a hole — it IS the B8→B9 distinction (§5.1).

## INV-4 boundary
The completion record is **agent-supplied evidence, never ground truth**. The
recorder must never read it for the true executor (INV-4). `verify_signature`
returning True says "validly signed," never "the claim is true."

## Crypto choice
Ed25519 (matches HDP/AIP and v2's `auth/dpop.py`); RFC 8032 signatures are
deterministic → identical inputs give identical bytes (§8.6 determinism).

## Test map (Rule 9 — tests encode the WHY)
| Test | Property it pins |
|---|---|
| `test_honest_record_roundtrips` | honest self-report verifies |
| `test_signature_is_key_bound` | won't verify under another key |
| `test_tamper_breaks_signature` | signature covers all fields |
| `test_colluding_record_has_a_valid_signature` | **the finding:** valid sig ≠ true claim |
| `test_unknown_attestation_source_fails_loud` | fail-loud, no silent default |
| `test_signing_is_deterministic` | §8.6 determinism |
