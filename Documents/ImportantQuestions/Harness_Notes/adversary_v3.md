# Adversary adapter (v3) — why it's shaped this way

- **Module:** `v3/aegis_at_v3/harness/adversary.py`
- **Spec:** `threat-model-v3.md` §3.2 (adversary realization) · §4.2a (scripted colluder) · §8.6 (determinism)
- **Tests:** `v3/tests/test_b8_b9_scripted.py`
- **Status:** Slices A–B ship the **honest** and **colluding** seats. The LLM seat is P4.

## What it is
The agent in the "liar seat" — a swappable plug that produces the **signed
completion record** for one adversary realization. The grader (the recorder) is
constant across seats; only the attacker varies (§3.3). This is what lets a
stochastic LLM attacker (P4) be measured by the same deterministic instrument as
the scripted seats.

## Why parent-side scripted injection (Tier-1)
The scripted colluder is injected **from the parent harness**, the same
construction as v2's token-lift / proof-replay stimuli (`threat-model-v2.md` §2).
Consequences:
- **Deterministic** (exercised with probability 1) — Tier-1 cells are exact and
  locked (§7.1).
- **INV-5 preserved** — the colluding executor is the **adversary's locus**, not a
  miscoded component. No system component misbehaves; the harness simply places a
  false-but-validly-signed completion into the audit path.
- **No key crosses the process boundary** — only the opaque action credential goes
  to the executor subprocess; the completion is signed in the parent. Keeps the
  execution path byte-identical to v2's B1/B2.

## Why a fixed Contain key (§8.6)
Contain signs under a **fixed** Ed25519 key (constant seed). Ed25519 is
deterministic (RFC 8032) and the completion payload is canonical JSON, so a
completion record is **byte-identical run-to-run** under a fixed clock — the
Tier-1 determinism the lock depends on.

## Why signer is decoupled from claim (the B8→B9 crux)
The completion's `attester_id` (who signed) is separate from `asserted_executor`
(who it claims ran) — see [`completion_record_v3.md`](../completion_notes/completion_record_v3.md).
- **Honest seat (Slice A):** `asserted_executor == attester_id == Contain` — valid
  signature, **true** claim → honest B8 = 1.0 (§8.1).
- **Colluding seat (Slice B):** `attester_id == Contain` but
  `asserted_executor == Enrich` — valid signature under Contain's **own** key, a
  **false** claim. No cryptographic check fails; only B9's independent verifier
  catches it. The colluder **cannot** sign under Enrich's key (cross-key forgery is
  out of scope, §4.2).

The objection "why not just enforce `attester_id == asserted_executor`?" is
answered by the tiers: that cross-check **is** independent verification — exactly
what `self_reported` (B8) omits and `tool_verified` (B9) supplies. So the
decoupling is not a bug; it **is** the measured gap (§5.1).

## Fail-loud
`make_completion` raises on an unknown seat (no silent default). Slice A
implements `honest` only — a `colluding` request raises until Slice B, keeping the
load-bearing checkpoint (§7.5) provably colluder-free.

## Test map (Rule 9 — tests encode the WHY)
| Test (Slice) | Property it pins |
|---|---|
| `test_honest_completion_signature_is_valid` (A) | honest seat: valid sig, `asserted==attester==Contain` |
| `test_honest_checkpoint_is_one` (A) | honest completion → B8/B9 = 1.0 (§7.5) |
| `test_colluding_completion_valid_under_own_key_false_claim` (B) | valid sig under Contain's key, false `asserted_executor=Enrich` |
| `test_b8_trusts_self_report_without_cross_checking_signer` (B) | B8 trusts the self-report; no `attester==asserted` cross-check |
