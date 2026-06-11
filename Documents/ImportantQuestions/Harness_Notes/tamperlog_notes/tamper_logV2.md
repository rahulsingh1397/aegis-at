# Tamper-Evident Log Notes — v2/aegis_at_v2/harness/tamper_log.py

Working notes for the hash-chained tamper-evident log. This is the Phase 4
change that makes **Baseline 4 real**. v1 shipped B4 as an
attribution-only stub (`B4 == B3` by construction, same code path) and
named the hash-chained module as future work; this *is* that module.

Implementation: `v2/aegis_at_v2/harness/tamper_log.py`. Pre-registered in
`threat-model-v2.md §6`. This file is the *why*.

> **The load-bearing insight (§6.3).** B4 LIS = 1.0 AND B4 AIS = 0.0,
> simultaneously. Tamper-evidence cryptographically *preserves* a record;
> it does not make the record *correct*. The wrong actor is committed
> upstream at minting (B3's resolution step), before the log ever sees the
> entry. So a perfect tamper-evident log faithfully preserves the wrong
> answer. That is v1's finding — now backed by a real artifact instead of
> an asserted stub.

---

## What this module is for (and the new metric it serves)

Two separate quantities, deliberately not conflated:

- **AIS** (Attribution Integrity Score) — is the recorded actor correct?
  Owned by `scorer.score_ais`. Unaffected by this module.
- **LIS** (Log Integrity Score, new in v2 §4.2) — is a post-hoc rewrite
  *detected*? Owned by `scorer.score_lis`, fed by this module's `verify`.

A baseline can score LIS = 1.0 (tamper-proof) and AIS = 0.0 (records the
wrong actor) at the same time. Keeping the two metrics orthogonal is the
whole point — a reviewer who conflates "tamper-evident" with "correct"
is exactly who §6.3 is written for.

---

## Mechanism (§6.1)

Each appended entry carries `prev_hash = SHA-256(canonical(entry) ||
prev_hash)` (tamper_log.py:53–58), so any change to a committed entry
breaks the chain from that entry forward. The chain **head** (the latest
hash) is signed by a dedicated Ed25519 logger key held only by the parent
harness (tamper_log.py:85–91) — no agent, the orchestrator, or the tool
holds it (same isolation pattern as the recorder and the DPoP replay
cache). Post-hoc tampering is therefore detectable two ways: the broken
link, and a head signature that no longer matches.

```
entry0 ──hash0=H(c0||GENESIS)──▶ entry1 ──hash1=H(c1||hash0)──▶ ... ──▶ head
                                                                          │
                                                          logger key signs head
```

---

## Locked decisions

### Canonical serialization (sorted keys, tight separators)

`_canonical` (tamper_log.py:41–50): `json.dumps(entry, sort_keys=True,
separators=(",",":"))`. The same logical entry must hash identically
regardless of dict insertion order, or a verifier that rebuilt the dict in
a different order would see a false tamper. Caveat documented in the
docstring: JSON coerces tuples to lists, so callers must not rely on a
tuple/list distinction inside an entry. (The records here — actor, scope,
chain, command, target, timestamp — don't.)

### Genesis is a fixed constant

`GENESIS_HASH = "0"*64` (tamper_log.py:38). A fixed seed means an empty
log has a well-defined, deterministic head, and the first entry's hash is
reproducible. Determinism matters because the whole benchmark is
deterministic-by-construction (INV-7's reproducibility).

### `verify` walks the STORED chain, reports the tamper SITE

`verify` (tamper_log.py:97–129) recomputes each link and compares against
the stored hash, walking forward using the **stored** `hashes[i]` as the
running `prev` (tamper_log.py:121), not the recomputed value. This is the
subtle, deliberate choice: a single in-place edit at index k then reports
as **one** broken link at k (the tamper site), not a cascade of every
entry after k. A verifier holds the stored chain; testing each stored link
against its recomputed value localizes the edit. The first broken index is
the tamper site.

### Head-signature check catches a tamper with no broken link

If `head_signature` is supplied and no link is broken, `verify` also
checks the signature against the logger's public key; a bad signature
flags the log as tampered by returning `[len(entries)-1]`
(tamper_log.py:123–128). This covers the case where an adversary recomputed
the entire chain consistently (so links verify) but cannot forge the
logger's signature over the new head. Two independent detectors, one for
each adversary capability.

### Logger key isolation mirrors the recorder

The logger key is generated inside `TamperEvidentLog.__init__`
(tamper_log.py:69–70) and exposed only as a *public* key for verification
(tamper_log.py:93–95). The private half never leaves the object the parent
harness holds. Same construction as Boundary 5's recorder and the DPoP
replay cache: integrity infrastructure lives in the harness, out of every
component's reach.

---

## How LIS is computed from this (the scorer hand-off)

The harness, per baseline: writes entries via `append`, signs the head,
then **rewrites a committed entry** (the tamper injection), then calls
`verify(head_signature)` → broken indices. `scorer.score_lis(tampered,
detected)` divides detected ∩ tampered by tampered.

- **B4**: has a `TamperEvidentLog`; the rewrite breaks a link; `verify`
  returns it; LIS = 1.0 (§6.2).
- **B1–B3, B5**: no integrity artifact, so `detected_indices` is empty
  while `tampered_indices` is not → LIS = 0.0 **by definition** (§4.2). A
  rewrite is simply undetectable.

See `scorer_notes.md` (v2 addition) for the LIS scoring half.

---

## INV walkthrough

- **INV-1 / INV-2:** N/A — the log stores records; it neither builds nor
  resolves token structure.
- **INV-3 (siem_action naming):** N/A.
- **INV-4 (ground-truth independence):** ✓ and reinforced — the logger key
  is harness-held, no component can forge the head. The log records what
  the tool claimed; it does not read identity from anywhere.
- **INV-5 (no illegitimate behavior):** ✓ — the tamper injection is
  harness-applied test pressure, not component misconduct.
- **INV-6 (baselines as config flags):** ✓ — B4 is "B3 + a
  `TamperEvidentLog` wired in"; the flag is whether the log exists, not a
  forked codebase. Critically, B4 AIS is still measured on the same
  attribution path as B3, which is why B4 AIS = B3 AIS = 0.0.
- **INV-7 (pre-registered):** B4 LIS = 1.0, B1–B3/B5 LIS = 0.0, and B4 AIS
  unchanged at 0.0 are all locked in §6 before this code ran.
- **INV-8 (verify against source):** ✓ — SHA-256 chaining and Ed25519
  sign/verify exercised in `tests/test_tamper_log.py`, including the
  load-bearing asymmetry test (LIS=1.0 ∧ AIS=0.0).

---

## Cross-references

- **threat-model-v2.md §6** — locked LIS/AIS predictions and the §6.3
  asymmetry.
- **scorer_notes.md** (`==== v2 additions ====`) — `score_lis` and the
  AIS/LIS asymmetry from the metric side.
- **v1 AEGIS-AT_Reference.md §II.6 Baseline 4** — the stub this replaces.
- **recorder_notes.md** — the same harness-held-key isolation pattern.
- **tests/test_tamper_log.py** — intact-chain, single-edit-site,
  head-sig-tamper, LIS curve, and the AIS-vs-LIS asymmetry test.
