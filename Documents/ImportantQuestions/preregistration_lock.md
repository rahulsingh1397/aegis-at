# Pre-Registration Lock — what test_threat_model_v2_locked.py actually does

You asked for this one because it's confusing. Here is the plain version,
then the why, then the exact mechanics.

Implementation: `v2/tests/test_threat_model_v2_locked.py`.
Locked file: `Documents/ThreatModel/ThreatModelv2/threat-model-v2.md`
(plus `threat-model-v2.1.md` amendment, same directory).
Lock records: `threat-model-v2.sha256` and `threat-model-v2.1.sha256` (same dir).

---

## The one-sentence version

It is a tripwire: it computes a fingerprint of `threat-model-v2.md` and
checks it against a saved fingerprint, so that **if anyone edits the
predictions, the test suite fails** — proving the predictions were written
*before* the code that measures them, not adjusted afterward to match the
results.

---

## Why this exists (the scientific point)

The entire credibility of AEGIS-AT rests on **pre-registration**: every
predicted number (B5 AIS = 1.0, B4 LIS = 1.0, the T2 curve, the stochastic
CI cells) is committed to writing *before* the code that produces those
numbers is written. That is the difference between a benchmark and a
demo — a demo tunes the claim to fit the result; a benchmark states the
claim first and reports whatever the measurement shows, even when it
contradicts the claim (INV-7, Rule 12).

In v1, pre-registration was enforced only by discipline and git history —
"trust that we wrote the threat model first." A skeptical reviewer has to
take that on faith. v2 makes it **mechanical**: the prediction file is
cryptographically frozen, and the CI gate fails the moment it changes. Now
"the predictions predate the measurement" is not a promise — it's a build
invariant anyone can re-run.

---

## How it works (the mechanics, step by step)

A SHA-256 hash is a fixed-length fingerprint of a file's bytes. Change one
character and the fingerprint changes completely. The scheme is just
"record the fingerprint once; re-check it forever":

1. **The lock file** `threat-model-v2.sha256` holds the recorded
   fingerprint — a 64-character hex string — computed once when the
   predictions were finalized.

2. **The test** (`test_threat_model_v2_hash_matches_lock`) recomputes the
   fingerprint of `threat-model-v2.md` right now and compares it to the
   recorded one.
   - Match → predictions are unchanged → test passes.
   - Mismatch → the file was edited → test **fails the build**, with a
     message telling you the file drifted from its lock.

3. **A second test** (`test_threat_model_v2_exists`) just asserts both
   files are present, so the lock can't be silently deleted.

### The one subtlety: line endings (`CRLF → LF`)

You're on Windows, which saves files with `\r\n` (CRLF) line endings;
Linux/CI uses `\n` (LF). The *same* document would hash *differently* on
the two systems purely because of invisible line-ending bytes — and the
test would fail for a reason that has nothing to do with the predictions.

So before hashing, the test normalizes: `read_bytes().replace(b"\r\n",
b"\n")` (test file line 28). It strips the Windows `\r` so the hash is
computed over LF-only bytes on every platform. **Consequence you must
know:** the recorded hash in the `.sha256` file is the **LF-normalized**
hash. If you ever regenerate it, you must hash the LF-normalized bytes the
same way, or the gate will reject a file you didn't meaningfully change.

---

## The rule this enforces, and how to change a prediction legitimately

**You do not edit `threat-model-v2.md` to change a prediction.** The lock
is designed to make that fail. If a prediction genuinely needs to change
(say B5 turns out not to be 1.0 and you want to re-register a revised
hypothesis), the procedure is:

> Add a **new** file `threat-model-v2.1.md` with its own lock
> (`threat-model-v2.1.sha256`). Never edit the frozen one.

This preserves the original prediction as a permanent, timestamped record
— so the history of "what we predicted, then what we learned" stays
auditable. A contradicted prediction is a *finding to report*, not a line
to quietly overwrite (INV-7).

---

## If the gate ever fails — diagnosing it

- **You edited the threat model on purpose** → don't "fix" the hash;
  follow the `v2.1` procedure above. The gate did its job.
- **You didn't touch the predictions but it still fails** → almost always
  line endings. Confirm the recorded hash was computed over LF-normalized
  bytes. (This is why the normalization exists; if a tool rewrote the file
  with different whitespace, that counts as a change.)
- **The file is missing** → `test_threat_model_v2_exists` caught a deleted
  lock or prediction file.

To compute the current LF-normalized hash by hand (matches the test):

```python
import hashlib, pathlib
b = pathlib.Path("Documents/ThreatModel/ThreatModelv2/threat-model-v2.md").read_bytes()
print(hashlib.sha256(b.replace(b"\r\n", b"\n")).hexdigest())
```

As of the Phase 4 commit this prints
`77000c9771b71ea9502a0e01cd97b4a17fdef22844ce92830a18c60abb9283ae`, which
matches the lock — i.e. the predictions are intact.

---

## Cross-references

- **threat-model-v2.md §10** — the change-discipline section this test
  enforces.
- **CLAUDE.md INV-7** — pre-registered predictions; contradictions are
  findings.
- **v1 AEGIS-AT_Reference.md §II.8** — "every AIS value is a pre-registered
  hypothesis"; this test is the v2 mechanization of that sentence.
- **v2/tests/test_threat_model_v2_locked.py** — the gate itself.
