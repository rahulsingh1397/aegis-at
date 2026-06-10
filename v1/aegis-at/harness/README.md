# Ground-truth recorder + AIS scorer live here. attacks/ holds the Week-2 sibling-impersonation payload.
# harness/ — measurement instrument (not part of the system under test)

| File | Role |
|---|---|
| [`recorder.py`](recorder.py) | Ground-truth recorder (Boundary 5): observes the true executor from the calling thread before the call; never reads the token (INV-4). |
| [`scorer.py`](scorer.py) | AIS metric, defect breakdown, Wilson CI, and `is_non_monotonic(curve)`. |
| [`sweep.py`](sweep.py) | Baseline switch + the canonical §5 attack (`run(baseline)`) + `verify_deterministic` + `emit_curve`. |

The attack is a single function — `sweep.run(baseline)` — not a separate `attacks/`
package. Keeping it one function preserves the one-degree-of-freedom cleanliness.