"""tests/core/test_sweep.py — smoke + curve check for harness/sweep.py.

Distinct from test_baseline_composition.py on purpose: that file mints
credentials inline (independent spec); this one exercises the sweep
module's own _credential_for + run(). If they ever drift, this fails
before emit_curve hides the divergence in a roll-up dict.
"""
from sweep import run, RunResult


def test_run_returns_predicted_curve_across_baselines():
    """The §6 curve: B1=0.0, B2=1.0, B3=0.0, B4=0.0 — non-monotonic, B2
    is the anchor. Same prediction as test_baseline_composition.py, but
    exercising sweep.run() rather than inline test minting."""
    curve = {b: run(b)["result"]["ais"] for b in ("B1", "B2", "B3", "B4")}
    assert curve == {"B1": 0.0, "B2": 1.0, "B3": 0.0, "B4": 0.0}, curve


def test_run_exposes_records_not_just_result():
    """RunResult deviates from harness_notes.md's '-> ScorerResult'
    spec: it also exposes claimed + truth records, so
    verify_deterministic can check record-level determinism on B2
    (which has no defects to embed records in via the ScorerResult).
    Lock that shape here."""
    r = run("B2")
    assert set(r.keys()) == {"baseline", "result", "claimed", "truth"}
    assert r["baseline"] == "B2"
    assert len(r["claimed"]) == 1
    assert len(r["truth"]) == 1


def test_run_fixed_clock_yields_byte_identical_records():
    """Determinism precondition for verify_deterministic: under a fixed
    now_fn, two runs of the same baseline produce byte-identical claimed
    and truth records. Checked on B2 (the anchor, no defects so records
    aren't visible via ScorerResult) and B3 (JWT path — proves the JWT's
    own iat/exp drift across runs does NOT leak into the records)."""
    fixed = lambda: 1_700_000_000.0
    for b in ("B2", "B3"):
        a = run(b, now_fn=fixed)
        c = run(b, now_fn=fixed)
        assert a["claimed"] == c["claimed"], f"{b}: claimed differs"
        assert a["truth"]   == c["truth"],   f"{b}: truth differs"


def test_run_rejects_unknown_baseline():
    """_credential_for fails loud per Rule 12 — unknown baseline is an
    error, not a default. Catches typos like 'B5' before they silently
    score zero on a phantom credential."""
    import pytest
    with pytest.raises(ValueError, match="unknown baseline"):
        run("B5")