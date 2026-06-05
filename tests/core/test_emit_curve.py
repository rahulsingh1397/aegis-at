"""Core tests for sweep.emit_curve + scorer.is_non_monotonic — §6 curve gate."""

from sweep import emit_curve
from scorer import is_non_monotonic


def test_emit_curve_produces_predicted_non_monotonic_curve():
    """The §6 headline finding, end-to-end: B2 anchors at 1.0; B1, B3,
    B4 at 0.0. Runs the full sweep (with the determinism check gating
    each baseline) and asserts the curve matches the prediction (§6 /
    INV-7). A contradicted prediction is a finding to report, not a
    bug to silence."""
    curve = emit_curve()
    assert curve["B1"]["ais"] == 0.0
    assert curve["B2"]["ais"] == 1.0
    assert curve["B3"]["ais"] == 0.0
    assert curve["B4"]["ais"] == 0.0
    assert is_non_monotonic(curve) is True


def test_emit_curve_includes_ci_caveat_string():
    """The ci_caveat travels with the data so a downstream report
    cannot omit the determinism disclosure (§4 / harness_notes.md)."""
    curve = emit_curve()
    assert "ci_caveat" in curve
    assert "deterministic" in curve["ci_caveat"]
    assert "not a sampling CI" in curve["ci_caveat"]


def test_emit_curve_does_not_store_non_monotonic_in_dict():
    """Non-monotonicity is computed by scorer.is_non_monotonic(curve),
    not stored as a derived field. If a regression adds 'non_monotonic'
    back into the dict, two definitions of the predicate become
    possible — exactly the drift the function-based approach prevents."""
    curve = emit_curve()
    assert "non_monotonic" not in curve


def test_is_non_monotonic_rejects_contradicted_curve():
    """Fault-injection: a flat curve (no B2 anomaly) violates the
    predicate. Proves is_non_monotonic actually discriminates rather
    than always returning True."""
    flat = {b: {"ais": 0.0} for b in ("B1", "B2", "B3", "B4")}
    assert is_non_monotonic(flat) is False


def test_emit_curve_fast_mode_skips_determinism_check():
    """with_determinism_check=False produces the same curve faster
    (no k=5 reruns per baseline). Useful for debugging defect
    breakdowns; not the default because shipping a curve without
    proving determinism re-opens the 'how do you know N=1 is enough'
    gap."""
    curve = emit_curve(with_determinism_check=False)
    assert curve["B2"]["ais"] == 1.0
    assert is_non_monotonic(curve) is True

