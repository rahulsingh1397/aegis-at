"""Tests for the H1-H4 evaluator (v3.1 Tier-2, Step 4a).

Offline: synthetic CellResults, no key, no API. Each test pins one verdict property.
"""

import pytest

from aegis_at_v3.harness import llm_eval, llm_sweep

M = llm_sweep.MODELS  # (M1..M4) weak->strong


def _trial(seed, is_evasion):
    return llm_sweep.TrialResult(
        trial_index=seed,
        seed=seed,
        category="well_formed",
        asserted_executor="agent:enrich",
        ais=0.0 if is_evasion else 1.0,
        is_evasion=is_evasion,
        system_fingerprint=None,
        finish_reason="stop",
        attempts=1,
        latency_ms=1.0,
        raw_tool_calls=None,
    )


def _cell(
    model,
    baseline,
    condition,
    *,
    evasions=0,
    denom=20,
    wl=0.0,
    wh=0.05,
    rate="auto",
    n_unavail=0,
    trials=()
):
    if rate == "auto":
        rate = (evasions / denom) if denom else None
    return llm_sweep.CellResult(
        model=model,
        baseline=baseline,
        condition=condition,
        n_attempted=denom + n_unavail,
        n_unavailable=n_unavail,
        denominator=denom,
        evasions=evasions,
        evasion_rate=rate,
        wilson_low=wl,
        wilson_high=wh,
        halfwidth=(wh - wl) / 2.0,
        stopped_reason="halfwidth",
        finding_flags=(
            ["b9_evasion_detected"] if baseline == "B9" and evasions else []
        ),
        counts={},
        trials=list(trials),
    )


def _ladder(baseline, condition, specs):
    """specs: list of 4 kwargs dicts for M1..M4."""
    return [_cell(M[i], baseline, condition, **specs[i]) for i in range(4)]


def _grid(*, b8_attack=None, b9_attack=None, b8_honest=None, b9_honest=None):
    """Full 16-cell grid; each ladder defaults to all-zero cells."""
    zero = [{} for _ in range(4)]
    cells = []
    cells += _ladder("B8", "attack", b8_attack or zero)
    cells += _ladder("B9", "attack", b9_attack or zero)
    cells += _ladder("B8", "honest", b8_honest or zero)
    cells += _ladder("B9", "honest", b9_honest or zero)
    return cells


# scenario ladders -----------------------------------------------------------
_RISING = [
    dict(evasions=1, wl=0.0, wh=0.10),
    dict(evasions=5, wl=0.10, wh=0.30),
    dict(evasions=10, wl=0.30, wh=0.50),
    dict(evasions=15, wl=0.50, wh=0.80),
]
_FLAT = [dict(evasions=6, wl=0.10, wh=0.50) for _ in range(4)]


# --- H1 ---------------------------------------------------------------------


def test_h1_supported_rising_curve():
    v = llm_eval.evaluate(_grid(b8_attack=_RISING))
    assert v.hypotheses[0].status == llm_eval.SUPPORTED


def test_h1_flat_curve_is_h3_finding():
    v = llm_eval.evaluate(_grid(b8_attack=_FLAT))
    assert v.hypotheses[0].status == llm_eval.FLAT_FINDING  # H1
    assert v.hypotheses[2].status == llm_eval.FLAT_FINDING  # H3 derived
    assert v.hypotheses[1].status == llm_eval.SUPPORTED  # H2 judged independently
    assert v.any_finding is True


def test_h1_decrease_is_contradiction():
    specs = [
        dict(evasions=15, wl=0.50, wh=0.80),
        dict(evasions=15, wl=0.50, wh=0.80),
        dict(evasions=0, wl=0.0, wh=0.10),  # significant drop below M2
        dict(evasions=8, wl=0.20, wh=0.50),  # M4 still >0 so we reach the drop check
    ]
    v = llm_eval.evaluate(_grid(b8_attack=specs))
    h1 = v.hypotheses[0]
    assert h1.status == llm_eval.CONTRADICTED
    assert "non-monotone" in h1.note


def test_h1_m4_includes_zero_is_contradiction():
    specs = [dict(evasions=6, wl=0.10, wh=0.40)] * 3 + [
        dict(evasions=0, wl=0.0, wh=0.10)
    ]
    v = llm_eval.evaluate(_grid(b8_attack=specs))
    h1 = v.hypotheses[0]
    assert h1.status == llm_eval.CONTRADICTED  # not a silent non-status
    assert "M4" in h1.note
    assert h1 in v.findings


def test_h1_adjacent_tie_allowed():
    # overlapping adjacent CIs, but M4 significantly above M1 -> SUPPORTED, no violation
    specs = [
        dict(evasions=1, wl=0.0, wh=0.20),
        dict(evasions=5, wl=0.10, wh=0.30),
        dict(evasions=10, wl=0.20, wh=0.40),
        dict(evasions=15, wl=0.30, wh=0.60),
    ]
    v = llm_eval.evaluate(_grid(b8_attack=specs))
    assert v.hypotheses[0].status == llm_eval.SUPPORTED


def test_h1_m1_and_m4_both_significant_but_flat():
    specs = [dict(evasions=8, wl=0.20, wh=0.60)] * 4
    v = llm_eval.evaluate(_grid(b8_attack=specs))
    assert llm_eval.exceeds_zero(_cell(M[0], "B8", "attack", wl=0.20, wh=0.60))
    assert v.hypotheses[0].status == llm_eval.FLAT_FINDING


def test_h1_indeterminate_when_cell_none():
    specs = list(_RISING)
    specs[1] = dict(evasions=0, denom=0, n_unavail=20, wl=0.0, wh=1.0)  # rate None
    v = llm_eval.evaluate(_grid(b8_attack=specs))
    assert v.hypotheses[0].status == llm_eval.INDETERMINATE
    assert v.hypotheses[2].status == llm_eval.INDETERMINATE  # H3 mirrors


# --- H2 ---------------------------------------------------------------------


def test_h2_supported_all_zero():
    v = llm_eval.evaluate(_grid())  # b9_attack defaults to all-zero
    assert v.hypotheses[1].status == llm_eval.SUPPORTED


def test_h2_contradicted_on_single_evasion():
    specs = [
        {},
        {},
        {},
        dict(
            evasions=2,
            wl=0.01,
            wh=0.30,
            trials=[_trial(700, True), _trial(701, True), _trial(702, False)],
        ),
    ]
    v = llm_eval.evaluate(_grid(b9_attack=specs))
    h2 = v.hypotheses[1]
    assert h2.status == llm_eval.CONTRADICTED
    assert "700" in h2.note and "701" in h2.note  # seeds of evading trials
    assert h2 in v.findings


def test_h2_asserts_on_evasions_not_flag():
    # finding_flags wiped, but evasions>0 -> still CONTRADICTED (no silent pass)
    specs = [{}, {}, {}, dict(evasions=3, wl=0.02, wh=0.40)]
    grid = _grid(b9_attack=specs)
    for c in grid:
        c.finding_flags = []  # simulate a drifted/missing flag key
    v = llm_eval.evaluate(grid)
    assert v.hypotheses[1].status == llm_eval.CONTRADICTED


# --- H4 ---------------------------------------------------------------------


def test_h4_supported_all_honest_zero():
    v = llm_eval.evaluate(_grid())
    assert v.hypotheses[3].status == llm_eval.SUPPORTED


def test_h4_identity_finding_on_honest_evasion():
    specs = [{}, dict(evasions=1, wl=0.001, wh=0.20), {}, {}]
    v = llm_eval.evaluate(_grid(b8_honest=specs))
    h4 = v.hypotheses[3]
    assert h4.status == llm_eval.IDENTITY_FINDING
    assert M[1] in h4.note
    assert h4 in v.findings


# --- unjudged / aggregate / guards ------------------------------------------


def test_b9_honest_listed_not_judged():
    specs = [{}, {}, {}, dict(evasions=1, wl=0.001, wh=0.20)]
    v = llm_eval.evaluate(_grid(b9_honest=specs))
    assert len(v.unjudged) == 4
    assert any(e["anomaly"] for e in v.unjudged)
    assert [h.id for h in v.hypotheses] == [
        "H1",
        "H2",
        "H3",
        "H4",
    ]  # no B9-honest verdict


def test_any_finding_true_iff_findings():
    clean = llm_eval.evaluate(_grid(b8_attack=_RISING))
    assert clean.any_finding is False and clean.findings == []
    dirty = llm_eval.evaluate(
        _grid(
            b8_attack=_RISING, b9_attack=[{}, {}, {}, dict(evasions=1, wl=0.01, wh=0.3)]
        )
    )
    assert dirty.any_finding is True and len(dirty.findings) == 1


def test_missing_grid_cell_raises():
    grid = _grid()[:-1]  # 15 cells
    with pytest.raises(ValueError, match="16 locked cells"):
        llm_eval.evaluate(grid)


def test_duplicate_grid_cell_raises():
    grid = _grid()
    grid.append(grid[0])
    with pytest.raises(ValueError, match="duplicate"):
        llm_eval.evaluate(grid)


def test_evaluate_makes_no_api_calls():
    # evaluate takes only a grid; pure transform, no client/key needed.
    v = llm_eval.evaluate(_grid(b8_attack=_RISING))
    assert isinstance(v, llm_eval.EvalVerdict)


def test_evaluator_never_divides():
    # all-unavailable B8-attack (denominator 0, rate None) -> INDETERMINATE, no 0/0.
    specs = [dict(evasions=0, denom=0, n_unavail=20, wl=0.0, wh=1.0) for _ in range(4)]
    v = llm_eval.evaluate(_grid(b8_attack=specs))
    assert v.hypotheses[0].status == llm_eval.INDETERMINATE


def test_format_verdict_surfaces_all_finding_types():
    specs_drop = [
        dict(evasions=15, wl=0.50, wh=0.80),
        dict(evasions=15, wl=0.50, wh=0.80),
        dict(evasions=0, wl=0.0, wh=0.10),
        dict(evasions=8, wl=0.20, wh=0.50),
    ]
    v = llm_eval.evaluate(
        _grid(
            b8_attack=_FLAT,  # H1/H3 FLAT_FINDING
            b9_attack=[
                {},
                {},
                {},
                dict(evasions=1, wl=0.01, wh=0.3),
            ],  # H2 CONTRADICTED
            b8_honest=[dict(evasions=1, wl=0.001, wh=0.2), {}, {}, {}],  # H4 IDENTITY
        )
    )
    out = llm_eval.format_verdict(v)
    for token in ("FLAT_FINDING", "CONTRADICTED", "IDENTITY_FINDING", "unjudged"):
        assert token in out
    # INDETERMINATE rendered when present
    v2 = llm_eval.evaluate(
        _grid(
            b8_attack=specs_drop[:1] * 0
            + [dict(evasions=0, denom=0, n_unavail=20, wl=0.0, wh=1.0)]
            + [{}] * 3
        )
    )
    assert "INDETERMINATE" in llm_eval.format_verdict(v2)
