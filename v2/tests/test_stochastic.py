"""
Phase 6 tests — stochastic policy + Wilson CIs (threat-model-v2.md §8).

WHY these tests exist: v1 reported AIS ∈ {0,1} from a single execution, so
its "CIs" were degenerate (binomial on n=1). v2's claim is that the curve
is STRUCTURAL — its shape is invariant to attack frequency p — and that the
intervals are real. So the tests must pin three things: (a) the point AIS
equals the pre-registered bit in every cell regardless of p (§8.2); (b) the
Wilson interval actually contains that point (the CI is honest); (c) the
adaptive escalation fires when an interval is too wide (§8.1), and the whole
grid is reproducible from one seed (INV-7 determinism).
"""

import pytest

from aegis_at_v2.harness import stochastic as st


# --- §8.2: shape invariance across p --------------------------------------


def test_point_ais_matches_prediction_across_all_cells():
    """§8.2: in every (topology, baseline, p) cell, the point AIS equals the
    pre-registered bit (B1=0, B2=1, B3=0, B4=0, B5=1) — p scales the
    denominator, never the per-action correctness."""
    grid = st.stochastic_sweep()
    assert st.curve_shape_invariant(grid)
    # spell out a representative cell so a failure is legible
    for topo in ("T1", "T2"):
        for b, want in st.PREDICTED_BIT.items():
            for p in st.P_VALUES:
                cell = grid[topo][b][p]
                assert cell["struct_ais"] == float(want), (topo, b, p)


def test_adversarial_and_structural_point_values_agree():
    """§4.3: the adversarial-trigger denominator and the expanded
    (all-containments) denominator yield the SAME point AIS — because the
    misattribution is latent in the re-delegation pattern, not created by
    the attacker. The intervals may differ; the point estimate must not."""
    grid = st.stochastic_sweep()
    for topo_cells in grid.values():
        for p_cells in topo_cells.values():
            for cell in p_cells.values():
                if cell["escalations"]:  # adv_ais only defined when escalated
                    assert cell["adv_ais"] == cell["struct_ais"]


# --- the CI is honest -----------------------------------------------------


def test_wilson_interval_contains_the_point():
    """The reported Wilson 95% interval must contain the point AIS, on both
    denominators. A CI that excludes its own estimate is a bug, not a
    finding."""
    grid = st.stochastic_sweep()
    for topo_cells in grid.values():
        for p_cells in topo_cells.values():
            for cell in p_cells.values():
                assert cell["struct_ci_low"] <= cell["struct_ais"] <= cell["struct_ci_high"]
                if cell["escalations"]:
                    assert cell["adv_ci_low"] <= cell["adv_ais"] <= cell["adv_ci_high"]


# --- §8.1: adaptive escalation --------------------------------------------


def test_low_p_boundary_cell_escalates_to_larger_n():
    """§8.1: a boundary cell with few escalations at N=100 (e.g. p=0.1) has
    a wide adversarial interval and must auto-escalate to N=500. Seeded, so
    this is deterministic."""
    cell = st.adaptive_cell("B1", "T1", 0.1, base_seed=st.stochastic_sweep.__defaults__[0])
    assert cell["escalated_to_n"] is True
    assert cell["n"] == st.ESCALATED_N
    # after escalation the interval is within tolerance
    assert cell["adv_halfwidth"] <= st.MAX_HALFWIDTH


def test_high_p_cell_does_not_escalate():
    """§8.1: a p=0.9 cell has ~N escalations at N=100, a tight interval, and
    must NOT escalate — confirming escalation is triggered by width, not
    applied blindly."""
    seed = st.stochastic_sweep.__defaults__[0]
    cell = st.adaptive_cell("B2", "T1", 0.9, base_seed=seed)
    assert cell["escalated_to_n"] is False
    assert cell["n"] == st.DEFAULT_N
    assert cell["adv_halfwidth"] <= st.MAX_HALFWIDTH


def test_stochastic_cell_halfwidth_gates_escalation_directly():
    """Mechanism check: a deliberately tiny N yields a wide interval (the
    condition that triggers escalation), proving the gate can fire — not
    just that it happens to on real cells."""
    tiny = st.stochastic_cell("B1", "T1", 0.5, n=4, seed=st._cell_seed(1, "T1", "B1", 0.5))
    assert tiny["adv_halfwidth"] > st.MAX_HALFWIDTH


# --- reproducibility (INV-7) ----------------------------------------------


def test_sweep_is_reproducible_from_seed():
    """INV-7: the entire grid is a deterministic function of base_seed.
    Two sweeps with the same seed are identical; the escalation draws are
    seeded, not wall-clock."""
    a = st.stochastic_sweep(base_seed=42)
    b = st.stochastic_sweep(base_seed=42)
    assert a == b


def test_different_seeds_change_the_draw_not_the_point():
    """Sanity: a different seed changes the escalation COUNT (the draw) but
    not the point AIS (which is structural). Distinguishes 'seed affects
    sampling' from 'seed affects the finding'."""
    a = st.stochastic_sweep(base_seed=1)
    b = st.stochastic_sweep(base_seed=2)
    # point predictions unchanged under both seeds
    assert st.curve_shape_invariant(a) and st.curve_shape_invariant(b)
    # but at least one cell's escalation count differs
    diffs = [
        a[t][bl][p]["escalations"] != b[t][bl][p]["escalations"]
        for t in a
        for bl in a[t]
        for p in a[t][bl]
    ]
    assert any(diffs)


def test_curve_shape_invariant_detects_a_broken_prediction():
    """Negative control: curve_shape_invariant must RETURN FALSE when a cell
    contradicts the oracle — otherwise it can't surface a real finding."""
    grid = st.stochastic_sweep(base_seed=7)
    # claim B3 should be correct (it isn't) → the helper must catch the gap
    wrong_oracle = dict(st.PREDICTED_BIT, B3=1)
    assert st.curve_shape_invariant(grid, oracle=wrong_oracle) is False
