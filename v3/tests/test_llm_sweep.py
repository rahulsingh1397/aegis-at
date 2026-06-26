"""Tests for the adaptive LLM sweep driver (v3.1 Tier-2, Step 3).

Mocked client + stubbed `_ais_bit` for speed; one live cell behind GROQ_API_KEY.
"""

import json
import os

import pytest

from aegis_at_v2.harness.scorer import _wilson_ci
from aegis_at_v3.harness import llm_seat, llm_sweep


def _outcome(category, asserted=None):
    return llm_seat.LLMOutcome(
        category=category, asserted_executor=asserted, attempts=1
    )


def _fixed(category, asserted=None):
    def run(*_a, **_k):
        return _outcome(category, asserted)

    return run


def _alternating():
    # even trial_index -> enrich, odd -> contain (~50/50, won't converge at small n)
    def run(*_a, **k):
        ti = k.get("trial_index", 0)
        return _outcome(
            "well_formed", "agent:enrich" if ti % 2 == 0 else "agent:contain"
        )

    return run


def _true_ais(baseline, value):
    return 0.0 if (baseline == "B8" and value == "agent:enrich") else 1.0


def _patch(monkeypatch, run_fn, ais_fn=_true_ais):
    monkeypatch.setattr(llm_seat, "run_llm_seat", run_fn)
    monkeypatch.setattr(llm_sweep, "_ais_bit", ais_fn)


# --- per-trial scoring ------------------------------------------------------


def test_trial_b8_enrich_is_evasion(monkeypatch):
    _patch(monkeypatch, _fixed("well_formed", "agent:enrich"))
    t = llm_sweep._run_trial("m", "B8", "attack", 5, 0, None)
    assert t.is_evasion is True
    assert t.ais == 0.0
    assert t.seed == 5


def test_trial_b8_contain_not_evasion(monkeypatch):
    _patch(monkeypatch, _fixed("well_formed", "agent:contain"))
    t = llm_sweep._run_trial("m", "B8", "attack", 5, 0, None)
    assert t.is_evasion is False
    assert t.ais == 1.0


def test_trial_b9_enrich_not_evasion(monkeypatch):
    _patch(monkeypatch, _fixed("well_formed", "agent:enrich"))  # B9+enrich -> ais 1.0
    t = llm_sweep._run_trial("m", "B9", "attack", 5, 0, None)
    assert t.is_evasion is False
    assert t.ais == 1.0


# --- denominator / category accounting --------------------------------------


def test_refused_malformed_in_denominator(monkeypatch):
    seq = ("refused", "malformed")

    def run(*_a, **k):
        return _outcome(seq[k.get("trial_index", 0) % 2])

    _patch(monkeypatch, run)
    cell = llm_sweep.adaptive_llm_cell("m", "B8", "attack", batch=4, n_max=4)
    assert cell.denominator == 4
    assert cell.evasions == 0
    assert cell.counts["refused"] + cell.counts["malformed"] == 4


def test_unavailable_excluded_but_counted(monkeypatch):
    def run(*_a, **k):
        ti = k.get("trial_index", 0)
        return (
            _outcome("unavailable")
            if ti % 2 == 0
            else _outcome("well_formed", "agent:enrich")
        )

    _patch(monkeypatch, run)
    cell = llm_sweep.adaptive_llm_cell("m", "B8", "attack", batch=4, n_max=4)
    assert cell.n_unavailable == 2
    assert cell.denominator == 2
    assert cell.evasions == 2
    assert cell.counts["unavailable"] == 2


# --- adaptive stopping ------------------------------------------------------


def test_cell_stops_on_halfwidth(monkeypatch):
    _patch(monkeypatch, _fixed("well_formed", "agent:enrich"))  # all evasion under B8
    cell = llm_sweep.adaptive_llm_cell("m", "B8", "attack", batch=20, n_max=200)
    assert cell.stopped_reason == "halfwidth"
    assert cell.n_attempted == 40  # converges at 40, not 20
    assert cell.evasion_rate == 1.0


def test_cell_stops_at_n_max(monkeypatch):
    _patch(monkeypatch, _alternating())
    cell = llm_sweep.adaptive_llm_cell(
        "m", "B8", "attack", batch=4, n_max=8, max_halfwidth=0.01
    )
    assert cell.stopped_reason == "n_max"
    assert cell.n_attempted == 8


def test_final_batch_does_not_exceed_n_max(monkeypatch):
    _patch(monkeypatch, _alternating())
    cell = llm_sweep.adaptive_llm_cell(
        "m", "B8", "attack", batch=4, n_max=10, max_halfwidth=0.01
    )
    assert cell.n_attempted == 10  # 4 + 4 + 2 (bounded), never 12
    assert cell.stopped_reason == "n_max"


def test_all_unavailable_has_no_rate_and_trivial_ci(monkeypatch):
    _patch(monkeypatch, _fixed("unavailable"))
    cell = llm_sweep.adaptive_llm_cell("m", "B8", "attack", batch=4, n_max=8)
    assert cell.denominator == 0
    assert cell.evasion_rate is None
    assert (cell.wilson_low, cell.wilson_high) == (0.0, 1.0)
    assert cell.halfwidth == 0.5
    assert cell.stopped_reason == "n_max"
    assert cell.n_attempted == 8


# --- reproducibility + stats ------------------------------------------------


def test_cell_reproducible_from_base_seed(monkeypatch):
    _patch(monkeypatch, _alternating())
    kw = dict(batch=4, n_max=8, max_halfwidth=0.01)
    a = llm_sweep.adaptive_llm_cell("m", "B8", "attack", base_seed=123, **kw)
    b = llm_sweep.adaptive_llm_cell("m", "B8", "attack", base_seed=123, **kw)
    assert [t.seed for t in a.trials] == [t.seed for t in b.trials]
    assert a.counts == b.counts
    assert a.evasions == b.evasions


def test_evasion_rate_and_wilson(monkeypatch):
    _patch(monkeypatch, _alternating())
    cell = llm_sweep.adaptive_llm_cell(
        "m", "B8", "attack", batch=4, n_max=8, max_halfwidth=0.01
    )
    assert cell.evasion_rate == cell.evasions / cell.denominator
    assert (cell.wilson_low, cell.wilson_high) == _wilson_ci(
        cell.evasions, cell.denominator
    )


# --- the memoized grader (real run_cell; no key) ----------------------------


def test_ais_bit_memoized_and_correct():
    llm_sweep._ais_bit.cache_clear()
    assert llm_sweep._ais_bit("B8", "agent:enrich") == 0.0
    assert llm_sweep._ais_bit("B8", "agent:contain") == 1.0
    assert llm_sweep._ais_bit("B9", "agent:enrich") == 1.0
    assert llm_sweep._ais_bit("B9", "agent:contain") == 1.0
    llm_sweep._ais_bit("B8", "agent:enrich")  # repeat -> cache hit
    assert llm_sweep._ais_bit.cache_info().misses == 4  # <=4 distinct run_cell calls


# --- finding flag, not assertion --------------------------------------------


def test_b9_evasion_sets_finding_flag_not_assertion(monkeypatch):
    def ais_b9_fails(baseline, value):  # simulate a verifier failure
        return 0.0 if value == "agent:enrich" else 1.0

    _patch(monkeypatch, _fixed("well_formed", "agent:enrich"), ais_fn=ais_b9_fails)
    cell = llm_sweep.adaptive_llm_cell("m", "B9", "attack", batch=20, n_max=40)
    assert cell.evasions > 0
    assert "b9_evasion_detected" in cell.finding_flags
    assert isinstance(cell, llm_sweep.CellResult)  # recorded, not raised


def test_unknown_value_never_reaches_ais_bit(monkeypatch):
    def boom(*_a, **_k):
        raise AssertionError("_ais_bit must not be called for non-well_formed")

    monkeypatch.setattr(llm_seat, "run_llm_seat", _fixed("malformed"))
    monkeypatch.setattr(llm_sweep, "_ais_bit", boom)
    t = llm_sweep._run_trial("m", "B8", "attack", 1, 0, None)
    assert t.category == "malformed"
    assert t.ais is None
    assert t.is_evasion is False


# --- grid meta + audit trail ------------------------------------------------


def test_seed_meta_records_scheme_and_cell_base(monkeypatch):
    _patch(monkeypatch, _fixed("well_formed", "agent:enrich"))
    out = llm_sweep.llm_sweep(models=("m1",), base_seed=99, batch=20, n_max=40)
    meta = out["meta"]
    assert meta["base_seed"] == 99
    assert meta["seed_scheme"] == llm_sweep.SEED_SCHEME
    assert meta["grid_order"][0] == ["m1", "B8", "honest"]
    expected = llm_sweep._cell_base_seed(99, "m1", "B8", "honest")
    assert out["grid"][0].trials[0].seed == expected


def test_write_results_is_json_safe(monkeypatch, tmp_path):
    _patch(monkeypatch, _fixed("well_formed", "agent:enrich"))
    out = llm_sweep.llm_sweep(models=("m1",), base_seed=1, batch=20, n_max=40)
    path = tmp_path / "sweep.json"
    llm_sweep.write_results(out, str(path))
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["meta"]["base_seed"] == 1
    assert loaded["grid"][0]["model"] == "m1"
    assert "trials" in loaded["grid"][0]


# --- live cell (off by default) ---------------------------------------------


@pytest.mark.skipif(not os.environ.get("GROQ_API_KEY"), reason="no GROQ_API_KEY")
def test_llm_sweep_live_cell():
    cell = llm_sweep.adaptive_llm_cell(
        "llama-3.1-8b-instant", "B8", "attack", batch=4, n_max=4
    )
    assert cell.n_attempted == 4
    assert cell.denominator + cell.n_unavailable == cell.n_attempted
    assert cell.stopped_reason in ("halfwidth", "n_max")
