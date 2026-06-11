"""
harness/stochastic.py — Bernoulli(p) escalation + Wilson CIs (§8).

Retires v1's degenerate-CI footnote (AIS ∈ {0,1} from a single execution).
v2 runs N attacks per (topology × baseline × p) cell and reports a Wilson
95% interval on the fraction, with adaptive escalation to a larger N when
an interval is too wide (§8.1).

KEY MODELLING DECISION (stated plainly, because a reviewer will ask).
Per-action attribution correctness is DETERMINISTIC given (baseline,
topology): verify_deterministic proves a run is byte-reproducible, and §8.2
pre-registers that p "scales the number of adversarial actions in the
denominator, not the per-action correctness." So the only stochastic
element in this model is WHICH trials escalate. We therefore evaluate the
attack ONCE per cell (the correctness bit) and draw N Bernoulli(p)
escalation events to form the denominator. This is EXACT, not sampled —
re-running the identical deterministic subprocess N times would change
nothing but wall-clock (Rule 5: code answers deterministic transforms).
The randomness that matters — the escalation draw — is seeded and
reproducible.

Two denominators are reported per cell (§4.3):
  - adversarial-trigger: the escalated (attacker-triggered) subset, ~Bin(N,p);
  - expanded/structural: ALL N re-delegated containments (attacked or not).
The two yield the SAME point AIS because the misattribution is structural,
not attacker-created — that equality is itself the §4.3 finding, and it is
visible here by construction. The intervals differ (the structural
denominator is always N; the adversarial one shrinks with p).
"""

import hashlib
import random
from functools import lru_cache
from typing import TypedDict

from aegis_at_v2.harness import sweep
from aegis_at_v2.harness.scorer import _wilson_ci
from aegis_at_v2.topologies import TOPOLOGY_NAMES

# Pre-registered escalation rates and sample sizes (threat-model-v2.md §8.1).
P_VALUES: tuple[float, ...] = (0.1, 0.5, 0.9)
DEFAULT_N: int = 100
ESCALATED_N: int = 500
MAX_HALFWIDTH: float = 0.1
BASELINES: tuple[str, ...] = ("B1", "B2", "B3", "B4", "B5")

# The locked per-action correctness bit per baseline (§8.2 point predictions:
# B1=0, B2=1, B3=0, B4=0, B5=1). Topology-independent (§7.2). Kept here ONLY
# as the test/prediction oracle — the measured bit comes from correctness_bit().
PREDICTED_BIT: dict[str, int] = {"B1": 0, "B2": 1, "B3": 0, "B4": 0, "B5": 1}


class StochasticCell(TypedDict):
    topology: str
    baseline: str
    p: float
    n: int
    bit: int  # measured per-action correctness (0/1)
    # adversarial-trigger denominator (the escalated subset)
    escalations: int
    adv_numerator: int
    adv_ais: float
    adv_ci_low: float
    adv_ci_high: float
    adv_halfwidth: float
    # expanded / structural denominator: all N containments (§4.3)
    struct_numerator: int
    struct_ais: float
    struct_ci_low: float
    struct_ci_high: float
    escalated_to_n: bool  # did adaptive escalation to ESCALATED_N fire?
    seed: int


def _cell_seed(base_seed: int, topology: str, baseline: str, p: float) -> int:
    """A stable per-cell seed derived from the cell identity, so the whole
    grid is reproducible from one base_seed and each cell is independent.
    Uses SHA-256 (not Python's salted hash) so it is stable across runs."""
    key = f"{base_seed}|{topology}|{baseline}|{p}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(key).digest()[:8], "big")


@lru_cache(maxsize=None)
def correctness_bit(baseline: str, topology: str = "T1") -> int:
    """1 if the single adversarial action is correctly attributed, else 0.

    Deterministic given (baseline, topology) — memoised so a full sweep
    spawns at most one subprocess per (baseline, topology) cell, not one
    per trial. AIS over a single adversarial action IS the correctness bit
    (denominator 1), so this reads it straight off run()."""
    ais = sweep.run(baseline, topology=topology)["result"]["ais"]
    return 1 if ais == 1.0 else 0


def _escalations(p: float, n: int, seed: int) -> int:
    """Number of escalations in n Bernoulli(p) trials (seeded)."""
    rng = random.Random(seed)
    return sum(1 for _ in range(n) if rng.random() < p)


def _halfwidth(low: float, high: float) -> float:
    return (high - low) / 2.0


def stochastic_cell(
    baseline: str,
    topology: str,
    p: float,
    n: int,
    seed: int,
) -> StochasticCell:
    """One (topology, baseline, p) cell at a fixed N. See module docstring
    for the modelling decision (correctness evaluated once, escalations
    drawn N times)."""
    bit = correctness_bit(baseline, topology)
    escalations = _escalations(p, n, seed)

    adv_num = escalations * bit
    adv_ais = (adv_num / escalations) if escalations else 0.0
    adv_lo, adv_hi = _wilson_ci(adv_num, escalations)

    struct_num = n * bit
    struct_ais = struct_num / n  # n >= 1 by construction
    s_lo, s_hi = _wilson_ci(struct_num, n)

    return {
        "topology": topology,
        "baseline": baseline,
        "p": p,
        "n": n,
        "bit": bit,
        "escalations": escalations,
        "adv_numerator": adv_num,
        "adv_ais": adv_ais,
        "adv_ci_low": adv_lo,
        "adv_ci_high": adv_hi,
        "adv_halfwidth": _halfwidth(adv_lo, adv_hi),
        "struct_numerator": struct_num,
        "struct_ais": struct_ais,
        "struct_ci_low": s_lo,
        "struct_ci_high": s_hi,
        "escalated_to_n": False,
        "seed": seed,
    }


def adaptive_cell(
    baseline: str,
    topology: str,
    p: float,
    base_seed: int,
    n0: int = DEFAULT_N,
    n1: int = ESCALATED_N,
    max_halfwidth: float = MAX_HALFWIDTH,
) -> StochasticCell:
    """Measure a cell at N=n0; if the adversarial-trigger Wilson half-width
    exceeds max_halfwidth, re-measure at N=n1 (§8.1 adaptive escalation).

    The adversarial denominator is the one that shrinks with p (boundary
    cells like B1 at p=0.1 have few escalations and a wide interval at
    n0=100), so it is the half-width that gates escalation. The SAME seed
    is reused so the escalation is a refinement of the same draw, not a
    different experiment."""
    seed = _cell_seed(base_seed, topology, baseline, p)
    cell = stochastic_cell(baseline, topology, p, n0, seed)
    if cell["adv_halfwidth"] > max_halfwidth:
        cell = stochastic_cell(baseline, topology, p, n1, seed)
        cell["escalated_to_n"] = True
    return cell


def stochastic_sweep(
    base_seed: int = 20260610,
    topologies: tuple[str, ...] | None = None,
    baselines: tuple[str, ...] = BASELINES,
    p_values: tuple[float, ...] = P_VALUES,
) -> dict:
    """Run the full grid (topology × baseline × p) with adaptive N.

    Returns nested dict {topology: {baseline: {p: StochasticCell}}}.
    Reproducible from base_seed alone. The §8.2 prediction — curve shape
    invariant across p — is checked by curve_shape_invariant() below; a
    contradiction is a finding (INV-7), not reconciled away.
    """
    topologies = topologies or TOPOLOGY_NAMES
    grid: dict = {}
    for topo in topologies:
        grid[topo] = {}
        for baseline in baselines:
            grid[topo][baseline] = {}
            for p in p_values:
                grid[topo][baseline][p] = adaptive_cell(
                    baseline, topo, p, base_seed
                )
    return grid


def curve_shape_invariant(grid: dict, oracle: dict | None = None) -> bool:
    """§8.2: is the AIS curve SHAPE invariant across p (and topology)?

    True iff every cell's point AIS (both denominators agree by
    construction) equals the pre-registered bit for its baseline. A False
    return names nothing — callers should diff against `oracle` to report
    WHICH cell broke the prediction (INV-7). `oracle` defaults to
    PREDICTED_BIT.
    """
    oracle = oracle or PREDICTED_BIT
    for topo_cells in grid.values():
        for baseline, p_cells in topo_cells.items():
            want = float(oracle[baseline])
            for cell in p_cells.values():
                # struct_ais always has denominator N; adv_ais only when the
                # cell escalated at least once. Both must equal the bit.
                if cell["struct_ais"] != want:
                    return False
                if cell["escalations"] and cell["adv_ais"] != want:
                    return False
    return True
