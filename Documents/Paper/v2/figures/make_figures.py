"""
make_figures.py — generate the AEGIS-AT v2 paper figures from MEASURED data.

Every number plotted here is produced by running the v2 harness, not typed
in — so the figures cannot drift from the code (INV-8) and regenerate with
one command. Outputs (vector PDF, for LaTeX \\includegraphics):

    fig_ais_curve.pdf      the non-monotonic AIS curve, T1 and T2 overlaid (§7)
    fig_ais_lis.pdf        AIS vs LIS per baseline — the §6.3 asymmetry
    fig_stochastic_ci.pdf  stochastic AIS with Wilson 95% CIs across p (§8)

Paper-build dependency: matplotlib (not a core/test dependency). Run:
    python Documents/Paper/figures/make_figures.py
from the repo root, or from anywhere — paths are anchored off this file.
"""

import pathlib
import sys

import matplotlib

matplotlib.use("Agg")  # headless: write files, never open a window
import matplotlib.pyplot as plt

# --- import the v2 harness (anchor off this file, not the cwd) ------------
HERE = pathlib.Path(__file__).resolve()
# figures -> v2 -> Paper -> Documents -> repo root
REPO_ROOT = HERE.parents[4]
V2_ROOT = REPO_ROOT / "v2"
sys.path.insert(0, str(V2_ROOT))

from aegis_at_v2.harness import sweep, stochastic as st  # noqa: E402

OUT = HERE.parent
BASELINES = ("B1", "B2", "B3", "B4", "B5")


def _save(fig, stem):
    """Write both a vector PDF (for the paper) and a PNG (for the README /
    GitHub, which cannot render PDF inline). Same figure, two formats."""
    fig.savefig(OUT / f"{stem}.pdf")
    fig.savefig(OUT / f"{stem}.png", dpi=200)
# Short labels for the x-axis (defense layer added at each baseline).
LABELS = {
    "B1": "B1\nshared\naccount",
    "B2": "B2\nper-agent\nidentity",
    "B3": "B3\n+RFC 8693\ndelegation",
    "B4": "B4\n+tamper-\nevident log",
    "B5": "B5\n+DPoP\n(sender-bound)",
}
# A restrained, print-safe palette.
C_GOOD = "#1b7837"   # attribution holds
C_BAD = "#b2182b"    # attribution fails
C_T1 = "#2166ac"
C_T2 = "#d6604d"
C_LIS = "#7b3294"

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.size": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.dpi": 150,
    }
)


def _measure():
    """Run the harness once and return everything the figures need."""
    curves = sweep.emit_curves(with_determinism_check=False)
    lis = sweep.emit_lis_curve()
    grid = st.stochastic_sweep()
    return curves, lis, grid


def fig_ais_curve(curves):
    """The headline: non-monotonic AIS across B1-B5, T1 and T2 overlaid.

    T1 and T2 land on identical points — that overlap IS the §7.2 finding
    (the gap does not heal with chain depth), so we draw T2 slightly offset
    and hollow so both are visible."""
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    xs = range(len(BASELINES))

    t1 = [curves["T1"][b]["ais"] for b in BASELINES]
    t2 = [curves["T2"][b]["ais"] for b in BASELINES]

    ax.plot(xs, t1, "-o", color=C_T1, lw=2, ms=7, label="T1 (2-agent)", zorder=3)
    ax.plot(
        xs, t2, "--s", color=C_T2, lw=1.6, ms=7, mfc="white",
        label="T2 (3-agent)", zorder=2,
    )

    # annotate the two turning points
    ax.annotate(
        "regression\n(signed delegation)",
        xy=(2, 0.0), xytext=(1.6, 0.42), color=C_BAD, fontsize=8.5,
        ha="center", arrowprops=dict(arrowstyle="->", color=C_BAD, lw=1.2),
    )
    ax.annotate(
        "recovery\n(sender-constraint)",
        xy=(4, 1.0), xytext=(3.5, 0.55), color=C_GOOD, fontsize=8.5,
        ha="center", arrowprops=dict(arrowstyle="->", color=C_GOOD, lw=1.2),
    )

    ax.set_xticks(list(xs))
    ax.set_xticklabels([LABELS[b] for b in BASELINES], fontsize=8)
    ax.set_ylim(-0.05, 1.12)
    ax.set_ylabel("Attribution Integrity Score (AIS)")
    ax.set_title("Attribution regresses with delegation, recovers with DPoP", fontsize=11)
    ax.legend(loc="center left", frameon=False, fontsize=9)
    ax.grid(axis="y", ls=":", alpha=0.5)
    fig.tight_layout()
    _save(fig, "fig_ais_curve")
    plt.close(fig)


def fig_ais_lis(curves, lis):
    """AIS vs LIS per baseline — the §6.3 asymmetry. B4 is the point: a
    perfect LIS (tamper-proof) sitting next to a zero AIS (wrong record)."""
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    xs = range(len(BASELINES))
    w = 0.38

    ais = [curves["T1"][b]["ais"] for b in BASELINES]
    lscore = [lis[b]["lis"] for b in BASELINES]

    ax.bar([x - w / 2 for x in xs], ais, w, color=C_BAD, label="AIS (attribution correct?)")
    ax.bar([x + w / 2 for x in xs], lscore, w, color=C_LIS, label="LIS (tamper detected?)")

    # call out the B4 asymmetry
    ax.annotate(
        "tamper-proof yet\nmis-attributing",
        xy=(3 + w / 2, 1.0), xytext=(2.55, 0.72), fontsize=8.5, ha="center",
        arrowprops=dict(arrowstyle="->", color="#333", lw=1.1),
    )

    ax.set_xticks(list(xs))
    ax.set_xticklabels([LABELS[b] for b in BASELINES], fontsize=8)
    ax.set_ylim(0, 1.15)
    ax.set_ylabel("score")
    ax.set_title("AIS and LIS are orthogonal: B4 preserves a wrong record", fontsize=11)
    ax.legend(loc="upper left", frameon=False, fontsize=9)
    ax.grid(axis="y", ls=":", alpha=0.5)
    fig.tight_layout()
    _save(fig, "fig_ais_lis")
    plt.close(fig)


def fig_stochastic_ci(grid):
    """Stochastic AIS with Wilson 95% CIs across p, T1. Shows the shape is
    invariant to attack frequency (§8.2) and the intervals are real (§8).
    Uses the adversarial-trigger denominator (the one that shrinks with p)."""
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    ps = st.P_VALUES
    offsets = {"B1": -0.16, "B2": -0.08, "B3": 0.0, "B4": 0.08, "B5": 0.16}
    colors = {"B1": C_BAD, "B2": C_GOOD, "B3": "#ef8a62", "B4": "#fddbc7", "B5": "#67a9cf"}

    for b in BASELINES:
        xs, ys, lo, hi = [], [], [], []
        for p in ps:
            cell = grid["T1"][b][p]
            xs.append(ps.index(p) + offsets[b])
            ys.append(cell["adv_ais"])
            lo.append(cell["adv_ais"] - cell["adv_ci_low"])
            hi.append(cell["adv_ci_high"] - cell["adv_ais"])
        ax.errorbar(
            xs, ys, yerr=[lo, hi], fmt="o", color=colors[b], ms=5, capsize=3,
            lw=1.4, label=b,
        )

    ax.set_xticks(range(len(ps)))
    ax.set_xticklabels([f"p = {p}" for p in ps])
    ax.set_xlabel("escalation probability (attack frequency)")
    ax.set_ylim(-0.08, 1.12)
    ax.set_ylabel("AIS (adversarial denominator)\nWilson 95% CI")
    ax.set_title("Curve shape is invariant to attack frequency", fontsize=11)
    ax.legend(loc="center left", frameon=False, fontsize=9, ncol=1)
    ax.grid(axis="y", ls=":", alpha=0.5)
    fig.tight_layout()
    _save(fig, "fig_stochastic_ci")
    plt.close(fig)


def main():
    curves, lis, grid = _measure()
    fig_ais_curve(curves)
    fig_ais_lis(curves, lis)
    fig_stochastic_ci(grid)
    print("wrote:")
    for name in ("fig_ais_curve.pdf", "fig_ais_lis.pdf", "fig_stochastic_ci.pdf"):
        print("  ", OUT / name)


if __name__ == "__main__":
    main()
