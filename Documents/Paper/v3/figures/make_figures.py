"""
make_figures.py — generate the AEGIS-AT v3 paper figures from MEASURED data.

Two figures, two provenance tiers (kept honest, per threat-model-v3.md §8.6):

    fig_ais_curve_v3.pdf   Tier-1 deterministic B1-B9 AIS curve, honest vs.
                           colluding. Regenerated from the LIVE harness on every
                           run (byte-reproducible) — the plotted numbers cannot
                           drift from the code (INV-8). B1-B5 come from the v2
                           sweep (imported, INV-6); B6-B9 from the v3
                           completion_sweep.

    fig_llm_forging.pdf    Tier-2 per-model B8-attack vs B9-attack forging rate
                           with Wilson 95% CIs. Read from the frozen sweep
                           artifact shipped with the paper (data/llm_sweep_v3.json;
                           fallback: results/llm_sweep_*.json). Tier-2 is
                           statistically, not byte, reproducible (L17): re-running
                           needs a Groq key and yields a fresh sample, so the
                           figure is drawn from the recorded audit artifact, not a
                           live call.

Paper-build dependency: matplotlib (not a core/test dependency). Run:
    python Documents/Paper/v3/figures/make_figures.py
from anywhere — paths are anchored off this file.
"""

import glob
import json
import pathlib
import sys

import matplotlib

matplotlib.use("Agg")  # headless: write files, never open a window
import matplotlib.pyplot as plt  # noqa: E402

# --- anchor paths off this file, not the cwd ------------------------------
HERE = pathlib.Path(__file__).resolve()
# figures -> v3 -> Paper -> Documents -> repo root
REPO_ROOT = HERE.parents[4]
sys.path.insert(0, str(REPO_ROOT / "v3"))
sys.path.insert(0, str(REPO_ROOT / "v2"))
RESULTS_DIR = REPO_ROOT / "results"
# Frozen Tier-2 sweep shipped WITH the paper (tracked), so the figure regenerates
# from the repo without a provider key. figures -> v3, then v3/data/.
FROZEN_SWEEP = HERE.parents[1] / "data" / "llm_sweep_v3.json"
OUT = HERE.parent

# --- the deterministic Tier-1 curve, B1..B9 -------------------------------
BASELINES = ("B1", "B2", "B3", "B4", "B5", "B6", "B7", "B8", "B9")
LABELS = {
    "B1": "B1\nshared\naccount",
    "B2": "B2\nper-agent\nidentity",
    "B3": "B3\n+RFC 8693\ndelegation",
    "B4": "B4\n+tamper-\nevident log",
    "B5": "B5\n+DPoP\n(RFC 9449)",
    "B6": "B6\n+mTLS\n(RFC 8705)",
    "B7": "B7\n+A-JWT\nexec. assert.",
    "B8": "B8\n+self-reported\ncompletion",
    "B9": "B9\n+tool-verified\ncompletion",
}
# Capability-ordered Tier-2 model ladder (threat-model-v3.1.md §C1/§C2).
MODELS = (
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
)
MODEL_LABELS = {
    "llama-3.1-8b-instant": "M1\nllama-3.1\n8b (6)",
    "llama-3.3-70b-versatile": "M2\nllama-3.3\n70b (9)",
    "openai/gpt-oss-20b": "M3\ngpt-oss\n20b (15)",
    "openai/gpt-oss-120b": "M4\ngpt-oss\n120b (24)",
}

# A restrained, print-safe palette (shared with v2).
C_GOOD = "#1b7837"   # attribution holds
C_BAD = "#b2182b"    # attribution fails
C_HONEST = "#2166ac"
C_COLLUDE = "#d6604d"

plt.rcParams.update(
    {
        "font.family": "serif",
        "font.size": 10,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.dpi": 150,
    }
)


def _save(fig, stem):
    """Write a vector PDF (for the paper) and a PNG (for the GitHub README,
    which cannot render PDF inline). Same figure, two formats."""
    fig.savefig(OUT / f"{stem}.pdf")
    fig.savefig(OUT / f"{stem}.png", dpi=200)


# --- Tier-1: measure the deterministic curve from the live harness --------
def _measure_tier1():
    """Run the harness once; return {B: {'honest': ais, 'colluding': ais}}.

    B1-B5 are seat-independent (honest == colluding by construction, §7.4):
    the v2 sweep emits a single AIS per baseline, mirrored into both columns.
    B6-B9 come from the v3 completion_sweep, which emits both seats.
    """
    from aegis_at_v2.harness import sweep
    from aegis_at_v3.harness import completion_sweep as cs

    v2curve = sweep.emit_curves(with_determinism_check=False)["T1"]
    out = {}
    for b in ("B1", "B2", "B3", "B4", "B5"):
        ais = v2curve[b]["ais"]
        out[b] = {"honest": ais, "colluding": ais}
    out["B6"] = cs.emit_b6_grid("T1")["B6"]
    out["B7"] = cs.emit_b7_grid("T1")["B7"]
    b8b9 = cs.emit_b8_b9_grid("T1")
    out["B8"] = b8b9["B8"]
    out["B9"] = b8b9["B9"]
    return out


def fig_ais_curve_v3(curve):
    """The Tier-1 headline: the deterministic B1-B9 AIS curve, honest vs.
    colluding. The two seats coincide everywhere except B8, where the colluding
    self-report collapses AIS to 0.0 while B9 (tool-verified) holds at 1.0 — the
    knockout. The recover-cluster {B5, B6, B7, B9} all sit at 1.0."""
    fig, ax = plt.subplots(figsize=(7.6, 3.8))
    xs = range(len(BASELINES))
    honest = [curve[b]["honest"] for b in BASELINES]
    collude = [curve[b]["colluding"] for b in BASELINES]

    ax.plot(
        xs, honest, "-o", color=C_HONEST, lw=2, ms=7,
        label="honest seat", zorder=3,
    )
    ax.plot(
        xs, collude, "--s", color=C_COLLUDE, lw=1.6, ms=7, mfc="white",
        label="colluding seat", zorder=2,
    )

    # the lone divergence: B8 colluding collapses to 0.0
    ax.annotate(
        "self-report collapses\nunder collusion",
        xy=(7, 0.0), xytext=(5.4, 0.34), color=C_BAD, fontsize=8.5,
        ha="center", arrowprops=dict(arrowstyle="->", color=C_BAD, lw=1.2),
    )
    ax.annotate(
        "tool-verified holds\n(structural control)",
        xy=(8, 1.0), xytext=(7.0, 0.60), color=C_GOOD, fontsize=8.5,
        ha="center", arrowprops=dict(arrowstyle="->", color=C_GOOD, lw=1.2),
    )

    ax.set_xticks(list(xs))
    ax.set_xticklabels([LABELS[b] for b in BASELINES], fontsize=7.5)
    ax.set_ylim(-0.05, 1.14)
    ax.set_ylabel("Attribution Integrity Score (AIS)")
    ax.set_title(
        "Verifying the executor at execution wins; trusting the self-report fails",
        fontsize=10.5,
    )
    ax.legend(loc="lower left", frameon=False, fontsize=9)
    ax.grid(axis="y", ls=":", alpha=0.5)
    fig.tight_layout()
    _save(fig, "fig_ais_curve_v3")
    plt.close(fig)


# --- Tier-2: read the recorded sweep, plot per-model forging --------------
def _load_tier2():
    """Load the recorded Tier-2 sweep. Returns (source_name, grid list).

    Prefer the FROZEN artifact shipped with the paper (data/llm_sweep_v3.json,
    tracked) so the figure regenerates from the repo alone; fall back to the
    latest live-run sweep under results/ (git-ignored). Tier-2 is statistically
    reproducible (L17): the figure is drawn from the recorded audit artifact,
    never a fresh live call (which would need a Groq key and resample). Fail loud
    if neither the frozen artifact nor a recorded sweep is present."""
    if FROZEN_SWEEP.exists():
        path = FROZEN_SWEEP
    else:
        candidates = sorted(glob.glob(str(RESULTS_DIR / "llm_sweep_*.json")))
        if not candidates:
            raise FileNotFoundError(
                f"no Tier-2 sweep: neither the frozen artifact {FROZEN_SWEEP} nor "
                f"{RESULTS_DIR}/llm_sweep_*.json exists. Tier-2 is statistically "
                "reproducible — re-run scripts/run_llm_sweep.py with a GROQ_API_KEY "
                "to regenerate, then re-run this script."
            )
        path = pathlib.Path(candidates[-1])
    with open(path) as fh:
        data = json.load(fh)
    return path.name, data["grid"]


def _cell(grid, model, baseline, condition):
    for c in grid:
        if (
            c["model"] == model
            and c["baseline"] == baseline
            and c["condition"] == condition
        ):
            return c
    raise KeyError(f"no cell {(model, baseline, condition)} in recorded grid")


def fig_llm_forging(grid):
    """Tier-2 per-model forging: B8-attack vs B9-attack evasion rate with Wilson
    95% CIs, across the capability-ordered ladder M1->M4. B8 saturates near the
    ceiling (H1 flat — the forced-call confound, disclosed) while B9 is floored
    at 0.0 for every model (H2 knockout, ε=0)."""
    fig, ax = plt.subplots(figsize=(7.2, 3.9))
    xs = list(range(len(MODELS)))
    w = 0.34

    def series(baseline):
        rates, los, his = [], [], []
        for m in MODELS:
            c = _cell(grid, m, baseline, "attack")
            r = c["evasion_rate"]
            rates.append(r)
            los.append(r - c["wilson_low"])
            his.append(c["wilson_high"] - r)
        return rates, [los, his]

    b8r, b8e = series("B8")
    b9r, b9e = series("B9")

    ax.bar(
        [x - w / 2 for x in xs], b8r, w, color=C_BAD, yerr=b8e, capsize=4,
        error_kw=dict(lw=1.1, ecolor="#333"),
        label="B8 self-reported (forging survives)",
    )
    ax.bar(
        [x + w / 2 for x in xs], b9r, w, color=C_GOOD, yerr=b9e, capsize=4,
        error_kw=dict(lw=1.1, ecolor="#333"),
        label="B9 tool-verified (forging nullified)",
    )

    # numeric labels above each B8 bar (the saturation), and a floor note for B9
    for x, r in zip(xs, b8r):
        ax.text(x - w / 2, r + 0.03, f"{r:.2f}", ha="center", fontsize=8, color=C_BAD)
    ax.annotate(
        "B9 = 0.00 for every model\n(knockout, ε = 0)",
        xy=(0 + w / 2, 0.0), xytext=(1.1, 0.30), color=C_GOOD, fontsize=8.5,
        ha="center", arrowprops=dict(arrowstyle="->", color=C_GOOD, lw=1.2),
    )

    ax.set_xticks(xs)
    ax.set_xticklabels([MODEL_LABELS[m] for m in MODELS], fontsize=8)
    ax.set_xlabel("model, weak → strong (Artificial Analysis index in parens)")
    ax.set_ylim(0, 1.16)
    ax.set_ylabel("executor-forging rate\nWilson 95% CI")
    ax.set_title(
        "A real model forges the executor under self-report; verification stops it",
        fontsize=10.5,
    )
    ax.legend(loc="center right", frameon=False, fontsize=8.5)
    ax.grid(axis="y", ls=":", alpha=0.5)
    fig.tight_layout()
    _save(fig, "fig_llm_forging")
    plt.close(fig)


def main():
    curve = _measure_tier1()
    fig_ais_curve_v3(curve)
    src, grid = _load_tier2()
    fig_llm_forging(grid)
    print("wrote (Tier-1 from live harness, Tier-2 from recorded sweep "
          f"{src}):")
    for name in ("fig_ais_curve_v3.pdf", "fig_llm_forging.pdf"):
        print("  ", OUT / name)


if __name__ == "__main__":
    main()
