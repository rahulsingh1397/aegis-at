# AEGIS-AT — Papers

This directory holds the AEGIS-AT benchmark papers, organized to mirror the
repository's `v1/` (frozen) / `v2/` (active) split.

| Version | Path | Title | Length | Status |
| :---: | :--- | :--- | :---: | :--- |
| **v1** | [`v1/aegis-at.tex`](./v1/aegis-at.tex) ·  [`v1/aegis-at.pdf`](./v1/aegis-at.pdf) | *AEGIS-AT: Measuring Attribution Integrity Under Sibling Impersonation in Multi-Agent Delegation* | 17 pp | Frozen with [`v1/`](../../v1/) (git tag `v1.0.0`) |
| **v2** | [`v2/aegis-at-v2.tex`](./v2/aegis-at-v2.tex) ·  [`v2/aegis-at-v2.pdf`](./v2/aegis-at-v2.pdf) | *AEGIS-AT v2: Does Sender-Constraint Recover Attribution?* | 14 pp | Active; extends v1 with Baseline 5 (DPoP), LIS, T2, stochastic CIs |

`.tex` is the citable source of truth for each version. v1 also keeps a
GitHub-rendered [`aegis-at.md`](./v1/aegis-at.md) companion.

---

## Layout

```
Documents/Paper/
├── README.md                  this file — directory index
├── v1/
│   ├── aegis-at.tex           frozen v1 LaTeX source
│   ├── aegis-at.pdf           compiled v1 (17 pp)
│   ├── aegis-at.md            GitHub-rendered v1 companion
│   ├── Makefile               builds aegis-at.pdf
│   └── EDIT_PLAN_sentinelagent_relatedwork.md   v1 editorial planning notes
└── v2/
    ├── aegis-at-v2.tex        v2 LaTeX source
    ├── aegis-at-v2.pdf        compiled v2 (14 pp)
    ├── Makefile               builds aegis-at-v2.pdf; also `make figures`
    └── figures/
        ├── make_figures.py    regenerates the 3 figures from the live harness
        ├── fig_ais_curve.{pdf,png}
        ├── fig_ais_lis.{pdf,png}
        └── fig_stochastic_ci.{pdf,png}
```

The v2 paper uses `\graphicspath{{figures/}}`, so its `.tex` and
`figures/` are intentionally co-located.

---

## Building

Both papers compile with any standard TeX distribution (TeX Live, MiKTeX).
Each uses only standard packages — no custom `.sty` / `.bib`; the bibliography
is a self-contained `thebibliography`.

```bash
# v1 (frozen — should never change)
cd Documents/Paper/v1 && make           # builds aegis-at.pdf

# v2 (active)
cd Documents/Paper/v2 && make figures   # regenerate figures from the harness
make                                    # then build aegis-at-v2.pdf
```

Manually (two passes resolve the TOC + cross-references):

```bash
cd Documents/Paper/v2
pdflatex -interaction=nonstopmode aegis-at-v2.tex
pdflatex -interaction=nonstopmode aegis-at-v2.tex
```

### v2 figure regeneration

The figures are **not hand-drawn**; they are produced from the live v2
harness — `sweep.emit_curves()`, `sweep.emit_lis_curve()`, and
`stochastic.stochastic_sweep()`. So the numbers in the paper cannot drift
from the code:

```bash
python Documents/Paper/v2/figures/make_figures.py
```

This writes both `.pdf` (vector, for the LaTeX build) and `.png` (raster,
for the README and GitHub) alongside the script. The script anchors all
paths off its own location, so it works regardless of `cwd`.

### No LaTeX installed?

- **Overleaf** — paste the relevant `.tex` into a blank project; click *Recompile*.
- **arXiv** — upload the `.tex`; arXiv compiles on its end.
- **TeX Live (Linux/macOS)** — `apt install texlive-latex-recommended texlive-latex-extra` or `brew install --cask mactex-no-gui`.
- **MiKTeX (Windows)** — `winget install MiKTeX.MiKTeX` then `initexmf --set-config-value "[MPM]AutoInstall=1"`.

---

## Pre-registration and reproducibility

Every quantitative claim in the v2 paper — the AIS curve on both topologies,
the LIS curve, every stochastic cell — is asserted in the v2 test suite
against a value pre-registered in
[`Documents/ThreatModel/ThreatModelv2/threat-model-v2.md`](../ThreatModel/ThreatModelv2/threat-model-v2.md)
(plus its [`threat-model-v2.1.md`](../ThreatModel/ThreatModelv2/threat-model-v2.1.md)
amendment), both SHA-256-locked by the CI gate. A contradicted prediction is
reported as a finding, not reconciled (INV-7).

The v1 paper's numbers are similarly fixed by `Documents/ThreatModel/threat-model.md`
and the 59 frozen tests under `v1/tests/core/`.

---

## License

Documentation in this directory is licensed **CC BY 4.0**, consistent with the
rest of `Documents/`. See [`../LICENSE-docs`](../LICENSE-docs).
