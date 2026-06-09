# AEGIS-AT — Research Paper

This directory holds the AEGIS-AT benchmark paper in three forms.

| File | What it is | Use it for |
| :--- | :--- | :--- |
| [`aegis-at.tex`](./aegis-at.tex) | Canonical LaTeX source (self-contained, standard packages) | arXiv / conference submission; the citable artifact |
| [`aegis-at.pdf`](./aegis-at.pdf) | Compiled output (17 pp., US-letter) | Reading / circulation |
| [`aegis-at.md`](./aegis-at.md) | GitHub-rendered Markdown companion | Browsing on GitHub; quick reference |

The `.tex` is the source of truth. The `.md` mirrors its content for GitHub
rendering (with MathJax for the metric definitions) but is not the citable form.

---

## Build the PDF

The paper compiles with any standard TeX distribution (TeX Live, MiKTeX). All
packages used are in the standard distribution; no custom `.sty` or `.bib` files
are needed (the bibliography is a self-contained `thebibliography`).

### With `make` (recommended)

```bash
cd Documents/Paper
make          # build aegis-at.pdf (runs pdflatex 3x: body, TOC, references)
make clean    # remove build artifacts (.aux .log .out .toc, keep .pdf)
make purge    # also remove the generated .pdf
```

### Manually

```bash
cd Documents/Paper
pdflatex -interaction=nonstopmode aegis-at.tex
pdflatex -interaction=nonstopmode aegis-at.tex   # resolve TOC + \ref / \cite
pdflatex -interaction=nonstopmode aegis-at.tex   # settle cross-references
```

Three passes are needed because the document has a table of contents and internal
cross-references; one pass leaves them unresolved.

### No LaTeX installed?

- **Overleaf** — create a blank project, paste `aegis-at.tex`, click *Recompile*.
- **arXiv** — upload `aegis-at.tex`; arXiv compiles source on its end.
- **MiKTeX (Windows)** — `winget install MiKTeX.MiKTeX`, then enable on-the-fly
  package installation once: `initexmf --set-config-value "[MPM]AutoInstall=1"`.
  Fresh installs may place `pdflatex` under
  `%LOCALAPPDATA%\Programs\MiKTeX\miktex\bin\x64\` rather than on `PATH`.
- **TeX Live (Linux/macOS)** — `apt install texlive-latex-recommended
  texlive-latex-extra` (or `brew install --cask mactex-no-gui`).

---

## Before submission

- [x] **Author block** — finalized (*Rahul Singh, Independent researcher, Jersey
      City, NJ*; email + GitHub). Add co-authors/affiliation if that changes.
- [x] **Citation check** — all 11 references verified against live primary sources
      (June 2026). The arXiv *Misattribution Gap* (2605.22842), NIST NCCoE, OpenID,
      CSA, HAID, Clinejection, and Salesloft Drift entries all resolve; two URLs
      were corrected in the process (NIST → `nccoe.nist.gov` canonical; Snyk
      Clinejection → `cline-supply-chain-attack-prompt-injection-github-actions`).
      Note: [`../References/References.md`](../References/References.md) still
      carries the older Snyk slug — reconcile if you want the repo fully consistent.
- [ ] **Numbers** — every quantitative claim (AIS curve, defect breakdown, 59 tests)
      matches the committed result in
      [`../ThreatModel/threat-model.md`](../ThreatModel/threat-model.md) §6 and the
      test suite. Re-run `pytest tests/core` if the code changes.

---

## License

Documentation in this directory is licensed **CC BY 4.0**, consistent with the rest
of `Documents/`. See [`../LICENSE-docs`](../LICENSE-docs).
