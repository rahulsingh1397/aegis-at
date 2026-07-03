# AEGIS-AT v3 paper build.
#   make         -> build aegis-at-v3.pdf (alias: make paper)
#   make figures -> regenerate the figures (Tier-1 from the live v3 harness;
#                   Tier-2 from the frozen sweep in data/llm_sweep_v3.json)
#   make clean   -> remove LaTeX build artifacts, keep the PDF
#   make purge   -> also remove the generated PDF
#
# Requires a TeX distribution (TeX Live or MiKTeX) providing pdflatex, plus
# matplotlib for `make figures` (see ../../../requirements.txt).
# Two passes resolve the TOC and internal cross-references; the bibliography
# is a self-contained thebibliography, so no bibtex/biber pass is needed.

TEX      := aegis-at-v3
PDFLATEX ?= pdflatex
PYTHON   ?= python
FLAGS    := -interaction=nonstopmode -halt-on-error

.PHONY: all paper figures clean purge

all: $(TEX).pdf
paper: $(TEX).pdf

$(TEX).pdf: $(TEX).tex
	$(PDFLATEX) $(FLAGS) $(TEX).tex
	$(PDFLATEX) $(FLAGS) $(TEX).tex

# Regenerate the 2 paper figures (Tier-1 from the live harness, Tier-2 from the
# recorded sweep). Idempotent.
figures:
	$(PYTHON) figures/make_figures.py

clean:
	rm -f $(TEX).aux $(TEX).log $(TEX).out $(TEX).toc

purge: clean
	rm -f $(TEX).pdf
