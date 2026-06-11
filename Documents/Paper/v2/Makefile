# AEGIS-AT v2 paper build.
#   make         -> build aegis-at-v2.pdf (alias: make paper)
#   make figures -> regenerate the figures from the live v2 harness
#   make clean   -> remove LaTeX build artifacts, keep the PDF
#   make purge   -> also remove the generated PDF
#
# Requires a TeX distribution (TeX Live or MiKTeX) providing pdflatex, plus
# matplotlib for `make figures` (see ../../requirements.txt).
# Two passes resolve the TOC and internal cross-references; the bibliography
# is a self-contained thebibliography, so no bibtex/biber pass is needed.

TEX      := aegis-at-v2
PDFLATEX ?= pdflatex
PYTHON   ?= python
FLAGS    := -interaction=nonstopmode -halt-on-error

.PHONY: all paper figures clean purge

all: $(TEX).pdf
paper: $(TEX).pdf

$(TEX).pdf: $(TEX).tex
	$(PDFLATEX) $(FLAGS) $(TEX).tex
	$(PDFLATEX) $(FLAGS) $(TEX).tex

# Regenerate the 3 paper figures from the live harness. Idempotent.
figures:
	$(PYTHON) figures/make_figures.py

clean:
	rm -f $(TEX).aux $(TEX).log $(TEX).out $(TEX).toc

purge: clean
	rm -f $(TEX).pdf
