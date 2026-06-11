# AEGIS-AT paper build.
#   make         -> build aegis-at.pdf (alias: make paper)
#   make clean   -> remove LaTeX build artifacts, keep the PDF
#   make purge   -> also remove the generated PDF
#
# Requires a TeX distribution (TeX Live or MiKTeX) providing pdflatex.
# Three passes resolve the table of contents and internal cross-references.
# The bibliography is a self-contained thebibliography, so no bibtex/biber pass
# is needed.

TEX     := aegis-at
PDFLATEX ?= pdflatex
FLAGS   := -interaction=nonstopmode -halt-on-error

.PHONY: all paper clean purge

all: $(TEX).pdf
paper: $(TEX).pdf

$(TEX).pdf: $(TEX).tex
	$(PDFLATEX) $(FLAGS) $(TEX).tex
	$(PDFLATEX) $(FLAGS) $(TEX).tex
	$(PDFLATEX) $(FLAGS) $(TEX).tex

clean:
	rm -f $(TEX).aux $(TEX).log $(TEX).out $(TEX).toc

purge: clean
	rm -f $(TEX).pdf
