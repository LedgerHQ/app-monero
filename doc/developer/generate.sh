#!/bin/bash

rm -f blue-app-monero.pdf blue-app-monero.latex

pandoc -s --template=blue-app-monero.template -f rst+raw_tex -t latex --toc --toc-depth 4 -N -o blue-app-commands.pdf blue-app-commands.rst

#cp blue-app-monero.rst blue-app-monero.md-toc-depth
#pandoc -s --template=blue-app-monero.template  -t latex --toc -N -o blue-app-monero.md.pdf blue-app-monero.md

#rst2latex --latex-preamble='\usepackage{eufrak}' --input-encoding='utf8' blue-app-monero.rst blue-app-monero.latex;

#pdflatex -halt-on-error -output-format=pdf blue-app-monero.latex
