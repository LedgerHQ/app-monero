#!/bin/bash

rm -f bolos-app-monero.pdf bolos-app-monero.latex

pandoc -s --variable graphics --template=bolos-app-monero.template -f rst+raw_tex+line_blocks+citations -t latex --toc -N -o bolos-app-monero.pdf bolos-app-monero.rst
