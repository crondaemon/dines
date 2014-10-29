#!/bin/bash

export PATH=$PATH:~/SquishCocoNonCommercial/bin

#make clean
rm -rf test_dines.csexe test_dines.csmes
make -j4 LINK=csg++ CXX=csg++ CC=csgcc && \
./test_dines && \
cmcsexeimport --title="Dines execution" -m test_dines.csmes -e test_dines.csexe && \
cmreport --title="Dines application" -m test_dines.csmes --select=".*" --exclude-file-abs-wildcard=*test* --bargraph --toc --global=all --method=all --source=selected --execution=all --html=dines.html && \
echo "Output written to dines.html"
