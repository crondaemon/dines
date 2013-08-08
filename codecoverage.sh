#!/bin/bash
export PATH=$PATH:/home/dario/SquishCocoNonCommercial/bin
make clean
make LINK=csg++ CXX=csg++ CC=csgcc
rm test_dines.csexe
./test_dines
cmcsexeimport --title="dines test" -m test_dines.csmes -e test_dines.csexe
cmreport --title="dines test" -m test_dines.csmes --select=".*" --bargraph --toc --global=all --method=all --source=all --execution=all --html=dines.html
