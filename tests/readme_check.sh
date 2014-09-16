#!/bin/bash

# First take the help from REAME
readme=`cat README.md | sed -n "/HELP START/,/HELP END/p" | head -n-2 | tail -n+3`

# Then take help from dines
dines=`./dines --help`

if [ "$readme" != "$dines" ]
then
	echo "Error! Diff follows"
	diff -pu <(echo "$readme") <(echo "$dines")
	exit 1
fi

# Fine.
echo "README.md and dines help are OK"
exit 0
