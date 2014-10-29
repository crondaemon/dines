#!/bin/bash

# before lauching this, compile dines with
# ./configure --enable-gcov

make -j && \
./test_dines && \
lcov --capture --directory . --output-file coverage.info && \
genhtml coverage.info --output-directory dines_html
