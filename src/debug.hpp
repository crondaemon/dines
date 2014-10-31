#ifndef __DEBUG_HPP__
#define __DEBUG_HPP__

#include <stdio.h>
#include <iostream>

using namespace std;

#define PRINT_HEX(buf, len, separator) \
{ \
    unsigned i; \
    for (i = 0; i < len; i++) { \
        printf("%.2X%s", *((u_char*)&((char*)buf)[i]), separator); \
    } \
}

#define LINE_TRACER(x) { cout << __PRETTY_FUNCTION__ << ":" << __LINE__ << " CHECKPOINT\n"; }

#endif
