
#ifndef __DEBUG_HPP__
#define __DEBUG_HPP__

#include <stdio.h>

#define PRINT_HEX(buf, len, separator) \
{ \
    unsigned i; \
    for (i = 0; i < len; i++) { \
        printf("%.2X%s", *((u_char*)&((char*)buf)[i]), separator); \
    } \
}

#endif
