
#ifndef __IN_CKSUM__
#define __IN_CKSUM__

#include <sys/types.h>

u_short in_cksum(u_short *addr, int len);

#endif
