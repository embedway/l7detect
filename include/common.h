#ifndef __COMMON_H__
#define __COMMON_H__

#include <sys/types.h>
#include "code.h"

typedef u_int8_t uint8_t;
typedef u_int16_t uint16_t;
typedef u_int32_t uint32_t;
typedef u_int64_t uint64_t;

#ifndef __linux__
#define LITTLE_ENDIAN 0x1234
#define BIG_ENDIAN 0x4321
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#endif
