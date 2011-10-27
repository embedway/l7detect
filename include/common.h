#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include "code.h"

#define MAX_WORKER_THREAD 16

/*
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
*/
//typedef u_int8_t uint8_t;
//typedef u_int16_t uint16_t;
//typedef u_int32_t uint32_t;
//typedef u_int64_t uint64_t;

#ifndef __linux__
#define LITTLE_ENDIAN 0x1234
#define BIG_ENDIAN 0x4321
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#endif
