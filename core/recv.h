#ifndef __RECV_H__
#define __RECV_H__

#include "common.h"
#include "module_manage.h"
#define MAX_PACKET_LEN 1518

typedef struct packet {
	uint32_t len;
	uint8_t data[0];
} packet_t;

extern module_ops_t recv_mod_ops;

#endif
