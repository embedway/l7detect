#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include "parser.h"
#include "list.h"
#include "code.h"
#include "longmask.h"

typedef struct proto_comm {
	uint32_t app_id;
	packet_t *packet;
	uint32_t engine_mask;
	longmask_t **match_mask;
} proto_comm_t;

#endif
