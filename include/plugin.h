#ifndef __PLUGIN_H__
#define __PLUGIN_H__

#include "common.h"

typedef struct flow_plugin_ops {
	uint32_t (*set)(uint32_t m);
	uint32_t (*get)();
} flow_plugin_ops_t;


#endif
