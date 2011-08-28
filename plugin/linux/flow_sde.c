#include "common.h"
#include "plugin.h"

static uint32_t flow_sde_set(uint32_t m);
static uint32_t flow_sde_get();

static uint32_t global_m;

flow_plugin_ops_t flow_sde_ops = {
	.set = flow_sde_set,
    .get = flow_sde_get,
};

flow_plugin_ops_t *flow_sde_init()
{
	return &flow_sde_ops;
}
static uint32_t flow_sde_set(uint32_t m)
{
	global_m = m;
	return 0;
}

static uint32_t flow_sde_get()
{
	return global_m;
}
