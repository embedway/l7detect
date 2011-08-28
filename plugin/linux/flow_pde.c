#include "common.h"
#include "plugin.h"

static uint32_t flow_pde_set(uint32_t m);
static uint32_t flow_pde_get();

static uint32_t global_m;

flow_plugin_ops_t flow_pde_ops = {
	.set = flow_pde_set,
    .get = flow_pde_get,
};

flow_plugin_ops_t *flow_pde_init()
{
	return &flow_pde_ops;
}
static uint32_t flow_pde_set(uint32_t m)
{
	global_m = m + 2;
	return 0;
}

static uint32_t flow_pde_get()
{
	return global_m;
}
