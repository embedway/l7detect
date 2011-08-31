#include <string.h>

#include "common.h"
#include "plugin.h"
#include "module_manage.h"
#include "conf.h"
#include "log.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

static int32_t pde_engine_init(module_info_t *this);
static int32_t pde_engine_process(module_info_t *this, void *data);

module_ops_t pde_engine_ops = {
	.init = pde_engine_init,
	.start = NULL,
	.process = pde_engine_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini = NULL,
};
typedef struct pde_engine_info{
	
} pde_engine_info;


static int32_t pde_engine_init(module_info_t *this)
{
	//sf_plugin_conf_t *conf = (sf_plugin_conf_t *)this->resource;
	lua_State *L = luaL_newstate();
	char *buff = "print(\"Lua hello\")";
	int error;

	luaL_openlibs(L);
	
	error = luaL_loadbuffer(L, buff, strlen(buff), "line") || lua_pcall(L, 0, 0, 0);
	if (error) {
		fprintf(stderr, "%s", lua_tostring(L, -1));
		lua_pop(L, 1);
	}
		
	lua_close(L);


	return 0;
}
static int32_t pde_engine_process(module_info_t *this, void *data)
{
#if 0
	packet_t *packet = (packet_t *)data;
	void *app_data = packet->data + packet->app_offset;
	uint32_t app_len = packet->len - packet->app_offset;
#endif		
	

	
	return 0;
}
