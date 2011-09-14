#include <string.h>
#include <assert.h>
#include "common.h"
#include "plugin.h"
#include "module_manage.h"
#include "conf.h"
#include "log.h"
#include "parser.h"


#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "ldlua.h"

static int32_t pde_engine_init(module_info_t *this);
static int32_t pde_engine_process(module_info_t *this, void *data);
static int32_t pde_engine_fini(module_info_t *this);

module_ops_t pde_engine_ops = {
	.init = pde_engine_init,
	.start = NULL,
	.process = pde_engine_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini = pde_engine_fini,
};
typedef struct pde_engine_info{
	lua_State *lua_v;
	sf_plugin_conf_t *conf;
} pde_engine_info;

#if 0
static void l_message (const char *pname, const char *msg) {
	if (pname) fprintf(stderr, "%s: ", pname);
	fprintf(stderr, "%s\n", msg);
	fflush(stderr);
}

static int report (lua_State *L, int status) {
	if (status && !lua_isnil(L, -1)) {
		const char *msg = lua_tostring(L, -1);
		if (msg == NULL) msg = "(error object is not a string)";
		l_message("l7detect", msg);
		lua_pop(L, 1);
	}
	return status;
}

static int32_t __luaL_loadbuffer(lua_State *L, char *data, uint32_t len, char *name)
{
	int status = luaL_loadbuffer(L, data, len, name) || lua_pcall(L, 0, 0, 0);
	return report(L, status);
}
#endif

static int32_t pde_engine_init(module_info_t *this)
{
	sf_plugin_conf_t *conf = (sf_plugin_conf_t *)this->resource;
	lua_State *L;
	pde_engine_info *info;

	info = zmalloc(pde_engine_info *, sizeof(pde_engine_info));
	if_error_return(info != NULL, -NO_SPACE_ERROR);
	L = luaL_newstate();
	assert(L);
	
	LDLUA_INIT(L);
	
	info->lua_v = L;
	info->conf = conf;
	
	//__luaL_loadbuffer(L, conf->data, strlen(conf->data), "pde");

	/*必须在此之前处理完所有的配置*/	
	this->resource = (pde_engine_info *)info;
	return 0;
}

static int32_t pde_engine_process(module_info_t *this, void *data)
{
	packet_t *packet = (packet_t *)data;
	//void *app_data = packet->data + packet->app_offset;
	//uint32_t app_len = packet->len - packet->app_offset;

	pde_engine_info *info;
	sf_plugin_conf_t *conf;
	lua_State *L;
	int error;
	
	info = (pde_engine_info *)this->resource;
	conf = info->conf;
	L = info->lua_v;

	lua_getglobal(L, "fx");
	push_pkb_to_stack(L, packet);
	error = lua_pcall(L, 1, 0, 0);
	luaL_openlibs(L);
	if (error) {
		fprintf(stderr, "%s", lua_tostring(L, -1));
		lua_pop(L, 1);
	}
	
	return 0;
}

static int32_t pde_engine_fini(module_info_t *this)
{
	pde_engine_info *info;
	
	info = (pde_engine_info *)this->resource;
	if (info->lua_v != NULL) {
		lua_close(info->lua_v);
	}
	return 0;
}
