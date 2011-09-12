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
static uint32_t __push_line_from_buffer(char *data, char *buffer_line, uint32_t len)
{
/*返回读取的长度*/
	for (i=0; i<len; i++) {
		if (data[i] == '\n' || data[i] == '\0') {
			buffer_line[i++] = '\0';
			break;
		} else {
			buffer_line[i] = data[i];
		}
	}
	if (buffer_line[i] != '\n' && buffer_line[i] != '\0') {
		buffer_line[i+1] = '\0';
	}
	if (strlen(buffer_line) > 0) {
		lua_pushstring(L, buffer_line);
	}
	return i;
}

static int incomplete (lua_State *L, int status) {
	if (status == LUA_ERRSYNTAX) {
		size_t lmsg;
		const char *msg = lua_tolstring(L, -1, &lmsg);
		const char *tp = msg + lmsg - (sizeof(LUA_QL("<eof>")) - 1);
		if (strstr(msg, LUA_QL("<eof>")) == tp) {
			lua_pop(L, 1);
			return 1;
		}
	}
	return 0;  /* else... */
}

static int32_t __luaL_loadbuffer(lua_State *L, char *data, uint32_t len, char *name)
{
	uint32_t i, rec = 0;
	char buffer[100];
	int error;
	uint32_t buffer_len, rd_len = 0;

	lua_settop(L, 0);
	while(rd_len < len) {
		buffer_len = __push_line_from_buffer(data+rd_len, buffer, len-rd_len);
		rd_len += buffer_len;
		if (strlen(buffer) > 0) {
			status = luaL_loadbuffer(L, lua_tostring(L, 1), lua_strlen(L, 1), name);
			if (!incomplete(L, status)) break;  /* cannot try to add lines? */
			
		}
	}
}
#endif

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

static int32_t pde_engine_init(module_info_t *this)
{
	sf_plugin_conf_t *conf = (sf_plugin_conf_t *)this->resource;
	lua_State *L;
	pde_engine_info *info;

	zmalloc(info, pde_engine_info *, sizeof(pde_engine_info));
	L = luaL_newstate();
	assert(L);
	
	LDLUA_INIT(L);
	
	info->lua_v = L;
	info->conf = conf;
	
	__luaL_loadbuffer(L, conf->data, strlen(conf->data), "pde");

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
