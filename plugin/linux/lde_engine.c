#include <string.h>
#include <assert.h>
#include "common.h"
#include "plugin.h"
#include "module_manage.h"
#include "conf.h"
#include "log.h"
#include "parser.h"
#include "helper.h"
#include "engine_comm.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "ldlua.h"

static int32_t lde_engine_init(module_info_t *this);
static int32_t lde_engine_process(module_info_t *this, void *data);
static int32_t lde_engine_fini(module_info_t *this);
static log_t *pt_log;

module_ops_t lde_engine_ops = {
	.init = lde_engine_init,
	.start = NULL,
	.process = lde_engine_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini = lde_engine_fini,
};
typedef struct lde_engine_info{
	packet_t *packet;
	lua_State *lua_v;
	sf_proto_conf_t *conf;
	longmask_t *lde_pre;/*前面有别的引擎的掩码*/
	longmask_t *lde_cur;/*lde引擎开始的掩码*/
	uint32_t lde_engine_id;
} lde_engine_info_t;

static int32_t __lde_conf_read(sf_proto_conf_t *conf, uint32_t lde_engine_id, 
							   longmask_t *lde_pre, longmask_t *lde_cur)
{
	uint32_t i;
	for (i=0; i<conf->total_proto_num; i++) {
		uint32_t engine_mask = conf->protos[i].engine_mask;
		if ((engine_mask & (1<<lde_engine_id)) == 0) {
			continue;
		}
		if ((engine_mask & ~((0xffffffff) << lde_engine_id)) != 0) {
			/*lde前面还有别的引擎*/
			longmask_bit_set(lde_pre, i);
		} else {
			longmask_bit_set(lde_cur, i);
		}
	}
	return 0;
}

static int32_t lde_match(void *data, uint32_t app_id)
{
	lde_engine_info_t *info;
	sf_proto_conf_t *conf;
	lua_State *L;
	packet_t *packet;
	int error, state;


	info = (lde_engine_info_t *)data;
	conf = info->conf;
	L = info->lua_v;
	packet = info->packet;
	
	lua_getglobal(L, conf->protos[app_id].name);
	lua_getfield(L, -1, "lde");
	push_pkb_to_stack(L, packet);
	error = lua_pcall(L, 1, 1, 0);
	
	if (error) {
		log_error(pt_log, "%s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
	} else {
		state = lua_tonumber(L, -1);
		lua_pop(L, 2);
		if (state == 9) {
			printf("app %s, state %d\n", conf->protos[app_id].name, state);
			return 0;
		}
	}
	return 1;
}

static int32_t lde_engine_init(module_info_t *this)
{
	sf_proto_conf_t *conf = (sf_proto_conf_t *)this->resource;
	lde_engine_info_t *info;
	lua_State *L;
	int error;

	pt_log = conf->proto_log;
	info = zmalloc(lde_engine_info_t *, sizeof(lde_engine_info_t));
	assert(info);

	info->lde_pre = longmask_create(conf->total_proto_num);
	assert(info->lde_pre);

	info->lde_cur = longmask_create(conf->total_proto_num);
	assert(info->lde_cur);

	L = luaL_newstate();
	assert(L);
	PKB_LUA_INIT(L);
	luaL_loadbuffer(L, conf->app_luabuf, strlen(conf->app_luabuf), "lde_engine");
	error = lua_pcall(L, 0, 0, 0);
	if (error) {
		err_print("%s\n", lua_tostring(L, -1));
		lua_pop(L, 1);
		return -1;
	}
	lua_settop(L, 0);
	info->lua_v = L;
	
	info->conf = conf;
	info->lde_engine_id = engine_id_get(conf, "lde");
	assert(info->lde_engine_id != INVALID_ENGINE_ID);

	__lde_conf_read(conf, info->lde_engine_id, info->lde_pre, info->lde_cur);
	this->resource = (lde_engine_info_t *)info;
	return 0;
}

static int32_t lde_engine_process(module_info_t *this, void *data)
{
	proto_comm_t *proto_comm;
	packet_t *packet;
	lde_engine_info_t *info;
	sf_proto_conf_t *conf;
	lua_State *L;
	uint32_t tag = 0;
	int32_t app_id;

	proto_comm = (proto_comm_t *)data;
	packet = proto_comm->packet;
	info = (lde_engine_info_t *)this->resource;
	conf = info->conf;
	L = info->lua_v;

	info->packet = packet;

	app_id = handle_engine_appid(conf, proto_comm->match_mask[info->lde_engine_id], 
								 lde_match, info,
								 proto_comm->match_mask, info->lde_engine_id, &tag, 1);

	longmask_all_clr(proto_comm->match_mask[info->lde_engine_id]);
	if (app_id < 0) {
		app_id = handle_engine_appid(conf, info->lde_cur, 
									 lde_match,  info,
									 proto_comm->match_mask, info->lde_engine_id, &tag, 0);
			
	}
	if (app_id > 0) {
		proto_comm->app_id = app_id;
		print("app_id=%d\n", app_id);
	} 
	return tag;
}

static int32_t lde_engine_fini(module_info_t *this)
{
	lde_engine_info_t *info;
	
	info = (lde_engine_info_t *)this->resource;
	if (info->lua_v) {
		lua_close(info->lua_v);
	}
	if (info->lde_pre) {
		longmask_destroy(info->lde_pre);
	}

	if (info->lde_cur) {
		longmask_destroy(info->lde_cur);
	}

	free(info);
	return 0;
}
