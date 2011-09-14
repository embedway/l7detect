#ifndef __CONF_H__
#define __CONF_H__
#include <stdlib.h>
#include "common.h"
#include "list.h"
#include "lua_ci.h"

#define common_free_cb free
#define ENGINE_NAME_LEN 10

enum {
	MODE_NOT_SET,
	MODE_LIVE,
	MODE_FILE,
};

typedef struct session_conf {
	uint32_t bucket_num;
	uint32_t session_expire_time;
	char *hash_name;
	char *session_logname;
} session_conf_t;

typedef struct proto_engine_data {
	int16_t lua_type;
	void *data;
} proto_engine_data_t;

typedef struct proto_conf {
	char *name;
	uint16_t engine_mask;
	proto_engine_data_t *engine_data;
} proto_conf_t;

typedef struct detect_engine {
	char name[ENGINE_NAME_LEN];
} detect_engine_t;

typedef struct sf_plugin_conf {
	char *name;
	lua_State *L;
	char *app_luabuf;
	uint32_t total_engine_num;
	uint32_t total_proto_num;
	detect_engine_t *engines;
	proto_conf_t *protos;
}sf_plugin_conf_t;

typedef struct conf {
	int mode;
	union {
		char *device;
		char *capfile;
	} u;
	char *logfile;
	char *protofile;
	list_head_t module_conf_head;
} conf_t;

typedef void (*conf_node_free_callback)(void *data);

extern conf_t g_conf;

int32_t conf_init();
int32_t conf_read(int argc, char *argv[]);
int32_t conf_module_config_insert(char *name, void *config, conf_node_free_callback free_cb);
void* conf_module_config_search(char *name, void *pos);
int32_t conf_fini();

#endif
