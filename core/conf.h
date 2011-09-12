#ifndef __CONF_H__
#define __CONF_H__

#include "common.h"
#include "list.h"

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

typedef struct sf_plugin_conf {
	char *name;
	char data[1024];
}sf_plugin_conf_t;

typedef struct conf {
	int mode;
	union {
		char *device;
		char *capfile;
	} u;
	char *logfile;
	list_head_t module_conf_head;
} conf_t;

extern conf_t g_conf;

int32_t conf_init();
int32_t conf_read(int argc, char *argv[]);
int32_t conf_module_config_insert(char *name, void *config, uint32_t size);
void* conf_module_config_search(char *name, void *pos);
int32_t conf_fini();

#endif
