#include <string.h>
#include "common.h"
#include "conf.h"

uint32_t engine_id_get(sf_proto_conf_t *conf, char *engine_name)
{
	uint32_t i;
	for (i=0; i<conf->total_engine_num; i++) {
		if (strcmp(conf->engines[i].name, engine_name) == 0)
			return i;/*id=lua中的id-1*/
	}
	return INVALID_ENGINE_ID;
}

uint32_t app_id_get(sf_proto_conf_t *conf, char *app_name)
{
	uint32_t i;
	for (i=0; i<conf->total_proto_num; i++) {
		if (strcmp(conf->protos[i].name, app_name) == 0)
			return i;/*id=lua-1*/
	}
	return INVALID_PROTO_ID;
}
