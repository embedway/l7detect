#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef __linux__
#include <dlfcn.h>
#endif
	
#include "common.h"
#include "log.h"
#include "conf.h"
#include "module_manage.h"
#include "sf_plugin.h"
#include "plugin.h"
#include "process.h"

static int32_t sf_plugin_init(module_info_t *this);
static int32_t sf_plugin_process(module_info_t *this, void *data);
static int32_t sf_plugin_fini(module_info_t *this);
static uint16_t parsed_tag;
#define MAX_STRING_LEN 80

module_ops_t sf_plugin_ops = {					
	.init = sf_plugin_init,
	.process = sf_plugin_process,
	.fini = sf_plugin_fini,
};

typedef struct sf_plugin_info {
	uint32_t plugin_num;
	void **handle;
	module_hd_t *plugin;
	tag_hd_t *tag;
	sf_proto_conf_t *pconf;
	proto_comm_t proto_comm;
} sf_plugin_info_t;

static int32_t sf_plugin_init(module_info_t *this)
{
	module_ops_t *ops;
	sf_plugin_info_t *info;
	char filename[MAX_STRING_LEN];
	char opsname[MAX_STRING_LEN];
	uint32_t i;
	module_info_t *plugin_info;
	int32_t status;
	sf_proto_conf_t *pconf;
	proto_comm_t *proto_comm;


	info = zmalloc(sf_plugin_info_t *, sizeof(sf_plugin_info_t));
	assert(info);

	this->resource = info;
	pconf = conf_module_config_search(SF_PROTO_CONF_NAME, NULL);
	assert(pconf);	

	info->plugin_num = pconf->total_engine_num;
	info->pconf = pconf;
	
	if (info->plugin_num == 0) {
		return 0;
	}
	info->plugin = module_list_create(info->plugin_num);
	assert(info->plugin);
	
	info->tag = tag_init(info->plugin_num);
	assert(info->tag);
	log_debug(syslog_p, "plugin number %d\n", info->plugin_num);
	
	info->handle = zmalloc(void **, sizeof(void *) * info->plugin_num);
	if_error_return(info->handle != NULL, -NO_SPACE_ERROR);
	i = 0;

	for (i=0; i<pconf->total_engine_num; i++) {
		sprintf(filename, ".libs/%s_engine.so", pconf->engines[i].name);
		log_notice(syslog_p, "open plugin %s\n", filename); 
		info->handle[i] = dlopen(filename, RTLD_LAZY);
		log_notice(syslog_p, "plugin handle %p\n", info->handle[i]); 
		if (!info->handle[i]) {
			log_notice(syslog_p, "%s\n", dlerror());
		}
		assert(info->handle[i]);
		
		sprintf(opsname, "%s_engine_ops", pconf->engines[i].name);
		
		ops = (module_ops_t *)dlsym(info->handle[i], opsname);
		
		if (dlerror() != NULL)  {
			log_error(syslog_p, "%s\n", dlerror());
			exit(-1);
		}
		assert(ops);
		status = module_list_add(info->plugin, pconf->engines[i].name, ops);
		assert(status == 0);
		
		tag_register(info->tag, pconf->engines[i].name);
		module_tag_bind(info->plugin, info->tag, pconf->engines[i].name, pconf->engines[i].name);
		
/*fixme:查到对应的plugin，通过设置resource来传入配置*/
		plugin_info = module_info_get_from_name(info->plugin, pconf->engines[i].name);
		assert(plugin_info);
		pconf->proto_log = syslog_p;
		plugin_info->resource = pconf;
	} 

	proto_comm = &info->proto_comm;
	proto_comm->match_mask = zmalloc(longmask_t **, sizeof(longmask_t *) * pconf->total_engine_num);
	assert(proto_comm->match_mask);

	for (i=0; i<pconf->total_engine_num; i++) {
		proto_comm->match_mask[i] = longmask_create(pconf->total_proto_num);
		assert(proto_comm->match_mask[i]);
	}
	
	parsed_tag = tag_id_get_from_name(pktag_hd_p, "parsed");
	module_list_init(info->plugin);
	
	return 0;
}

static int32_t sf_plugin_process(module_info_t *this, void *data)
{
	sf_plugin_info_t *info;
	proto_comm_t *proto_comm;
	sf_proto_conf_t *pconf;
	uint32_t i;
	packet_t *packet = (packet_t *)data;

	info = (sf_plugin_info_t *)this->resource;
	pconf = info->pconf;
	proto_comm = &info->proto_comm;

	proto_comm->packet = data;
	proto_comm->engine_mask = 0;
	proto_comm->app_id = INVALID_PROTO_ID;
	
	for (i=0; i<pconf->total_engine_num; i++) {
		longmask_all_clr(proto_comm->match_mask[i]);
	}

	if (info->plugin_num) {
		module_list_process(info->plugin, info->tag, -1, proto_comm);
	}
	if (proto_comm->app_id != INVALID_PROTO_ID) {
		packet->app_type = proto_comm->app_id;
	}
	packet->pktag = parsed_tag;
	
	return packet->pktag;
}

static int32_t sf_plugin_fini(module_info_t *this)
{
	uint32_t i;
	sf_plugin_info_t *info;
	sf_proto_conf_t *pconf;

	info = (sf_plugin_info_t *)this->resource;
	module_manage_fini(&info->plugin);
	tag_fini(&info->tag);

	pconf = info->pconf;
	for (i=0; i<info->plugin_num; i++) {
		if (info->handle[i] != NULL) {
			log_notice(syslog_p, "plugin  %p close\n", info->handle[i]); 	
			dlclose(info->handle[i]);
		}
	}
	free(info->handle);
	for (i=0; i<pconf->total_engine_num; i++) {
		longmask_destroy(info->proto_comm.match_mask[i]);
	}
	free(info->proto_comm.match_mask);
	free(info);
	return 0;
}

