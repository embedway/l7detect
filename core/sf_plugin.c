#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef __linux__
#include <dlfcn.h>
#include "plugin.h"
#endif
	
#include "common.h"
#include "log.h"
#include "conf.h"
#include "module_manage.h"
#include "sf_plugin.h"

static int32_t sf_plugin_init(module_info_t *this);
static int32_t sf_plugin_process(module_info_t *this, void *data);
static int32_t sf_plugin_fini(module_info_t *this);

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
} sf_plugin_info_t;

static int32_t sf_plugin_init(module_info_t *this)
{
	module_ops_t *ops;
	sf_plugin_conf_t *pconf;
	sf_plugin_info_t *info;
	char filename[MAX_STRING_LEN];
	char opsname[MAX_STRING_LEN];
	uint32_t plugin_num, i;
	module_info_t *plugin_info;
	int32_t status;

	info = malloc(sizeof(sf_plugin_info_t));
	assert(info);
	
	memset(info, 0, sizeof(sf_plugin_info_t));

	pconf = NULL;
	plugin_num = 0;
	i = 0;
	do {
		pconf = conf_module_config_search("sf_plugin", pconf);
		if (pconf != NULL) {
			plugin_num++;
		} 
	}while (pconf != NULL);

	info->plugin = module_list_create(plugin_num);
	info->plugin_num = plugin_num;
	info->handle = zmalloc(void **, sizeof(void *) * plugin_num);
	if_error_return(info->handle != NULL, -NO_SPACE_ERROR);
	i = 0;

	do {
		pconf = conf_module_config_search("sf_plugin", pconf);
		if (pconf != NULL) {
			sprintf(filename, ".libs/%s.so", pconf->name);
			log_notice(syslog_p, "open plugin %s\n", pconf->name); 
			info->handle[i] = dlopen(filename, RTLD_LAZY);
			log_notice(syslog_p, "plugin handle %p\n", info->handle[i]); 
			assert(info->handle[i]);
			
			sprintf(opsname, "%s_ops", pconf->name);
			
			ops = (module_ops_t *)dlsym(info->handle[i], opsname);
			
			if (dlerror() != NULL)  {
				log_error(syslog_p, "%s", dlerror());
				exit(-1);
			}
			assert(ops);
			status = module_list_add(info->plugin, pconf->name, ops);
			assert(status == 0);

/*fixme:查到对应的plugin，通过设置resource来传入配置*/
			plugin_info = module_info_get_from_name(info->plugin, pconf->name);
			assert(plugin_info);

			plugin_info->resource = pconf;
			i++;
		} else {
			break;
		}
	} while (1);
	
	module_list_init(info->plugin);
	this->resource = info;	
	return 0;
}

static int32_t sf_plugin_process(module_info_t *this, void *data)
{
	sf_plugin_info_t *info;
	
	info = (sf_plugin_info_t *)this->resource;
	module_list_process(info->plugin, NULL, data);
	return 0;
}

static int32_t sf_plugin_fini(module_info_t *this)
{
	uint32_t i;
	sf_plugin_info_t *info;
	
	info = (sf_plugin_info_t *)this->resource;
	module_manage_fini(&info->plugin);
	
	for (i=0; i<info->plugin_num; i++) {
		if (info->handle[i] != NULL) {
			log_notice(syslog_p, "plugin  %p close\n", info->handle[i]); 	
			dlclose(info->handle[i]);
		}
	}
	free(info->handle);
	free(info);
	return 0;
}

