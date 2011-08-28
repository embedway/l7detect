#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <dlfcn.h>
#include "plugin.h"
#endif

#include "common.h"
#include "mem.h"
#include "module_manage.h"
#include "conf.h"
#include "parser.h"
#include "log.h"
#include "process.h"

static int32_t flow_frm_init(module_info_t *this);
static int32_t flow_frm_process(module_info_t *this, void *data);
//static void* flow_frm_get(module_info_t *this);
//static void flow_frm_free(module_info_t *this);
static int flow_frm_fini(module_info_t *this);
typedef flow_plugin_ops_t* (*init)();


module_ops_t flow_frm_ops = {					
	.init = flow_frm_init,
	.start = NULL,					
	.process = flow_frm_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini = flow_frm_fini,
};

static int32_t flow_frm_init(module_info_t *this)
{
	void *handle;
	char *error;
	flow_plugin_ops_t *ops;
	init plugin_init;
	//flow_plugin_ops_t* (*plugin_init)();
	int32_t res;
	
	handle = dlopen (".libs/flow_pde.so", RTLD_LAZY);
	assert(handle);

	dlerror();    /* Clear any existing error */
	plugin_init = (init)dlsym(handle, "flow_pde_init");
	if ((error = dlerror()) != NULL)  {
		log_error(syslog_p, "%s", dlerror());
		exit(-1);
	}

	ops = plugin_init();
	res = ops->set(811208);
	log_notice(syslog_p, "set result %d\n", res);
	log_notice(syslog_p, "get result %d\n", ops->get());
	dlclose(handle);
	return 0;
}


static int32_t flow_frm_process(module_info_t *this, void *data)
{
	return 0;
}

static int32_t flow_frm_fini(module_info_t *this)
{
	return 0;
}
