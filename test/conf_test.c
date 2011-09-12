#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "common.h"
#include "conf.h"
#include "log.h"

int32_t conf_test()
{
	int32_t status;
	uint32_t i;
	session_conf_t session_conf;
	sf_plugin_conf_t sf_plugin_conf;
	void *pos = NULL;
	
	char *sf_plugin_name[] = {
		"pde_engine"
		//"flow_sde",
	};
	
	session_conf.bucket_num = (1<<14) - 1;
	session_conf.session_expire_time = 30;
	session_conf.hash_name = "hash_xor";
	session_conf.session_logname = "/tmp/session.csv";
	status = conf_module_config_insert("session", &session_conf, sizeof(session_conf));
	
	for (i=0; i<sizeof(sf_plugin_name)/sizeof(sf_plugin_name[0]); i++) {
		sf_plugin_conf.name = sf_plugin_name[i];
		status = conf_module_config_insert("sf_plugin", &sf_plugin_conf, sizeof(sf_plugin_conf));
		if (status != 0) {
			fprintf(stderr, "<Error>:Plugin %s configure read error, status %d\n", sf_plugin_name[i], status);
		}
	}
	do {
		pos =  conf_module_config_search("sf_plugin", pos);
		if (pos != NULL) {
			if (strcmp(((sf_plugin_conf_t *)pos)->name, "pde_engine") == 0) {
				break;
			}
		}
	} while (pos != NULL);

	if (pos != NULL) {
		FILE *fp;
		int fd;
		int rd_size;
		sf_plugin_conf_t *conf_p;
		
		conf_p = (sf_plugin_conf_t *)pos;
		
		fp = fopen("/tmp/pde.lua", "r");
		assert(fp);
		
		fd = fileno(fp);

		rd_size = read(fd, conf_p->data, 1024);
		conf_p->data[rd_size] = '\0';

	}
	
	
	return status;
}
