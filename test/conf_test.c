#include <string.h>
#include <unistd.h>
#include <assert.h>
#include "common.h"
#include "conf.h"
#include "log.h"

int32_t conf_test()
{
	int32_t status;
	session_conf_t *session_conf;
	
	session_conf = zmalloc(session_conf_t *, sizeof(session_conf_t));
	if_error_return(session_conf != NULL, -NO_SPACE_ERROR);
	
	session_conf->bucket_num = (1<<14) - 1;
	session_conf->session_expire_time = 30;
	session_conf->hash_name = "hash_xor";
	session_conf->session_logname = "/tmp/session.csv";
	status = conf_module_config_insert("session", session_conf, common_free_cb);
	
	return status;
}
