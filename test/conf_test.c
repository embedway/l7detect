#include "common.h"
#include "conf.h"
#include "log.h"

int32_t conf_test()
{
	int32_t status;
	session_conf_t conf;
	conf.bucket_num = (1<<14) - 1;
	conf.session_expire_time = 30;
	conf.hash_name = "hash_xor";
	conf.session_logname = "/tmp/session.csv";
	status = conf_insert_module_config("session", &conf, sizeof(conf));
	return status;
}
