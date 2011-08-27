#include <string.h>

#include "parser.h"
#include "conf.h"
#include "log.h"

#include "module_manage.h"

static int32_t recv_init(module_info_t *this);

module_ops_t recv_mod_ops = {
	.init = recv_init,/*在调用recv_init,会自动填充成和模式相关接收操作API*/
	.start = NULL,
	.process = NULL,
	.result_get = NULL,
	.result_free = NULL,
	.fini = NULL,
};

static int32_t recv_init(module_info_t *this)
{
	int32_t rv = 0;
	extern module_ops_t pcap_read_ops;
	
	switch (g_conf.mode) {
	case MODE_LIVE:
		/*暂时还不支持*/
		rv = -INVALID_PARAM;
		break;
	case MODE_FILE:
		memcpy(&recv_mod_ops, &pcap_read_ops, sizeof(module_ops_t));
		rv = recv_mod_ops.init(this);
		break;
	default:
		rv = -INVALID_PARAM;
		break;
	}
	return rv;
}


