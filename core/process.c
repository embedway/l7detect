#include "process.h"
#include "parser.h"
#include "log.h"

tag_hd_t *pktag_hd_p;

void process_loop(module_hd_t *module_head)
{
	int32_t status;
	extern int system_exit;
	do {
		status = module_list_process(module_head, pktag_hd_p, -1, NULL);
	} while (status >= 0 && !system_exit);
	
}
