#include "process.h"
#include "parser.h"
#include "log.h"

tag_hd_t *pktag_hd_p;

void process_loop(module_hd_t *module_head)
{
	int32_t status;

	do {
		status = module_list_process(module_head, pktag_hd_p, NULL);
	} while (status >= 0);
	
}
