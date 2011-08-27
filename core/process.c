#include "process.h"
#include "recv.h"
#include "log.h"

void process_loop(module_hd_t *head_p)
{
	module_list_process(head_p);
}
