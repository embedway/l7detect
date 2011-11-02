#ifndef __PROCESS_H__
#define __PROCESS_H__

#include "common.h"
#include "module_manage.h"

extern tag_hd_t *pktag_hd_p;

void process_loop(module_hd_t *module_head);
#ifdef __linux__
extern struct threadpool *tp;
#endif
#endif
