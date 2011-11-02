#ifndef __THREAD__
#define __THREAD__
#include "common.h"

uint32_t thread_init_global();
uint32_t thread_init_local();
uint32_t thread_id_get();
uint32_t thread_fini_local();
uint32_t thread_fini_global();

#endif
