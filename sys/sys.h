#ifndef __SYS_H__
#define __SYS_H__

#ifdef __linux__
#include "linux/thread.h"

#define sys_thread_init_global thread_init_global
#define sys_thread_init_local thread_init_local
#define sys_thread_id_get thread_id_get
#define sys_thread_fini_global thread_fini_global
#define sys_thread_fini_local thread_fini_local

#else
#error "Not implement yet!"
#endif

#endif
