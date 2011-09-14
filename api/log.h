#ifndef __LOG_H__
#define __LOG_H__

#include "common.h"
#include "stdio.h"

enum {
	EMERG,
	ALERT,
	CRIT,
	ERR,
	WARNING,
	NOTICE,
	INFO,
	DEBUG,
};

typedef struct {
	int fd;
	uint32_t level;
} log_t;

log_t* log_init(char *logfile, uint32_t level);

int32_t log_log(log_t *log_p, uint32_t level, const char * fmt, ...);

int32_t log_print(log_t *log_p, const char * fmt, ...);

int32_t log_fini(log_t **log_pp);

extern log_t *syslog_p;

#define log_emege(log, fmt, args...) log_log(log, EMERG, fmt, ##args)
#define log_alert(log, fmt, args...) log_log(log, ALERT, fmt, ##args)
#define log_crit(log, fmt, args...) log_log(log, CRIT, fmt, ##args)
#define log_error(log, fmt, args...) log_log(log, ERR, fmt, ##args)
#define log_warn(log, fmt, args...) log_log(log, WARNING, fmt, ##args)
#define log_notice(log, fmt, args...) log_log(log, NOTICE, fmt, ##args)
#define log_info(log, fmt, args...) log_log(log, INFO, fmt, ##args)
#define log_debug(log, fmt, args...) log_log(log, DEBUG, fmt, ##args)

#define print printf
#define err_print(fmt, args...) fprintf(stderr, fmt, ##args)
#define TRACE print("TRACE:%s:%s, line %d\n", __FILE__,  __FUNCTION__, __LINE__)

#define if_error_return(statement, rv)\
	do{																	\
		if (!(statement)) {												\
			log_error(syslog_p, "%s:%d:statement %s failed\n", __FILE__, __LINE__, #statement); \
			return rv;													\
		}																\
	}while(0)


#endif
