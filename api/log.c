#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <malloc.h>
#include "log.h"

log_t *log_init(char *file, uint32_t level)
{
	FILE *fp;
	log_t *log_p;

	log_p = (log_t *)malloc(sizeof(log_t));
	assert(log_p != NULL);
	
	log_p->level = level;

	if (file == NULL) {
		fp = stdout;
	} else {
		fp = fopen(file, "w");
		assert(fp != NULL);
	}
	log_p->fd = fileno(fp);

	return log_p;
}

int32_t log_log(log_t *log_p, uint32_t level, const char * fmt, ...)
{
	char buffer[1024];
	va_list ap;
	char *head = "<%d> ";
	char *p, *end;
	int n = 0;
	
	assert(log_p != NULL);

	if (log_p->level >= level) {
		p = buffer;
		end = buffer + sizeof(buffer);
		va_start(ap, fmt);
		n = snprintf(p, strlen(head), head, level);
		p += n;
		
		n = vsnprintf(p, end-p, fmt, ap);
		n = write(log_p->fd, buffer, strlen(head) + n);
		va_end(ap);
	} 
	return n;
}

int32_t log_fini(log_t **log_pp)
{
	log_t *log_p = *log_pp;
	if (log_p != NULL) {
		if (log_p->fd != fileno(stdout)) {
			close(log_p->fd);
		}
		free(log_p);
	}
	*log_pp = NULL;
	return 0;
}
