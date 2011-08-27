#ifndef __CONF_H__
#define __CONF_H__

enum {
	MODE_NOT_SET,
	MODE_LIVE,
	MODE_FILE,
};

typedef struct conf {
	int mode;
	union {
		char *device;
		char *capfile;
	} u;
	char *logfile;
} conf_t;

extern conf_t g_conf;
int parse_args(int argc, char *argv[]);
int read_conf();


#endif
