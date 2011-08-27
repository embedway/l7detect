#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "conf.h"

conf_t g_conf;

#if 0
static int __mode_conflict(int mode1, int mode2)
{
	if ((mode1 == mode2) || (mode1 == 0) || (mode2 == 0)) {
		return 0;
	} else {
		return 1;
	}
}
#endif

static void usage(char *prog_name)
{
	printf("%s [-i ifname] [-r capfile] [-l logfile]\n", prog_name);
	exit (-1);
}

int parse_args(int argc, char *argv[])
{
	int opt;
	memset(&g_conf, 0, sizeof(conf_t));
	while ((opt = getopt(argc, argv, "i:r:l:h")) > 0) {
		switch (opt) {
		case 'i':
			g_conf.mode = MODE_LIVE;
			g_conf.u.device = optarg;
			break;
		case 'r':
			g_conf.mode = MODE_FILE;
			g_conf.u.capfile = optarg;
			break;
		case 'l':
			g_conf.logfile = optarg;
			break;
		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}
	return 0;
}

int read_conf()
{
	return 0;
}



