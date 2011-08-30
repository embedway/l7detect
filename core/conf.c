#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "conf.h"
#include "log.h"
conf_t g_conf;

typedef struct conf_list {
	list_head_t list;
	char *name;
	void *data;
} conf_node_t;

static void __usage(char *prog_name)
{
	print("%s [-i ifname] [-r capfile] [-l logfile]\n", prog_name);
	exit (-1);
}

int __parse_args(int argc, char *argv[])
{
	int opt;
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
			__usage(argv[0]);
			exit (-1);
			break;
		}
	}
	return 0;
}

int32_t conf_init()
{
	memset(&g_conf, 0, sizeof(conf_t));
	LIST_HEAD_INIT(&g_conf.module_conf_head);
	return 0;
}

int32_t conf_read(int argc, char *argv[])
{
	/*读取命令行参数*/
	assert(__parse_args(argc, argv) == 0);

	if (g_conf.mode != MODE_LIVE && g_conf.mode != MODE_FILE) {
		__usage(argv[0]);
		exit (-1);
	}

	/*读取配置文件*/
	return 0;
}

static inline int32_t __conf_insert(list_head_t *head, char *name, void *data, uint32_t size)
{
	conf_node_t *node;

	node = malloc(sizeof(conf_node_t));
	if (node == NULL) {
		return -NO_SPACE_ERROR;
	} else {
		node->name = name;
		node->data = malloc(size);
		if (node->data != NULL) {
			memcpy(node->data, data, size);
		} else {
			free(node);
			return -NO_SPACE_ERROR;
		}
	}
	list_add_tail(&node->list, head);
	return 0;
}

static inline void* __conf_search(list_head_t *head, char *name)
{
	list_head_t *p;

	list_for_each(p, head) {
		conf_node_t *node = list_entry(p, conf_node_t, list);
		if (strcmp(node->name, name) == 0) {
			return node->data;
		}
	}
	return NULL;
}

int32_t conf_insert_module_config(char *name, void *config, uint32_t size)
{
	return __conf_insert(&g_conf.module_conf_head, name, config, size);
}

void* conf_search_module_config(char *name)
{
	return __conf_search(&g_conf.module_conf_head, name);
}

int32_t conf_fini()
{
	list_head_t *p, *tmp;
	list_for_each_safe(p, tmp, &g_conf.module_conf_head) {
		conf_node_t *node = list_entry(p, conf_node_t, list);
		if (node != NULL) {
			list_del(&node->list);
			if (node->data != NULL) {
				free(node->data);
			}
			free(node);
		}
	}
	return 0;
}
