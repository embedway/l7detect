#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "conf.h"
#include "log.h"
#include "list.h"
#include "lua_ci.h"

conf_t g_conf;

#define DEFAULT_CONFIG_FILE_PATH "test/global.conf"
#define READ_BUF_SIZE 1024
#define PROTO_LIST_NAME "proto_list"
#define ENGINE_LIST_NAME "engine_list"
#define ENGINE_PDE_NAME "pde"
#define ENGINE_SDE_NAME "sde"

typedef struct conf_list {
	list_head_t list;
	char *name;
	void *data;
	conf_node_free_callback free_cb;
} conf_node_t;

static void __global_conf_show(conf_t *gconf);
static void __proto_conf_show(sf_proto_conf_t *conf);
static void __session_conf_show(session_conf_t *session);

static void __usage(char *prog_name)
{
	print("%s [-i ifname] [-r capfile] [-c config_file_path] [-h]\n", prog_name);
	exit (-1);
}

static void __init_default_config()
{
	g_conf.configfile = DEFAULT_CONFIG_FILE_PATH;
}

static int __parse_args(int argc, char *argv[])
{
	int opt;
	while ((opt = getopt(argc, argv, "i:r:c:h")) > 0) {
		switch (opt) {
		case 'i':
			g_conf.mode = MODE_LIVE;
			g_conf.u.device = optarg;
			break;
		case 'r':
			g_conf.mode = MODE_FILE;
			g_conf.u.capfile = optarg;
			break;
		case 'c':
            g_conf.configfile = optarg;
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

uint32_t __read_file(char *filename, char **rd_buf, int init_size, int step)
{
	char buf[READ_BUF_SIZE];
	FILE *fp;
	int fd;
	char *p, *head;
	uint32_t total_size, count, read_size;

	assert(filename);
	if (init_size < READ_BUF_SIZE) {
		init_size = READ_BUF_SIZE;
	}

	fp = fopen(filename, "r");
	assert(fp);

	fd = fileno(fp);

	p = malloc(init_size);
    if (p == NULL) {
        print("malloc error !\n");
        return 0;
    }

	head = p;
	read_size = 0;
	total_size = init_size;
	while ((count = read(fd, buf, READ_BUF_SIZE)) != 0) {
        if ((p + count) > (head + total_size)) {
			if ((p+count) > (head + total_size) + step) {
				step = p + count - (head+total_size);
			}
			p = realloc(head, total_size + step);
            if (p != NULL) {
                head = p;
				total_size += step;
				p += read_size;
			} else {
                print("realloc failed");
				return 0;
			}
		}
		memcpy(p, buf, count);
        p += count;
		read_size += count;
	}

    if (read_size == total_size) {
        /*enlarge buffer space to add '\0'*/
        p = realloc(head, total_size + 1);
        if (p != NULL) {
            head = p;
            total_size += 1;
            p += read_size;
        } else {
            print("realloc failed");
            return 0;
        }
    }
    *p = '\0';
	fclose(fp);
	*rd_buf = head;
	return read_size;
}

int32_t __proto_item_read(lua_State *L, char *proto_name, int index, sf_proto_conf_t *conf)
{
	uint32_t i;
	int type;
	proto_conf_t *p;

	p = &conf->protos[index];

	assert(conf->engines);
	p->name = malloc(strlen(proto_name) + 1);
	assert(p->name);
	strcpy(p->name, proto_name);

	p->engine_data = zmalloc(proto_engine_data_t *, sizeof(proto_engine_data_t) * conf->total_engine_num);
	assert(p->engine_data);

	for (i=0; i<conf->total_engine_num; i++) {
		type = ldlua_table_item_type(L, proto_name, conf->engines[i].name);
		if (type <= 0) {
			p->engine_data[i].lua_type = -1;
		} else {
			p->engine_data[i].lua_type = type;
			p->engine_mask |= 1<<i;
		}
		if (type == LUA_TSTRING) {
			char *str;
			str = ldlua_table_key_get_string(L, proto_name, conf->engines[i].name);
			assert(str && strlen(str) > 0);
			p->engine_data[i].data = malloc(strlen(str) + 1);
			assert(p->engine_data[i].data);
			strcpy(p->engine_data[i].data, str);
		}
	}
	return 0;
}


sf_proto_conf_t *__proto_conf_read()
{
	sf_proto_conf_t *sf_conf;
	int error;
	int proto_num, total_engine_num;
	int i;
    lua_State *L;
	uint32_t read_size;

    sf_conf = zmalloc(sf_proto_conf_t *, sizeof(sf_proto_conf_t));
	assert(sf_conf);

	read_size = __read_file(g_conf.protofile, &sf_conf->app_luabuf, READ_BUF_SIZE, READ_BUF_SIZE);
	if (read_size == 0) {
		free(sf_conf);
		return NULL;
	} else {
		print("read size %d\n", read_size);

		L = luaL_newstate();
		assert(L);
		luaL_openlibs(L);
		luaL_loadbuffer(L, sf_conf->app_luabuf, read_size, "app_parser");
        error = lua_pcall(L, 0, 0, 0);
		if (error) {
			err_print("%s\n", lua_tostring(L, -1));
			lua_pop(L, 1);
			free(sf_conf);
			return NULL;
		}
	}

	total_engine_num = ldlua_table_items_num(L, ENGINE_LIST_NAME);
	assert(total_engine_num);
	sf_conf->total_engine_num = total_engine_num;

	sf_conf->final_state = ldlua_table_key_get_num(L, "gstate", "final");
	assert(sf_conf->final_state);

	sf_conf->engines = zmalloc(detect_engine_t *, total_engine_num * sizeof(detect_engine_t));
	assert(sf_conf->engines);

	for (i=1; i<=total_engine_num; i++) {
		char *p;
		p = ldlua_table_raw_get_string(L, ENGINE_LIST_NAME, i);
		assert(strlen(p) <= ENGINE_NAME_LEN);
		strcpy(sf_conf->engines[i-1].name, p);
	}

	proto_num = ldlua_table_items_num(L, PROTO_LIST_NAME);
	assert(proto_num);
	sf_conf->total_proto_num = proto_num;
	sf_conf->protos = zmalloc(proto_conf_t *, proto_num * sizeof(proto_conf_t));

	for (i=1; i<=proto_num; i++) {
		char *proto_name;
		proto_name = ldlua_table_raw_get_string(L, PROTO_LIST_NAME, i);
		if (proto_name) {
			__proto_item_read(L, proto_name, i-1, sf_conf);
		} else {
			err_print("item %d type error, %s\n",
					  i, lua_typename(L, lua_type(L, -1)));
		}
	}

	__proto_conf_show(sf_conf);

	lua_close(L);
	return sf_conf;
}

void __proto_conf_show(sf_proto_conf_t *conf)
{
	uint32_t i, j;

	print("total_engine_num=%d, list:\n", conf->total_engine_num);
	for (i=0; i<conf->total_engine_num; i++) {
		print("\t%s\n", conf->engines[i].name);
	}

	print("total_proto_num=%d\n", conf->total_proto_num);
	for (i=0; i<conf->total_proto_num; i++) {
		print("\tname:%s,engine_mask:%d\n", conf->protos[i].name, conf->protos[i].engine_mask);
		for (j=0; j<conf->total_engine_num; j++) {
			print("\t\tengine:%s, type:%d, data:%s\n", conf->engines[j].name,
				  conf->protos[i].engine_data[j].lua_type,
				  (conf->protos[i].engine_data[j].data == NULL)?"NULL":(char *)conf->protos[i].engine_data[j].data);
		}
	}
}


void __proto_conf_free(void *data)
{
	sf_proto_conf_t *conf;
	uint32_t i;

	conf = (sf_proto_conf_t *)data;

	if (conf->app_luabuf) {
		free(conf->app_luabuf);
	}
	if (conf->engines) {
		free(conf->engines);
	}

	if (conf->protos) {
		for (i=0; i<conf->total_proto_num; i++) {
			if (conf->protos[i].name) {
				free(conf->protos[i].name);
			}
			if (conf->protos[i].engine_data) {
				if (conf->protos[i].engine_data->data) {
					free(conf->protos[i].engine_data->data);
				}
				free(conf->protos[i].engine_data);
			}
		}
		free(conf->protos);
	}

	free(conf);
}


static inline int32_t __conf_insert(list_head_t *head, char *name, void *data,
									conf_node_free_callback free_cb)
{
	conf_node_t *node;

	node = zmalloc(conf_node_t *, sizeof(conf_node_t));
	if_error_return(node != NULL, -NO_SPACE_ERROR);
	node->name = name;
	node->data = data;
	node->free_cb = free_cb;
	list_add_tail(&node->list, head);
	return 0;
}

static inline void* __conf_search(list_head_t *head, void *pos, char *name)
{
	list_head_t *p;
	int found = 0;

	list_for_each(p, head) {
		conf_node_t *node = list_entry(p, conf_node_t, list);
		if ((pos != NULL) && !found) {
			if (pos == node->data) {
                /*跳过这个节点，从下一个开始*/
                found = 1;
			}
			continue;
		}
		if (strcmp(node->name, name) == 0) {
			return node->data;
		}
	}
	return NULL;
}

static inline int32_t
__value_set_string_from_lua_table(lua_State *L, char *table_name,
                                  char *key, char **data)
{
    char *p;
    int type;

    type = ldlua_table_item_type(L, table_name, key);
    if (type != LUA_TSTRING) {
        return -INVALID_PARAM;
    } else {
        p =  ldlua_table_key_get_string(L, table_name, key);
        if (p == NULL) {
            return -ITEM_NOT_FOUND;
        }
        *data = malloc(strlen(p) + 1);
        if (*data == NULL) {
            return -NO_SPACE_ERROR;
        } else {
            strcpy(*data, p);
        }
    }
    return 0;
}

static inline int32_t
__value_set_num_from_lua_table(lua_State *L, char *table_name,
                               char *key, int *data)
{
    int value;
    int type;

    type = ldlua_table_item_type(L, table_name, key);
    if (type != LUA_TNUMBER) {
        return -INVALID_PARAM;
    } else {
        value =  ldlua_table_key_get_num(L, table_name, key);
        *data = value;
    }
    return 0;
}

static int32_t __global_conf_read(lua_State *L)
{
    int status;

    status = __value_set_string_from_lua_table(L, "config_file_path", "app_proto",
                                               &g_conf.protofile);
    assert(status == 0);

    status = __value_set_num_from_lua_table(L, "global_config", "thread_num",
                                            (int *)&g_conf.thread_num);
    assert(status == 0);
    assert(g_conf.thread_num >= 1 && g_conf.thread_num < MAX_WORKER_THREAD);

    status = __value_set_string_from_lua_table(L, "global_config", "log_file_path",
                                        &g_conf.logfile);
    assert(status == 0);
    if (strcmp(g_conf.logfile, "stdout") == 0) {
        free(g_conf.logfile);
        g_conf.logfile = NULL;
    }

    __global_conf_show(&g_conf);
    return 0;
}

static void __global_conf_show(conf_t *conf)
{
    print("log_path=%s\n", (conf->logfile == NULL) ? "stdout" : conf->logfile);
    print("proto_file_path=%s\n", conf->protofile);
    print("thread_num=%d\n", conf->thread_num);
}

static void __global_conf_free()
{
    if (g_conf.protofile != NULL) {
        free(g_conf.protofile);
    }
    if (g_conf.logfile != NULL) {
        free(g_conf.logfile);
    }
}

static session_conf_t *__session_conf_read(lua_State *L)
{
    int32_t status;
    session_conf_t *session_conf;

    session_conf = zmalloc(session_conf_t *, sizeof(session_conf_t));
    assert(session_conf);

    status = __value_set_num_from_lua_table(L, "session_config", "bucket_num",
                                            (int *)&session_conf->bucket_num);
    assert(status == 0);

    status = __value_set_num_from_lua_table(L, "session_config", "session_expire_time",
                                            (int *)&session_conf->session_expire_time);
    assert(status == 0);

    status = __value_set_string_from_lua_table(L, "session_config", "hash_name",
                                               &session_conf->hash_name);
    assert(status == 0);

    status = __value_set_string_from_lua_table(L, "session_config", "session_result",
                                               &session_conf->session_logname);
    assert(status == 0);
    __session_conf_show(session_conf);
   return session_conf;
}

static void __session_conf_show(session_conf_t *session_conf)
{
    print("session_bucket=%x\n", session_conf->bucket_num);
    print("session_expire_time=%d seconds\n", session_conf->session_expire_time);
    print("session_hash_name=%s\n", session_conf->hash_name);
    print("session_logname=%s\n", session_conf->session_logname);
}

static void __session_conf_free(void *data)
{
    session_conf_t *session_conf;

    session_conf = (session_conf_t *)data;

    if (session_conf->hash_name != NULL) {
        free(session_conf->hash_name);
    }
    if (session_conf->session_logname != NULL) {
        free(session_conf->session_logname);
    }
    free(session_conf);
}

int32_t conf_module_config_insert(char *name, void *config, conf_node_free_callback free_cb)
{
	return __conf_insert(&g_conf.module_conf_head, name, config, free_cb);
}

void* conf_module_config_search(char *name, void *pos)
{
	return __conf_search(&g_conf.module_conf_head, pos, name);
}

int32_t conf_init()
{
	memset(&g_conf, 0, sizeof(conf_t));
	LIST_HEAD_INIT(&g_conf.module_conf_head);
	__init_default_config();
	return 0;
}

int32_t conf_read(int argc, char *argv[])
{
	/*读取命令行参数*/
	void *data;
    char *global_buf;
    lua_State *L;
    uint32_t read_size;
    int error;
    int32_t status;

    assert(__parse_args(argc, argv) == 0);

	if (g_conf.mode != MODE_LIVE && g_conf.mode != MODE_FILE) {
		__usage(argv[0]);
		exit (-1);
	}
    read_size = __read_file(g_conf.configfile, &global_buf, READ_BUF_SIZE, READ_BUF_SIZE);
	if (read_size == 0) {
		return -CONFIG_ERROR;
	} else {
		print("global configure size %d\n", read_size);
		L = luaL_newstate();
		assert(L);
		luaL_openlibs(L);
		luaL_loadbuffer(L, global_buf, read_size, "global_config");
        error = lua_pcall(L, 0, 0, 0);
		if (error) {
			err_print("%s\n", lua_tostring(L, -1));
			lua_pop(L, 1);
			return -SYSCALL_ERROR;
		}
        free(global_buf);
	}

    status = __global_conf_read(L);
    assert(status == 0);

    data = __session_conf_read(L);
    assert(data);
    assert(conf_module_config_insert(SESSION_CONF_NAME, data, __session_conf_free) == 0);

    lua_close(L);

    /*读取协议配置文件*/
	data = __proto_conf_read();
	assert(data);
	assert(conf_module_config_insert(SF_PROTO_CONF_NAME, data, __proto_conf_free) == 0);
	return 0;
}

int32_t conf_fini()
{
	list_head_t *p, *tmp;
	list_for_each_safe(p, tmp, &g_conf.module_conf_head) {
		conf_node_t *node = list_entry(p, conf_node_t, list);
		if (node != NULL) {
			list_del(&node->list);
			if (node->free_cb) {
				node->free_cb(node->data);
			}
			free(node);
		}
	}
    __global_conf_free(&g_conf);
	return 0;
}
