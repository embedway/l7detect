#ifndef __MODULE_MANAGE_H__
#define __MODULE_MANAGE_H__

#include <stdio.h>
#include <stdint.h>
#include "tag_manage.h"
#include "common.h"

#define MODULE_QUIT 0x10

typedef struct module_info module_info_t;

typedef struct module_ops {
	int32_t (*init_global)(module_info_t *this);
	int32_t (*init_local)(module_info_t *this, uint32_t thread_id);
    int32_t (*start)(module_info_t *this);
	int32_t (*process)(module_info_t *this, void *data);
	void* (*result_get)(module_info_t *this);
	void (*result_free)(module_info_t *this);
	int32_t (*fini_global)(module_info_t *this);
	int32_t (*fini_local)(module_info_t *this, uint32_t thread_id);
} module_ops_t;

struct module_info {
	char *name;
	module_ops_t *ops;
	uint32_t flags;
	void *pub_rep; /*公共资源*/
    void *priv_rep[MAX_WORKER_THREAD]; /*每个worker线程私有资源*/
};

typedef struct module_hd {
	uint32_t module_max;
	uint32_t module_valid;
	struct module_info *module_info;
} module_hd_t;


/**
 * 模块管理创建函数
 *
 * @param max_module_name 最大模块数
 *
 * @return 0，成功；其他值，表示失败原因；
 */
module_hd_t *module_list_create(int max_module_num);

/**
 * 创建模块
 *
 * @param head 模块的头指针，由module_list_create函数返回
 * @param name 模块名称
 * @param ops 操作回调函数
 *
 * @return  0，成功；其他值，表示失败原因;
 */
int32_t module_list_add(module_hd_t *head, char *name, module_ops_t *ops);

/**
 * 模块全局初始化函数，会通过回调初始化所有注册的模块
 *
 * @param head 模块的头指针
 *
 * @return 0，成功；其他值，失败原因；
 */
int32_t module_list_init_global(module_hd_t *head);

/**
 * 模块本地初始化函数，在所有线程上初始化一次
 *
 * @param head 模块的头指针
 * @param thread_id 线程id
 *
 * @return 0，成功；其他值，失败原因；
 */
int32_t module_list_init_local(module_hd_t *head, uint32_t thread_id);

/**
 * @brief 获取模块线程私有变量
 *
 * @param module 模块指针
 * @param thread_id 线程id
 *
 * @return 线程私有变量指针
 */
void* module_priv_rep_get(module_info_t *module, uint32_t thread_id);

/**
 * @brief 设置模块线程私有变量的指针指向data
 *
 * @param module 模块指针
 * @param thread_id 线程id
 * @param data 数据指针
 *
 */
void module_priv_rep_set(module_info_t *module, uint32_t thread_id, void *data);

/**
 * 模块启动函数，该函数会按照id的顺序通过回调启动所有注册的模块
 *
 * @param head 模块的头指针
 *
 * @return 0，成功；其他值，失败原因；
 */
int32_t module_list_start(module_hd_t *head);

/**
 * 模块处理函数，该函数会按照函数返回的tag调用对应的模块处理函数，直到成功处理完所有模块，返回0；或者失败返回错误原因
 *
 * @param head_p 模块头指针
 * @param tag_p tag头指针
 * @param init_tag  初始的tag，如果tag <= 0，那么运行时从第一个module开始，否则从tag绑定的module开始
  @param init_data 初始传入的data
 *
 * @return 0，成功；< 0，失败原因；
 */
int32_t module_list_process(module_hd_t *head_p, tag_hd_t *tag_p, int32_t init_tag, void *init_data);
/**
 * 根据模块名称，获取模块信息
 *
 * @param head 模块的头指针
 * @param name 模块名称
 *
 * @return 非NULL值，表示模块信息；NULL，表示失败；
 */
module_info_t *module_info_get_from_name(module_hd_t *head, char *name);


/**
 * 根据模块名称，返回模块对应的id
 *
 * @param head 模块的头指针
 * @param name 模块名称
 *
 * @return >0，表示模块id；0，表示失败；
 */
uint16_t module_id_get_from_name(module_hd_t *head, char *name);

/**
 * module和tag绑定函数
 *
 * @param module_head module头指针
 * @param tag_head tag头指针
 * @param module_name 要绑定的module名称
 * @param tag_name 要绑定的tag名称
 */
void module_tag_bind(module_hd_t *module_head, tag_hd_t *tag_head, char *module_name, char *tag_name);
/**
 * 根据模块id，获取模块信息
 *
 * @param head 模块的头指针
 * @param id 模块id
 *
 * @return 非NULL值，表示模块信息；NULL，表示失败；
 */
module_info_t *module_info_get_from_id(module_hd_t *head, uint16_t id);

/**
 * 模块列表显示函数
 *
 * @param head 模块的头指针
 */
void module_list_show(module_hd_t *head);

/**
 * 模块全局退出函数，该函数会通过回调退出所有注册的模块
 *
 *
 * @param head 模块的头指针
 * @return 0，表示成功；其他值，表示失败原因；
 */
int32_t module_list_fini_global(module_hd_t *head);

/**
 * @brief 模块本地退出函数，该函数会通过回调退出所有注册模块
 *
 * @param head_p 模块的头指针
 * @param thread_id 线程id
 *
 * @return 0，表示成功；其他值，表示失败原因；
 */
int32_t module_list_fini_local(module_hd_t *head_p, uint32_t thread_id);

/**
 * 模块管理退出函数，同时会退出所有没有退出的模块
 *
 *
 * @param head 指向模块头指针的指针
 * @return 0，表示成功；其他值，表示失败原因；
 */
int32_t module_manage_fini(module_hd_t **head_pp);


#endif
