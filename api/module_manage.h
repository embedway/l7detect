#ifndef __PROBE_H__
#define __PROBE_H__
#include <stdio.h>
#include <stdint.h>

#define MODULE_QUIT 0x10

typedef struct module_info module_info_t;

typedef struct module_ops {
	int32_t (*init)(module_info_t *this);
	int32_t (*start)(module_info_t *this);
	int32_t (*process)(module_info_t *this, void *data);
	void* (*result_get)(module_info_t *this);
	void (*result_free)(module_info_t *this);
	int (*fini)(module_info_t *this);
} module_ops_t;

struct module_info {
	char *name;
	module_ops_t *ops;
	uint32_t flags;
	void *resource;
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
 * 模块初始化函数，该函数会通过回调初始化所有注册的模块
 * 
 * @param head 模块的头指针
 * 
 * @return 0，成功；其他值，失败原因；
 */
int32_t module_list_init(module_hd_t *head);

/** 
 * 模块启动函数，该函数会按照id的顺序通过回调启动所有注册的模块
 * 
 * @param head 模块的头指针
 * 
 * @return 0，成功；其他值，失败原因；
 */

int32_t module_list_start(module_hd_t *head);


int32_t module_list_process(module_hd_t *head_p);
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
 * 模块退出函数，该函数会通过回调退出所有注册的模块
 * 
 * 
 * @param head 模块的头指针
 * @return 0，表示成功；其他值，表示失败原因；
 */
int32_t module_list_fini(module_hd_t *head);

/** 
 * 模块管理退出函数，同时会退出所有没有退出的模块
 * 
 * 
 * @param head 指向模块头指针的指针
 * @return 0，表示成功；其他值，表示失败原因；
 */
int32_t module_manage_fini(module_hd_t **head_pp);


#endif
