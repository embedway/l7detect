#ifndef __TAG_MANAGE_H__
#define __TAG_MANAGE_H__
#include "common.h"

typedef struct tag_info {
	char *name;
	uint16_t module_id;
} tag_info_t;

typedef struct tag_hd {
	uint32_t tag_max;
	uint32_t tag_valid;
	tag_info_t *tag_info;
} tag_hd_t;

tag_hd_t *tag_init(int max_tag_num);
void tag_register(tag_hd_t *head_p, char *name);
uint16_t tag_id_get_from_name(tag_hd_t *head_p, char *name);
uint16_t module_id_get_from_tag_id(tag_hd_t *head_p, uint16_t tag_id);
void tag_fini(tag_hd_t **head_pp);

#endif
