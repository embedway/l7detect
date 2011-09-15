#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "log.h"
#include "tag_manage.h"

tag_hd_t *tag_init(int max_tag_num)
{
	tag_hd_t *head = (tag_hd_t *)malloc(sizeof(tag_hd_t));
	assert(head);
	
	head->tag_info = (tag_info_t *)malloc(sizeof(tag_info_t) * (max_tag_num+1));
	assert(head->tag_info);

	head->tag_max = max_tag_num + 1;
	head->tag_valid = 0;
	memset(head->tag_info, 0, max_tag_num * sizeof(tag_info_t));
	
	return head;
}

void tag_register(tag_hd_t *head_p, char *name)
{
	tag_info_t *tag_info;
	uint16_t i;

	assert(head_p);
	assert(head_p->tag_info);
	assert(name);
	assert(head_p->tag_valid + 1 < head_p->tag_max);

	tag_info = head_p->tag_info;
	i = head_p->tag_valid + 1;
	tag_info[i].name = name;
	tag_info[i].module_id = 0;
	head_p->tag_valid++;
}

uint16_t tag_id_get_from_name(tag_hd_t *head_p, char *tag_name)
{
	uint16_t i;
	tag_info_t *tag_info;

	assert(head_p);
	assert(head_p->tag_info);
	tag_info = head_p->tag_info;
	
	for (i=1; i<=head_p->tag_valid; i++) {
		if (strcmp(tag_info[i].name, tag_name) == 0) { 
			break;
		}
	}
	if (i <= head_p->tag_valid) {
		return i;
	} else {
		return 0;
	}
}

uint16_t module_id_get_from_tag_id(tag_hd_t *head_p, uint16_t tag_id)
{
	if_error_return ((tag_id <= head_p->tag_valid), 0);
	return head_p->tag_info[tag_id].module_id;
}

void tag_fini(tag_hd_t **head_pp)
{
	tag_hd_t *head_p = *head_pp;
	if (head_p) {
		if (head_p->tag_info) {
			free(head_p->tag_info);
		}
		free(head_p);
		*head_pp = NULL;
	}
}
