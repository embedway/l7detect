#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "common.h"
#include "module_manage.h"
#include "log.h"

module_hd_t *module_list_create(int max_module_num)
{
	module_hd_t *head_p;
	head_p = malloc(sizeof(module_hd_t));
	if_error_return(head_p != NULL, NULL);
	memset(head_p, 0, sizeof(module_hd_t));

	head_p->module_max = max_module_num + 1;
	head_p->module_valid = 0;
	head_p->module_info = malloc(sizeof(module_info_t) * (max_module_num+1));
	if (head_p->module_info == NULL) {
		free(head_p);
		return NULL;
	}
	return head_p;
}
int32_t module_list_add(module_hd_t *head_p, char *name, module_ops_t *ops)
{
	int i = 0;
	module_info_t *modules;
	
	if_error_return(head_p != NULL, -NOT_INIT_READY);

	modules= head_p->module_info;
	if_error_return(modules != NULL, -NOT_INIT_READY);
	if_error_return(name != NULL, -INVALID_PARAM);
	if_error_return(head_p->module_valid + 1 < head_p->module_max, -NO_SPACE_ERROR);
	
	i = head_p->module_valid + 1;
	modules[i].name = name;
	//modules[i].id = id;
	modules[i].ops = ops;
	head_p->module_valid++;
	return STATUS_OK;
}

int32_t module_list_init(module_hd_t *head_p)
{
	int i;
	int status;
	module_info_t *modules;
	
	if_error_return(head_p != NULL, -NOT_INIT_READY);

	modules	= head_p->module_info;	
	if_error_return(modules != NULL, -NOT_INIT_READY);
	
	for (i=1; i<(int)head_p->module_valid + 1; i++) {
		if ((modules[i].ops != NULL) && (modules[i].ops->init != NULL)) {
			status = modules[i].ops->init(&modules[i]);
			if_error_return(status == 0, status);
		}
	}
	return STATUS_OK;
}

int32_t module_list_start(module_hd_t *head_p)
{
	int i;
	int status;
	module_info_t *modules;

	if_error_return(head_p != NULL, -NOT_INIT_READY);

	modules = head_p->module_info;
	if_error_return(modules != NULL, -NOT_INIT_READY);

	for (i=1; i<(int)head_p->module_valid + 1; i++) {
		if ((modules[i].ops != NULL) && (modules[i].ops->start != NULL)) {
			status = modules[i].ops->start(&modules[i]);
			if_error_return(status == 0, status);
		}
	}
	return STATUS_OK;
}

int32_t module_list_process(module_hd_t *head_p)
{
	int32_t last, current, next;
	module_info_t *modules, *current_mod, *last_mod;
	module_ops_t *current_ops, *last_ops;
	void *data;
	
	if_error_return(head_p != NULL, -NOT_INIT_READY);
	modules = head_p->module_info;
	if_error_return(modules != NULL, -NOT_INIT_READY);

	last = current = next = 1;
	data = NULL;
	do {
		current_mod = &modules[current];
		current_ops = current_mod->ops;
		last_mod = &modules[last];
		last_ops = last_mod->ops;
		if ((current_ops != NULL) && (current_ops->process != NULL)) {
			data = last_ops->result_get(last_mod);
			next = current_ops->process(&modules[current], data);
			if_error_return(next >= 0, next);
			last_ops->result_free(last_mod);
			last = current;
			current = next;
		} else {
			break;
		}
	} while ((next > 0) && ((uint32_t)next < head_p->module_valid + 1));
	return STATUS_OK;
}

module_info_t *module_info_get_from_name(module_hd_t *head_p, char *name)
{
	int i;
	module_info_t *modules;

	if_error_return(head_p != NULL, NULL);

	modules =  head_p->module_info;
	if_error_return(modules != NULL, NULL);

	for (i=1; i<(int)head_p->module_valid + 1; i++) {
		if (strcmp(modules[i].name, name) == 0) {
				return &modules[i];
		}
	}
	return NULL;
}

void module_list_show(module_hd_t *head_p)
{
	int i;
	module_info_t *modules;

	if(head_p == NULL) {
		return;
	}

    modules =  head_p->module_info;

	print("ewx module information:\n");
	print("%16s %5s\n", "module name", "id");
	
	if (modules != NULL) {
		for (i=1; i<(int)head_p->module_valid + 1; i++) {
			print("%16s %5d\n", modules[i].name, i);
		}
	}
}

int32_t module_list_fini(module_hd_t *head_p)
{
	int i, valid;
	int status;
	module_info_t *modules;

	if (head_p != NULL) {
		modules = head_p->module_info;
		if (modules != NULL) {
			valid = head_p->module_valid;
			for (i=(int)valid; i>=1; i--) {
				if ((modules[i].ops != NULL) && (modules[i].ops->fini != NULL)) {
					log_notice(syslog_p, "fini module %s\n", modules[i].name);
					modules[i].flags |= MODULE_QUIT;
					status = modules[i].ops->fini(&modules[i]);
					if (status != 0) {
						log_notice(syslog_p, "module %s fini status %d\n", modules[i].name, status);
					}
					head_p->module_valid--;
				}
			}
		}
	}
	return 0;
}

int32_t module_manage_fini(module_hd_t **head_pp)
{
	module_info_t *modules;
	module_hd_t *head_p = *head_pp;

	module_list_fini(head_p);
	
	if (head_p != NULL) {
		modules = head_p->module_info;
		if (modules != NULL) {
			free(modules);
		}
		free(head_p);
		*head_pp = NULL;
	}
	return 0;
}
