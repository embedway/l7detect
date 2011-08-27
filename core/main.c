#include <stdio.h>
#include <assert.h>
#include <signal.h>

#include "common.h"
#include "conf.h"
#include "log.h"
#include "module_manage.h"
#include "recv.h"
#include "process.h"

#define MAX_MODULE_NUM  20

static void (*original_sig_int)(int num);
static void (*original_sig_term)(int num);

static int system_exit;

log_t *syslog_p;

void cap_term(int signum)
{
    system_exit = 1;
    if (original_sig_int)
        signal(SIGINT, original_sig_int);
    if(original_sig_term)
        signal(SIGTERM, original_sig_term);
}

static int32_t __sys_init()
{
    original_sig_int = signal(SIGINT, cap_term);
    original_sig_term = signal(SIGTERM, cap_term);

    system_exit = 0;
	
	/*日志*/
	if ((syslog_p = log_init(g_conf.logfile, NOTICE)) == NULL) {
		return -INIT_ERROR;
	}

    return STATUS_OK;
}

static int32_t __sys_fini()
{
	if (log_fini(&syslog_p) != 0) {
		return -FINI_ERROR;
	}
    return STATUS_OK;
}

static module_hd_t *__module_init()
{
    module_hd_t *module_hd;
	
	module_hd = module_list_create(MAX_MODULE_NUM);
	assert(module_hd);
	module_list_add(module_hd, "recv", &recv_mod_ops);

	assert(module_list_init(module_hd) == 0);
	assert(module_list_start(module_hd) == 0);
	
	return module_hd;
}

static int32_t __module_fini(module_hd_t **module_hd_pp)
{
	int status;
    status = module_manage_fini(module_hd_pp);
    if_error_return(status == STATUS_OK, status);

    return STATUS_OK;
}

int main(int argc, char *argv[])
{
	int32_t status;
	module_hd_t *module_hd_p;
/*获取配置*/
	parse_args(argc, argv);
	if (read_conf() != 0) {
		print("read conf error!\n");
	}
/*初始化*/
	assert(__sys_init() == 0);

	log_notice(syslog_p, "sys init OK!\n");
	
	module_hd_p = __module_init();
	if (module_hd_p == NULL) {
		log_error(syslog_p, "Some module init error\n");
		goto end;
	}
	
	log_notice(syslog_p, "module init OK!\n");
	
/*开始处理*/
	
	process_loop(module_hd_p);

/*处理结束*/
end:
	if (__module_fini(&module_hd_p) != 0) {
		log_error(syslog_p, "Some module finish error...\n");
	} else {
		log_notice(syslog_p, "module safe exit...\n");
	}

	if ((status = __sys_fini()) != 0) {
		print("sys fin status %d\n", status);
	} else {
		print("sys exit OK\n");
	}
	return 0;
}
