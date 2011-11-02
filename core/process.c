#include <assert.h>
#include "threadpool.h"
#include "log.h"
#include "conf.h"
#include "process.h"
#include "parser.h"

typedef struct thread_data {
    module_hd_t *module_head;
    void *packet;
} thread_data_t;

tag_hd_t *pktag_hd_p;

void worker_thread_process(void *data)
{
    thread_data_t *td;
    packet_t *packet;
    assert(data);

    td = (thread_data_t *)data;
    packet = (packet_t *)td->packet;
    module_list_process(td->module_head, pktag_hd_p, packet->pktag, packet);
}

void process_loop(module_hd_t *module_head)
{
	int32_t status, tag_id;
	extern int system_exit;
    module_info_t *recv;
    thread_data_t td;
    void *data;

    if (g_conf.mode == MODE_LIVE || g_conf.mode == MODE_FILE) {
    /*收包，线程中加入处理*/
        recv = module_info_get_from_name(module_head, "recv");
        assert(recv && recv->ops->process);
        td.module_head = module_head;
        do {
            tag_id = recv->ops->process(recv, NULL);
            if (tag_id > 0) {
                data = recv->ops->result_get(recv);
                td.packet = data;
                status = threadpool_add_task(tp, worker_thread_process, &td, 0);
                if (status != 0) {
                    log_error(syslog_p, "Threadpool add task, status %d\n", status);
                    status = 0;
                }
                recv->ops->result_free(recv);
            }
        } while( status >= 0 && !system_exit);
    } else if (g_conf.mode == MODE_SE) {
        do {
            status = module_list_process(module_head, pktag_hd_p, -1, NULL);
	    } while (status >= 0 && !system_exit);
    }
}
