#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include "common.h"
#include "mem.h"
#include "module_manage.h"
#include "conf.h"
#include "parser.h"
#include "log.h"
#include "process.h"

#define MAX_PACKET_HANDLE 200
#define CAP_LIVE_TIMEOUT 1000

typedef struct pcap_live_stats {
	uint64_t good_pkts;
	uint64_t bad_pkts;
	uint64_t drop_pkts;
	uint64_t oversize_pkts;
} pcap_live_stats_t;

typedef struct info_global {
    packet_t *packet;
    pcap_t *pcap;
	pcap_live_stats_t stats;
} info_global_t;

/*这个模块是单线程的，因此和local相关的都不需要处理*/
static int32_t pcap_live_init_global(module_info_t *this);
static int32_t pcap_live_process(module_info_t *this, void *data);
static int32_t pcap_live_fini_global(module_info_t *this);
static int16_t tag_decap;

module_ops_t pcap_live_ops = {
	.init_global = pcap_live_init_global,
    .init_local = NULL,
	.start = NULL,
	.process = pcap_live_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini_global = pcap_live_fini_global,
	.fini_local = NULL,
};

static int32_t pcap_live_init_global(module_info_t *this)
{
	info_global_t *p;
	char ebuf[PCAP_ERRBUF_SIZE];

	assert(this != NULL);

	p = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(p);

	p->pcap = pcap_open_live(g_conf.u.device, MAX_PACKET_LEN, 1, CAP_LIVE_TIMEOUT, ebuf);
	assert(p->pcap);

	tag_decap = tag_id_get_from_name(pktag_hd_p, "decap");

    this->pub_rep = (void *)p;
	log_notice(syslog_p, "pcap_live module init OK\n");
	return 0;
}

static inline void __packet_init(packet_t *packet)
{
	memset(packet, 0, sizeof(packet_t));
	packet->prot_types[0] = 1;
	packet->prot_depth = 1;
}
static void
pcap_live_cb(u_char *user, const struct pcap_pkthdr *hdr,
          const u_char *pd)
{
    info_global_t *p = (info_global_t *)user;
    packet_t *packet;

  	assert(p->packet);
    packet = p->packet;
	__packet_init(packet);
	packet->len = hdr->caplen;
	if (packet->len >= MAX_PACKET_LEN) {
		p->stats.oversize_pkts++;
		packet->len = MAX_PACKET_LEN;
	}
	packet->data = (void *)packet + sizeof(packet_t);
	memcpy(packet->data, pd, packet->len);
	p->stats.good_pkts++;
	packet->pktag = tag_decap;
    p->packet = packet;
}

static int32_t pcap_live_process(module_info_t *this, void *data)
{
	info_global_t *p;
    int inpkts;

	p = (info_global_t *)this->pub_rep;
    p->packet = data;
    inpkts = pcap_dispatch(p->pcap, 1, pcap_live_cb, (u_char *)p);
    if (inpkts > 0) {
        return tag_decap;
    } else {
        return 0;
    }
}

static int32_t pcap_live_fini_global(module_info_t *this)
{
    info_global_t *p = this->pub_rep;

	log_notice(syslog_p, "    pcap_live Stats:\n");
	log_notice(syslog_p, "    Good packets    :%d\n", p->stats.good_pkts);
	log_notice(syslog_p, "    Bad  packets    :%d\n", p->stats.bad_pkts);
	log_notice(syslog_p, "    Drop packets    :%d\n", p->stats.drop_pkts);
	log_notice(syslog_p, "    Oversize packets:%d\n", p->stats.drop_pkts);

	pcap_close(p->pcap);
	p->pcap = NULL;
	p->packet = NULL;
	free(p);
	log_notice(syslog_p, "    pcap_live module finish OK\n");
	return 0;
}
