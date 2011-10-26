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
#include "threadpool.h"

#define MAX_PACKET_HANDLE 200
#define CAP_LIVE_TIMEOUT 1000

typedef struct pcap_live_stats {
	uint64_t good_pkts;
	uint64_t bad_pkts;
	uint64_t drop_pkts;
	uint64_t oversize_pkts;
} pcap_live_stats_t;

typedef struct threadpool threadpool_t;
typedef struct pcap_live {
	packet_t *packet;
	zone_t *zone;
	pcap_live_stats_t stats;
    pcap_t *pcap;
    threadpool_t *tp;
} pcap_live_t;

static int32_t pcap_live_init(module_info_t *this);
static int32_t pcap_live_process(module_info_t *this, void *data);
static void* pcap_live_result_get(module_info_t *this);
static void pcap_live_result_free(module_info_t *this);
static int pcap_live_fini(module_info_t *this);
static int16_t tag_decap;

module_ops_t pcap_live_ops = {
	.init = pcap_live_init,
	.start = NULL,
	.process = pcap_live_process,
	.result_get = pcap_live_result_get,
	.result_free = pcap_live_result_free,
	.fini = pcap_live_fini,
};

static int32_t pcap_live_init(module_info_t *this)
{
	pcap_live_t *p;
	char ebuf[PCAP_ERRBUF_SIZE];
    threadpool_t *tp;

	assert(this != NULL);

	this->resource = (pcap_live_t *)malloc(sizeof(pcap_live_t));
	assert(this->resource);

	memset(this->resource, 0, sizeof(pcap_live_t));
	p = (pcap_live_t *)this->resource;
	p->pcap = pcap_open_live(g_conf.u.device, MAX_PACKET_LEN, 1, CAP_LIVE_TIMEOUT, ebuf);
	assert(p->pcap);

	p->zone = zone_init("pcap_live", sizeof(packet_t) + MAX_PACKET_LEN, MAX_PACKET_HANDLE);
	assert(p->zone);

    tp = threadpool_init(g_conf.thread_num);
    assert(tp);

    p->tp = tp;
	tag_decap = tag_id_get_from_name(pktag_hd_p, "decap");

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
	pcap_live_t *p = (pcap_live_t *)user;
    packet_t *packet;

  	assert(!p->packet);

	packet = zone_alloc(p->zone, 0);
	if (packet == NULL) {
		p->stats.drop_pkts++;
		log_error(syslog_p, "no space error!\n");
		return;
	}

	p->packet = packet;

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
	pcap_live_t *p;
    int inpkts;

	p = (pcap_live_t *)this->resource;
    inpkts = pcap_dispatch(p->pcap, 1, pcap_live_cb, (u_char *)p);
    if (inpkts > 0) {
        return tag_decap;
    } else {
        return 0;
    }
}

static void* pcap_live_result_get(module_info_t *this)
{
	pcap_live_t *pcap = this->resource;
	if (pcap != NULL) {
		return pcap->packet;
	}
	return NULL;
}

static void pcap_live_result_free(module_info_t *this)
{
	if (this->resource != NULL) {
		pcap_live_t *p = this->resource;
		if (p->packet) {
			zone_free(p->zone, p->packet);
			p->packet = NULL;
		}
	}
}

static int pcap_live_fini(module_info_t *this)
{
	pcap_live_t *p = this->resource;

	log_notice(syslog_p, "    pcap_live Stats:\n");
	log_notice(syslog_p, "    Good packets    :%d\n", p->stats.good_pkts);
	log_notice(syslog_p, "    Bad  packets    :%d\n", p->stats.bad_pkts);
	log_notice(syslog_p, "    Drop packets    :%d\n", p->stats.drop_pkts);
	log_notice(syslog_p, "    Oversize packets:%d\n", p->stats.drop_pkts);

    threadpool_free(p->tp, 1);
	if (p->zone) {
		zone_fini(p->zone);
		p->zone = NULL;
	}
	pcap_close(p->pcap);
	p->pcap = NULL;
	p->packet = NULL;
	free(p);
	log_notice(syslog_p, "    pcap_live module finish OK\n");
	return 0;
}
