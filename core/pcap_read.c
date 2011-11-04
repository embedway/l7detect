#include <assert.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h>

#include "common.h"
#include "module_manage.h"
#include "conf.h"
#include "parser.h"
#include "log.h"
#include "process.h"


typedef struct pcap_stats {
	uint64_t good_pkts;
	uint64_t bad_pkts;
	uint64_t drop_pkts;
	uint64_t oversize_pkts;
} pcap_stats_t;

typedef struct info_global {
	pcap_t *pcap;
	pcap_stats_t stats;
} info_global_t;

/*这个模块是单线程的，因此和local相关的都不需要处理*/
static int32_t pcap_read_init_global(module_info_t *this);
//static int32_t pcap_read_init_local(module_info_t *this, uint32_t thread_id);
static int32_t pcap_read_process(module_info_t *this, void *data);
static int pcap_read_fini_global(module_info_t *this);
//static int pcap_read_fini_local(module_info_t *this, uint32_t thread_id);
static int16_t tag_decap;

module_ops_t pcap_read_ops = {
	.init_global = pcap_read_init_global,
    .init_local = NULL,
	.start = NULL,
	.process = pcap_read_process,
	.result_get = NULL,
	.result_free = NULL,
	.fini_global = pcap_read_fini_global,
    .fini_local = NULL,
};

static int32_t pcap_read_init_global(module_info_t *this)
{
	info_global_t *p;

	char ebuf[PCAP_ERRBUF_SIZE];
	assert(this != NULL);

	p = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(p);

	p->pcap = pcap_open_offline(g_conf.u.capfile, ebuf);
	assert(p->pcap);

	tag_decap = tag_id_get_from_name(pktag_hd_p, "decap");

    this->pub_rep = (void *)p;
	log_notice(syslog_p, "pcap_read module init OK\n");
	return 0;
}

static inline void __packet_init(packet_t *packet)
{
	memset(packet, 0, sizeof(packet_t));
	packet->prot_types[0] = 1;
	packet->prot_depth = 1;
}

static int32_t pcap_read_process(module_info_t *this, void *data)
{
	struct pcap_pkthdr hdr;
	const u_char *ptr;
	packet_t *packet;
	info_global_t *p;
	uint16_t tag = tag_decap;

	p = (info_global_t *)(this->pub_rep);
	ptr = pcap_next(p->pcap, &hdr);

	if (ptr == NULL) {
		return -1;
	}
	packet = (packet_t *)data;
	__packet_init(packet);
	packet->len = hdr.caplen;
	if (packet->len >= MAX_PACKET_LEN) {
		p->stats.oversize_pkts++;
		packet->len = MAX_PACKET_LEN;
	}
	packet->data = (void *)packet + sizeof(packet_t);
	memcpy(packet->data, ptr, packet->len);
	p->stats.good_pkts++;
	packet->pktag = tag;
	return tag;
}

static int pcap_read_fini_global(module_info_t *this)
{
	info_global_t *p = (info_global_t *)(this->pub_rep);

	log_notice(syslog_p, "    pcap_read Stats:\n");
	log_notice(syslog_p, "    Good packets    :%d\n", p->stats.good_pkts);
	log_notice(syslog_p, "    Bad  packets    :%d\n", p->stats.bad_pkts);
	log_notice(syslog_p, "    Drop packets    :%d\n", p->stats.drop_pkts);
	log_notice(syslog_p, "    Oversize packets:%d\n", p->stats.drop_pkts);

	pcap_close(p->pcap);
	p->pcap = NULL;
	free(p);
	log_notice(syslog_p, "    pcap_read module finish OK\n");
	return 0;
}
