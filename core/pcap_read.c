#include <assert.h>
#include <string.h>
#include <pcap.h>
#include <stdlib.h>

#include "common.h"
#include "mem.h"
#include "module_manage.h"
#include "conf.h"
#include "parser.h"
#include "log.h"
#include "process.h"

#define MAX_PACKET_HANDLE 200

typedef struct pcap_stats {
	uint64_t good_pkts;
	uint64_t bad_pkts;
	uint64_t drop_pkts;
	uint64_t oversize_pkts;
} pcap_stats_t;

typedef struct pcap_read {
	pcap_t *pcap;
	zone_t *zone;
	pcap_stats_t stats;
	packet_t *packet;
} pcap_read_t;

static int32_t pcap_read_init(module_info_t *this);
static int32_t pcap_read_process(module_info_t *this, void *data);
static void* pcap_read_result_get(module_info_t *this);
static void pcap_read_result_free(module_info_t *this);
static int pcap_read_fini(module_info_t *this);
static int16_t tag_decap;

module_ops_t pcap_read_ops = {					
	.init = pcap_read_init,
	.start = NULL,					
	.process = pcap_read_process,
	.result_get = pcap_read_result_get,
	.result_free = pcap_read_result_free,
	.fini = pcap_read_fini,	
};

 static int32_t pcap_read_init(module_info_t *this)
{
	pcap_read_t *p;
	char ebuf[PCAP_ERRBUF_SIZE];
	assert(this != NULL);

	this->resource = (pcap_read_t *)malloc(sizeof(pcap_read_t));
	assert(this->resource);

	memset(this->resource, 0, sizeof(pcap_read_t));
	p = (pcap_read_t *)this->resource;
	p->pcap = pcap_open_offline(g_conf.u.capfile, ebuf);
	assert(p->pcap);
	
	p->zone = zone_init("pcap_read", sizeof(packet_t) + MAX_PACKET_LEN, MAX_PACKET_HANDLE);
	assert(p->zone);
	
	tag_decap = tag_id_get_from_name(pktag_hd_p, "decap");

	log_notice(syslog_p, "pcap_read module init OK\n");
	return 0;
}

static inline void packet_init(packet_t *packet)
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
	pcap_read_t *p;
	uint16_t tag = tag_decap;
	
	p = (pcap_read_t *)this->resource;
	ptr = pcap_next(p->pcap, &hdr);
	
	if (ptr == NULL) {
		return -1;
	}

	assert(!p->packet);
	
	packet = zone_alloc(p->zone, 0);
	if (packet == NULL) {
		p->stats.drop_pkts++;
		log_error(syslog_p, "no space error!\n");
		return 0;
	}

	p->packet = packet;

	packet_init(packet);
	packet->len = hdr.caplen;
	if (packet->len >= MAX_PACKET_LEN) {
		p->stats.oversize_pkts++;
		packet->len = MAX_PACKET_LEN;
	}
	memcpy(packet->data, ptr, packet->len);
	p->stats.good_pkts++;
	packet->pktag = tag;
	return tag;
}

static void* pcap_read_result_get(module_info_t *this)
{
	pcap_read_t *pcap = this->resource;
	if (pcap != NULL) {
		return pcap->packet;
	}
	return NULL;
}

static void pcap_read_result_free(module_info_t *this)
{
	if (this->resource != NULL) {
		pcap_read_t *p = this->resource;
		if (p->packet) {
			zone_free(p->zone, p->packet);
			p->packet = NULL;
		}
	}
}

static int pcap_read_fini(module_info_t *this)
{
	pcap_read_t *p = this->resource;

	log_notice(syslog_p, "    pcap_read Stats:\n");
	log_notice(syslog_p, "    Good packets    :%d\n", p->stats.good_pkts);
	log_notice(syslog_p, "    Bad  packets    :%d\n", p->stats.bad_pkts);
	log_notice(syslog_p, "    Drop packets    :%d\n", p->stats.drop_pkts);
	log_notice(syslog_p, "    Oversize packets:%d\n", p->stats.drop_pkts);

	if (p->zone) {
		zone_fini(p->zone);
		p->zone = NULL;
	}
	pcap_close(p->pcap);
	p->pcap = NULL;
	p->packet = NULL;
	log_notice(syslog_p, "    pcap_read module finish OK\n");
	return 0;
}
