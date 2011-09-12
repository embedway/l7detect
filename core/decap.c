#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <arpa/inet.h>
#endif

#include "common.h"
#include "mem.h"
#include "module_manage.h"
#include "conf.h"
#include "parser.h"
#include "log.h"
#include "process.h"
#include "decap.h"
#include "helper.h"

#define PKTS_MAX_NUM 10
#define PKTS_MAX_LEN MAX_PACKET_LEN

static int32_t decap_init(module_info_t *this);
static int32_t decap_process(module_info_t *this, void *data);
static void* decap_result_get(module_info_t *this);
static void decap_result_free(module_info_t *this);
static int decap_fini(module_info_t *this);

static uint16_t ipv4_frag_tag;
static uint16_t tcp_tag;
static uint16_t udp_tag;

typedef struct decap_stats {
	uint64_t ipv4_frag_pkts;
	uint64_t ipv6_frag_pkts;
	uint64_t ipv6_pkts;
	uint64_t icmp_pkts;
	uint64_t arp_pkts;
	uint64_t malformed_pkts;
	uint64_t tcp_pkts;
	uint64_t udp_pkts;
	uint64_t unknown_pkts;
} decap_stats_t;

enum {
	UNHANDLE_PKTS = 100,
	UNKNOWN_PKTS,
	MALFORMED_PKTS,
} cap_code;

typedef struct decap_info {
	packet_t *packet;
	decap_stats_t stats;
	struct cap_info {
		uint8_t pkts_cap[PKTS_MAX_LEN];
		uint32_t pkts_len;
		uint32_t code;
	} cap_pkts[PKTS_MAX_NUM];
	uint8_t cap_num;
} decap_info_t;

module_ops_t decap_mod_ops = {					
	.init = decap_init,
	.start = NULL,					
	.process = decap_process,
	.result_get = decap_result_get,
	.result_free = decap_result_free,
	.fini = decap_fini,	
};

static inline void __pkts_cap(decap_info_t *info, uint32_t code)
{
	if (info->cap_num < PKTS_MAX_NUM) {
		memcpy(info->cap_pkts[info->cap_num].pkts_cap, info->packet->data, info->packet->len);
		info->cap_pkts[info->cap_num].pkts_len = info->packet->len;
		info->cap_pkts[info->cap_num].code = code;
		info->cap_num++;
	}
}

static inline void __pkts_dump(decap_info_t *info)
{
	int i;
	for (i=0; i<info->cap_num; i++) {
		log_print(syslog_p, "--------------------code:%d-------------------\n", info->cap_pkts[i].code);
		list_format_print_buffer(info->cap_pkts[i].pkts_cap, 8, info->cap_pkts[i].pkts_len, FORMAT_PRINT_WITH_HEAD);
		log_print(syslog_p, "\n");
	}

}

static int32_t decap_init(module_info_t *this)
{
	this->resource = (decap_info_t *)malloc(sizeof(decap_info_t));
	assert(this->resource);

	memset(this->resource, 0, sizeof(decap_info_t));
	ipv4_frag_tag = tag_id_get_from_name(pktag_hd_p, "ipv4_frag");
	tcp_tag = tag_id_get_from_name(pktag_hd_p, "tcp");
	udp_tag = tag_id_get_from_name(pktag_hd_p, "udp");
	return 0;
}

static int32_t decap_process(module_info_t *this, void *data)
{
	packet_t *packet = (packet_t *)data;
	void *ptr = packet->data;
	void *start_ptr = ptr;
	uint16_t tag;
	dpi_ether_hdr_t *ether;
    dpi_vlan_hdr_t *vlan;
    dpi_mpls_hdr_t *mpls;
    dpi_ipv4_hdr_t *ipv4;
    dpi_tcp_hdr_t *tcp;
    dpi_udp_hdr_t *udp;
	int vlan_layer;
	int mpls_layer;
	uint16_t ether_type;
	uint8_t first_nibble;
	decap_info_t *info = (decap_info_t *)(this->resource);
	decap_stats_t *stats = &info->stats;
	uint8_t ip_protocol;

	switch (packet->prot_types[packet->prot_depth-1]) {
	case DPI_PROT_ETHER:
        goto do_decap_ether;
    case DPI_PROT_IPV4:
        goto do_decap_ipv4;
    case DPI_PROT_IPV6:
        goto do_decap_ipv6;
	default:
		goto unknown_pkts;
	}

do_decap_ether:
	info->packet = packet;
	ether =  (dpi_ether_hdr_t *)ptr;
	ptr += sizeof(dpi_ether_hdr_t);
	ether_type = ntohs(ether->type);
	vlan_layer = 0;
	
	while ((ether_type == DPI_ETHTYPE_VLAN) || (ether_type == DPI_ETHTYPE_VLAN2)) {
        vlan = (dpi_vlan_hdr_t *)ptr;
        ptr += sizeof(dpi_vlan_hdr_t);
        ether_type = ntohs(vlan->type);
        vlan_layer++;
        packet->prot_types[packet->prot_depth-1]++;
        if ( vlan_layer == 4 ) {
            break;
        }
    }
	switch (ether_type) {
	case DPI_ETHTYPE_IPV4:
		packet->prot_types[packet->prot_depth] = DPI_PROT_IPV4;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_ipv4;
    case DPI_ETHTYPE_IPV6:
        packet->prot_types[packet->prot_depth] = DPI_PROT_IPV6;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_ipv6;
	case DPI_ETHTYPE_ARP:
		stats->arp_pkts++;
		goto do_decap_unhandle;
    case DPI_ETHTYPE_MPLS:
        packet->prot_types[packet->prot_depth] = DPI_PROT_MPLS1;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_mpls;
	default:
		goto unknown_pkts;
    }

do_decap_mpls:
	mpls_layer = 0;
    while (1) {
        mpls = (dpi_mpls_hdr_t *)ptr;
        ptr += sizeof(dpi_mpls_hdr_t);
        mpls_layer++;
        packet->prot_types[ packet->prot_depth - 1 ]++;
        if ( mpls->s ) {
            break;
        }
        if ( mpls_layer == 8 ) {
        }
    }
	first_nibble = ( ( uint8_t * )ptr )[ 0 ] >> 4;
    switch ( first_nibble ) {
    case 4:
        packet->prot_types[packet->prot_depth] = DPI_PROT_IPV4;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_ipv4;
    case 6:
        packet->prot_types[packet->prot_depth] = DPI_PROT_IPV6;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_ipv6;
	default:
		goto unknown_pkts;
    }
do_decap_ipv4:
	ipv4 = (dpi_ipv4_hdr_t *)ptr;
	if ((htons(ipv4->offset) & IP_FRAGMASK) != 0) {
        stats->ipv4_frag_pkts++;
		tag = ipv4_frag_tag;
		packet->pktag = tag;
		return tag;
    }
	
	ptr += ipv4->hdr_len * 4;
	ip_protocol = ipv4->protocol;
	packet->real_applen = ntohs(ipv4->length) - ipv4->hdr_len * 4;
	
	switch (ip_protocol) {
	case DPI_IPPROT_ICMP:
        packet->prot_types[packet->prot_depth] = DPI_PROT_ICMP;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_icmp;
	case DPI_IPPROT_TCP:
        packet->prot_types[packet->prot_depth] = DPI_PROT_TCP;
        packet->prot_offsets[packet->prot_depth] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_tcp;
	case DPI_IPPROT_UDP:
        packet->prot_types[ packet->prot_depth ] = DPI_PROT_UDP;
        packet->prot_offsets[ packet->prot_depth ] = ptr - start_ptr;
        packet->prot_depth++;
        goto do_decap_udp;
	default:
		goto unknown_pkts;
	}
do_decap_tcp:
	tcp = (dpi_tcp_hdr_t *)ptr;
    ptr += tcp->hdr_len * 4;
	packet->app_offset = ptr - start_ptr;
	packet->real_applen -= tcp->hdr_len * 4;
	if (packet->app_offset <= packet->len){
		stats->tcp_pkts++;
		tag = tcp_tag;
		packet->pktag = tag;
		return tag;
    } else {
		__pkts_cap(info, MALFORMED_PKTS);
		stats->malformed_pkts++;
		packet->pktag = 0;
		return 0;
	}
do_decap_udp:
	udp = (dpi_udp_hdr_t *)ptr;
    ptr += sizeof(dpi_udp_hdr_t);
	packet->app_offset = ptr - start_ptr;
	packet->real_applen -= sizeof(dpi_udp_hdr_t);
	if (packet->app_offset <= packet->len){
		stats->udp_pkts++;
		tag = udp_tag;
		packet->pktag = tag;
        return tag;
    } else {
		__pkts_cap(info, MALFORMED_PKTS);
		stats->malformed_pkts++;
		packet->pktag = 0;
		return 0;
	}
	
do_decap_icmp:
	//__pkts_cap(info, DPI_PROT_ICMP);
	
	packet->pktag = 0;
	stats->icmp_pkts++;
	return 0;
do_decap_ipv6:
	//__pkts_cap(info, DPI_PROT_IPV6);
	packet->pktag = 0;			
	stats->ipv6_pkts++;
	return 0;
do_decap_unhandle:
	//__pkts_cap(info, UNHANDLE_PKTS);
	packet->pktag = 0;
	return 0;
unknown_pkts:
	__pkts_cap(info, UNKNOWN_PKTS);
	packet->pktag = 0;
	stats->unknown_pkts++;
	return 0;
}

static void* decap_result_get(module_info_t *this)
{
	decap_info_t *info = (decap_info_t *)(this->resource);	
	return info->packet;
}

static void decap_result_free(module_info_t *this)
{
	decap_info_t *info = (decap_info_t *)(this->resource);	
	info->packet = NULL;
}

static int decap_fini(module_info_t *this)
{
	decap_info_t *info = (decap_info_t *)(this->resource);	
	decap_stats_t *stats = &info->stats;

	log_notice(syslog_p, "\n------------------decapinfo---------------\n");
	log_notice(syslog_p, "ipv4_frag_pkts=%llu\n", stats->ipv4_frag_pkts);
	log_notice(syslog_p, "ipv6_frag_pkts=%llu\n", stats->ipv6_frag_pkts);
	log_notice(syslog_p, "ipv6_pkts=%llu\n", stats->ipv6_pkts);
	log_notice(syslog_p, "icmp_pkts=%llu\n", stats->icmp_pkts);
	log_notice(syslog_p, "arp_pkts=%llu\n", stats->arp_pkts);
	log_notice(syslog_p, "tcp_pkts=%llu\n", stats->tcp_pkts);
	log_notice(syslog_p, "udp_pkts=%llu\n", stats->udp_pkts);
	log_notice(syslog_p, "malformed_pkts=%llu\n", stats->malformed_pkts);
	log_notice(syslog_p, "unknown_pkts=%llu\n", stats->unknown_pkts);

	log_notice(syslog_p, "\n------------------decap packet info---------------\n");
	__pkts_dump(info);
	
	log_notice(syslog_p, "\n");
	if (info) {
		free(info);
	}
	return 0;
}

