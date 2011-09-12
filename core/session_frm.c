#include <assert.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <dlfcn.h>
#include "plugin.h"
#include <arpa/inet.h>
 #include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "common.h"
#include "mem.h"
#include "module_manage.h"
#include "conf.h"
#include "parser.h"
#include "log.h"
#include "process.h"
#include "hash_table.h"
#include "decap.h"

#define INC_CNT(count) count++

static int32_t session_frm_init(module_info_t *this);
static int32_t session_frm_process(module_info_t *this, void *data);
static void* session_frm_result_get(module_info_t *this);
static void session_frm_result_free(module_info_t *this);
static int session_frm_fini(module_info_t *this);
static uint16_t sf_plugin_tag;
module_ops_t session_frm_ops = {					
	.init = session_frm_init,
	.start = NULL,
	.process = session_frm_process,
	.result_get = session_frm_result_get,
	.result_free = session_frm_result_free,
	.fini = session_frm_fini,
};

typedef struct session_frm_stats {
	uint64_t unknown_pkts;
	uint64_t unknown_dir;
	uint64_t session_count;
	uint64_t session_failed;
} session_frm_stats_t;

typedef struct flow_item {
	uint32_t pkts;
	uint32_t bytes;
} flow_item_t;

typedef struct session_index {
	uint32_t ip[2];
	uint16_t port[2];
	uint32_t protocol:8;
	uint32_t reserved:24;	
} session_index_t;

typedef struct session_item {
	session_index_t index;
	flow_item_t flow[2];		/**< [0]为上行流，[1]为下行流 */
	uint16_t dir:2;
#define FLOW_UP_STREAM_INDEX 0
#define FLOW_DN_STREAM_INDEX 1
	uint16_t flag:14;
#define SESSION_INDEX_UPSTREAM PKT_DIR_UPSTREAM
#define SESSION_INDEX_DNSTREAM PKT_DIR_DNSTREAM
#define SESSION_DIR_MASK 0x3
	uint16_t stage;
	uint64_t id;
	uint64_t start_time;
	uint64_t last_time;
	uint32_t app_classify;		/**<  协议大类*/
	uint32_t app_type;			/**<  协议小类*/
}session_item_t;

typedef uint32_t (*hash_func)(session_index_t *info);

typedef struct session_frm_info {
	packet_t *packet;
	hash_table_hd_t *session_table;
	session_conf_t *conf;
	log_t *log_c;
	session_item_t *session;	    /**< 流表中找到的表项*/	
	session_index_t index_cache;	/**< 临时的session cache，减小每次进入函数堆栈分配的开销 */
	hash_func hash_cb;
	session_frm_stats_t stats;
} session_frm_info;

typedef struct hash_map {
	char *name;
	hash_func hash_cb;
} hash_map_t;

static uint32_t hash_xor(session_index_t *index)
{
	return index->ip[0] ^ index->ip[1] ^ index->port[0] ^ index->port[1];
}

static uint32_t hash_xor_sum(session_index_t *index)
{
	return (index->ip[0] ^ index->ip[1]) + (index->port[0] ^ index->port[1]);
}

static uint32_t hash_sum(session_index_t *index)
{
	return (index->ip[0] + index->ip[1]) + (index->port[0] + index->port[1]);
}

void __update_session_count(session_item_t *session, packet_t *packet)
{
	uint32_t dir =  packet->dir & PKT_DIR_MASK;
	if (dir == PKT_DIR_UPSTREAM) {
		session->flow[FLOW_UP_STREAM_INDEX].pkts++;
		session->flow[FLOW_UP_STREAM_INDEX].bytes += packet->len;
	} else if (dir == PKT_DIR_DNSTREAM) {
		session->flow[FLOW_DN_STREAM_INDEX].pkts++;
		session->flow[FLOW_DN_STREAM_INDEX].bytes += packet->len;
	} 
}

static inline int32_t __is_interal_ip(uint32_t ip)
{
	if (((ip & 0xff000000) == 0xa0000000) || ((ip & 0xffff0000) == 0xc0a80000) ||
		((ip >= 0xaca00000) && (ip <= 0xac1f0000))) {
		return 1;
	} else {
		return 0;
	}
}

static inline int32_t __session_index_dir(session_index_t *index)
{
	int32_t dir;
	if (__is_interal_ip(index->ip[0])) {
		dir = PKT_DIR_UPSTREAM;
	} else if (__is_interal_ip(index->ip[1])) {
		dir = PKT_DIR_DNSTREAM;
	} else if (index->port[0] < index->port[1]) {
		dir = PKT_DIR_DNSTREAM;
	} else {
		dir = PKT_DIR_UPSTREAM;
	}
	return dir;
}

static inline void __init_session(session_item_t *session, session_index_t *index, packet_t *packet)		
{
	memset(session, 0, sizeof(session_item_t));
	memcpy(&session->index, index, sizeof(session_index_t));
	session->dir = __session_index_dir(index);
}


static int32_t session_compare(void *this, void *user_data, void *item)
{
	session_item_t *table_item = (session_item_t *)item;
	
	if (memcmp(this, &table_item->index, sizeof(session_index_t)) == 0) {
		/*匹配*/
		return 0;
	}
	/*不匹配*/
	return 1;
}

static int32_t session_frm_init(module_info_t *this)
{
	session_frm_info *info = malloc(sizeof(session_frm_info));
	session_conf_t *conf;
	uint32_t i;
	hash_map_t hash_map[] = {
		{"hash_xor", hash_xor},
		{"hash_xor_sum", hash_xor_sum},
		{"hash_sum", hash_sum},
	};

	assert(sizeof(session_item_t) <= 128);
	assert(info);

	conf = (session_conf_t *)conf_module_config_search("session", NULL);
	assert(conf);
	info->session_table = hash_table_init(conf->bucket_num, SPINLOCK);
	assert(info->session_table);	
	
	info->log_c = log_init(conf->session_logname, DEBUG);
	assert(info->log_c);
	log_print(info->log_c, "源IP, 源端口, 目的IP, 目的端口, 协议类型, 上行包数, 下行包数, 上行字节数, 下行字节数\n");
	
	for(i=0; i<sizeof(hash_map)/sizeof(hash_map[0]); i++) {
		if (strcmp(hash_map[i].name, conf->hash_name) == 0) {
			info->hash_cb = hash_map[i].hash_cb;
			break;
		}
	}
	assert(info->hash_cb);
	sf_plugin_tag = tag_id_get_from_name(pktag_hd_p, "sf_plugin");
	this->resource = info;

	return 0;
}

static int32_t session_frm_process(module_info_t *this, void *data)
{
	packet_t *packet = (packet_t *)data;
	session_frm_info *info = (session_frm_info *)this->resource;
	session_frm_stats_t *stats;
	dpi_ipv4_hdr_t *iphdr;
	dpi_l4_hdr_t *l4hdr;
	session_item_t *session;
	session_index_t *buf;
	hash_table_hd_t *hd;
	uint32_t hash;
	uint8_t swap_flag = 0;
	int32_t status;
	
	stats = &info->stats;
	buf = &info->index_cache;
	session = info->session;
	hd = info->session_table;
	info->packet = data;
	
	if (!(packet->prot_types[packet->prot_depth-2] == DPI_PROT_IPV4)) {
		return -UNKNOWN_PKT;
	} else {
		uint8_t last_prot = packet->prot_types[packet->prot_depth-1];
		if ((last_prot != DPI_PROT_TCP) && (last_prot != DPI_PROT_UDP) && (last_prot != DPI_PROT_ICMP)) {
			return -UNKNOWN_PKT;
		}
	}
	iphdr = (dpi_ipv4_hdr_t *)((void *)packet->data + packet->prot_offsets[packet->prot_depth-2]);
	l4hdr = (dpi_l4_hdr_t *)((void *)packet->data + packet->prot_offsets[packet->prot_depth-1]);
	buf->ip[0] = ntohl(iphdr->src_ip);
	buf->ip[1] = ntohl(iphdr->dst_ip);
	buf->port[0] = ntohs(l4hdr->src_port);
	buf->port[1] = ntohs(l4hdr->dst_port);
	buf->protocol = iphdr->protocol;
	
	if (buf->ip[0] > buf->ip[1]) {
		swap(buf->ip[0], buf->ip[1]);
		swap(buf->port[0], buf->port[1]);
		swap_flag = 1;
	}

	hash = info->hash_cb(buf);
	hash = hash % hd->bucket_num;

	hash_table_lock(hd, hash, 0);
	session = hash_table_search(hd, hash, NULL, session_compare, buf, NULL);
	
	if (session == NULL) {
		/*新建流*/
		session = (session_item_t *)malloc(sizeof(session_item_t));
		if (session == NULL) {
			log_error(syslog_p, "new session no space now\n");
			goto failed;
		}
		
		__init_session(session, buf, packet);
		INC_CNT(stats->session_count);
		status = hash_table_insert(hd, hash, session);
		if (status != 0) {
			log_error(syslog_p, "new session insert error, status=%d\n", status);
			goto failed;
		}
	} 
	info->session = session;

	if (swap_flag) {
		/*包的ip1和ip2已经交换过了，所以把包的方向换过来*/
		packet->dir = session->dir ^ SESSION_DIR_MASK;
	} else {
		packet->dir = session->dir;
	}

	__update_session_count(session, packet);
	hash_table_unlock(hd, hash, 0);
	if (packet->real_applen == 0) {
		/*app length is 0*/
		return 0;
	} else {
		return sf_plugin_tag;
	}
failed:
	INC_CNT(stats->session_failed);
	hash_table_unlock(hd, hash, 0);
	return 0;
}

static void* session_frm_result_get(module_info_t *this)
{
	session_frm_info *info = this->resource;
	return info->packet;
}

static void session_frm_result_free(module_info_t *this)
{
	session_frm_info *info = (session_frm_info *)this->resource;
	info->packet = NULL;
	info->session = NULL;
}


static char *__get_ip_protocol_name(uint16_t protocol)
{
	switch(protocol) {
	case 1:
		return "icmp";
	case 6:
		return "tcp";
	case 17:
		return "udp";
	default:
		return "error";
		break;
	}
	return "error";
}
static void session_item_show(session_frm_info *info)
{
	session_frm_stats_t *stats = &info->stats;
	hash_table_hd_t *session_table = info->session_table;
	uint32_t i;
	char ip0[20], ip1[20];
	uint32_t ip0_int, ip1_int;
	uint16_t port0, port1;
	uint32_t bucket, max_bucket = 0;
	
	log_notice(syslog_p, "\n-----------------sessioninfo---------------\n");
    log_notice(syslog_p, "unknown_pkts=%llu\n", stats->unknown_pkts);
    log_notice(syslog_p, "unknown_dir=%llu\n", stats->unknown_dir);
    log_notice(syslog_p, "session_count=%llu\n", stats->session_count);
	log_notice(syslog_p, "session_failed=%llu\n", stats->session_failed);

	for (i=0; i<session_table->bucket_num; i++) {
		session_item_t *item = NULL;
		bucket = 0;
		hash_table_lock(session_table, i, 0);
		hash_table_one_bucket_for_each(session_table, i, item) {
			ip0_int = htonl(item->index.ip[0]);
			ip1_int = htonl(item->index.ip[1]);
			port0 = item->index.port[0];
			port1 = item->index.port[1];
			bucket++;
			
			if (item->dir == SESSION_INDEX_DNSTREAM) {
				/*如果索引是下行的，交换一下ip和端口来展示*/
				swap(ip0_int, ip1_int);
				swap(port0, port1);
			}
			/*源ip，源端口，目的ip, 目的端口，协议类型，上行包数，下行包数，上行字节数，下行字节数*/
			log_print(info->log_c, "%s,%d,%s,%d,%s,%d,%d,%d,%d\n", 
					   inet_ntop(AF_INET, &ip0_int, ip0, sizeof(ip0)), 
					   port0,
					   inet_ntop(AF_INET, &ip1_int, ip1, sizeof(ip1)), 
					   port1,
					   __get_ip_protocol_name(item->index.protocol),
					  item->flow[0].pkts, item->flow[1].pkts,
					  item->flow[0].bytes, item->flow[1].bytes);
		}
		hash_table_unlock(session_table, i, 0);
		if (bucket > max_bucket) {
			max_bucket = bucket;
		}
	}
	log_notice(syslog_p, "max_bucket=%d\n", max_bucket);
}

static void __session_table_clear(hash_table_hd_t *session_table)
{
	uint32_t i;
	int32_t status;

	for (i=0; i<session_table->bucket_num; i++) {
		session_item_t *item = NULL;
		hash_table_lock(session_table, i, 0);
		hash_table_one_bucket_for_each(session_table, i, item) {
			if (item) {
				status = hash_table_remove(session_table, i, item);
				if (status != 0) {
					log_error(syslog_p, "remove item error, status %d\n", status);
				}
				free(item);
			}
		}
		hash_table_unlock(session_table, i, 0);
	}
}

static int32_t session_frm_fini(module_info_t *this)
{
	session_frm_info *info = (session_frm_info *)this->resource;

	session_item_show(info);

	if (info != NULL) {
		if (info->log_c) {
			log_fini(&info->log_c);
		}
		if (info->session_table) {
			__session_table_clear(info->session_table);
		}
	}

	free(info);
	return 0;
}
