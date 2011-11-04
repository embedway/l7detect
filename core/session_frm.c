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
#include "sys.h"
#include "conf.h"
#include "parser.h"
#include "log.h"
#include "process.h"
#include "hash_table.h"
#include "decap.h"

#define INC_CNT(count) count++

static int32_t session_frm_init_global(module_info_t *this);
static int32_t session_frm_init_local(module_info_t *this, uint32_t thread_id);
static int32_t session_frm_process(module_info_t *this, void *data);
static void* session_frm_result_get(module_info_t *this);
static void session_frm_result_free(module_info_t *this);
static int session_frm_fini_global(module_info_t *this);
static int session_frm_fini_local(module_info_t *this, uint32_t thread_id);

static uint16_t sf_plugin_tag;
static uint16_t parsed_tag;
static uint16_t next_stage_tag; /*未来扩展使用*/

module_ops_t session_frm_ops = {
	.init_global = session_frm_init_global,
	.init_local = session_frm_init_local,
    .start = NULL,
	.process = session_frm_process,
	.result_get = session_frm_result_get,
	.result_free = session_frm_result_free,
	.fini_global = session_frm_fini_global,
    .fini_local = session_frm_fini_local,
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
	uint32_t hash:24;
} session_index_t;

typedef struct session_item {
	session_index_t index;
	flow_item_t flow[2];		/**< [0]为上行流，[1]为下行流 */
#define FLOW_UP_STREAM_INDEX 0
#define FLOW_DN_STREAM_INDEX 1
	uint16_t dir:2;
#define SESSION_INDEX_UPSTREAM PKT_DIR_UPSTREAM
#define SESSION_INDEX_DNSTREAM PKT_DIR_DNSTREAM
#define SESSION_DIR_MASK 0x3
#define SESSION_DIRTY 0x10
	uint16_t flag:14;
	uint16_t stage;
	uint64_t id;
	uint64_t start_time;
	uint64_t last_time;
	uint32_t app_type;			/**<  协议小类*/
	uint32_t app_state;         /**< 协议识别状态*/
	list_head_t protobuf_head;
}session_item_t;

typedef uint32_t (*hash_func)(session_index_t *info);

typedef struct info_global {
    session_conf_t *conf;
	sf_proto_conf_t *sf_conf;
	hash_table_hd_t *session_table;
	log_t *log_c;
	hash_func hash_cb;
} info_global_t;

typedef struct info_local {
	packet_t *packet;
	session_item_t *session;	    /**< 流表中找到的表项*/
	session_index_t index_cache;	/**< 临时的session cache，减小每次进入函数堆栈分配的开销 */
	session_frm_stats_t stats;
	proto_comm_t proto_buf;        /**< 用于处理时传递上一次的数据给sf_plugin */
} info_local_t;

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
	if (((ip & 0xff000000) == 0xa000000) || ((ip & 0xffff0000) == 0xc0a80000) ||
		((ip >= 0xac100000) && (ip <= 0xac1f0000))) {
		return 1;
	} else {
		return 0;
	}
}

static inline int32_t __session_index_dir(session_index_t *index)
{
	int32_t dir;
	int32_t internal_ip0, internal_ip1;

	internal_ip0 = __is_interal_ip(index->ip[0]);
	internal_ip1 = __is_interal_ip(index->ip[1]);

	if (internal_ip0 && !internal_ip1) {
		dir = PKT_DIR_UPSTREAM;
	} else if (internal_ip1 && !internal_ip0) {
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
	session->app_type = INVALID_PROTO_ID;
	LIST_HEAD_INIT(&session->protobuf_head);
}

static inline uint32_t __post_parsed(hash_table_hd_t *hd, packet_t* packet, session_item_t* session,
							  proto_comm_t *comm, uint32_t final_state)
{
	hash_table_lock(hd, session->index.hash, 0);
	if (comm->state == final_state) {
		session->app_type = packet->app_type;
		/*do some clean things*/
		protobuf_destroy(&session->protobuf_head);
	} else if (comm->state != session->app_state) {
		/*save status*/
		session->app_state = comm->state;
		/*mask在sf_plugin模块中已经被修改*/
	}
    session->flag &= ~SESSION_DIRTY;
    hash_table_unlock(hd, session->index.hash, 0);
	packet->pktag = next_stage_tag;
	return packet->pktag;
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

static int32_t session_frm_init_global(module_info_t *this)
{
    info_global_t *info;
	session_conf_t *conf;
	sf_proto_conf_t *sf_conf;
    hash_table_hd_t *session_table;
	uint32_t i;
	hash_map_t hash_map[] = {
		{"hash_xor", hash_xor},
		{"hash_xor_sum", hash_xor_sum},
		{"hash_sum", hash_sum},
	};

	assert(sizeof(session_item_t) <= 128);
    info = zmalloc(info_global_t *, sizeof(info_global_t));
	assert(info);

	conf = (session_conf_t *)conf_module_config_search("session", NULL);
	assert(conf);

	sf_conf = (sf_proto_conf_t *)conf_module_config_search(SF_PROTO_CONF_NAME, NULL);
	assert(sf_conf);

	session_table = hash_table_init(conf->bucket_num, SPINLOCK);
	assert(session_table);

    info->session_table = session_table;
    info->conf = conf;
    info->sf_conf = sf_conf;

	info->log_c = log_init(conf->session_logname, DEBUG);
	assert(info->log_c);

	for(i=0; i<sizeof(hash_map)/sizeof(hash_map[0]); i++) {
		if (strcmp(hash_map[i].name, conf->hash_name) == 0) {
			info->hash_cb = hash_map[i].hash_cb;
			break;
		}
	}
	assert(info->hash_cb);

    this->pub_rep = info;

    sf_plugin_tag = tag_id_get_from_name(pktag_hd_p, "sf_plugin");
	parsed_tag = tag_id_get_from_name(pktag_hd_p, "parsed");

    return 0;
}


static int32_t session_frm_init_local(module_info_t *this, uint32_t thread_id)
{
    info_local_t *info;
    info = zmalloc(info_local_t *, sizeof(info_local_t));

    module_priv_rep_set(this, thread_id, (void *)info);
    return 0;
}

static int32_t session_frm_process(module_info_t *this, void *data)
{
	packet_t *packet;
    info_global_t *gp;
    info_local_t *lp;
	session_frm_stats_t *stats;
	dpi_ipv4_hdr_t *iphdr;
	dpi_l4_hdr_t *l4hdr;
	session_item_t *session;
	session_index_t *buf;
	hash_table_hd_t *hd;
	uint32_t hash;
	uint8_t swap_flag = 0;
	int32_t status;
	proto_comm_t *comm = NULL;

    gp = (info_global_t *)this->pub_rep;
    lp = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());

	hd = gp->session_table;
	stats = &lp->stats;
	session = lp->session;
	buf = &lp->index_cache;

	if ((lp->packet != NULL) && lp->packet != data) {
		comm = (proto_comm_t *)data;

		packet = comm->packet;
		assert(packet == lp->packet);
	} else {
		packet = (packet_t *)data;
	}

	lp->packet = packet;

	if (packet->pktag == parsed_tag) {
		assert(comm);
		return __post_parsed(hd, packet, session, comm, gp->sf_conf->final_state);
	}

	if (!(packet->prot_types[packet->prot_depth-2] == DPI_PROT_IPV4)) {
		return -UNKNOWN_PKT;
	} else {
		uint8_t last_prot = packet->prot_types[packet->prot_depth-1];
		if ((last_prot != DPI_PROT_TCP) && (last_prot != DPI_PROT_UDP) &&
			(last_prot != DPI_PROT_ICMP)) {
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

	hash = gp->hash_cb(buf);
	hash = hash % hd->bucket_num;
	buf->hash = hash;

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
		session->index.hash = hash;
		status = hash_table_insert(hd, hash, session);
		if (status != 0) {
			log_error(syslog_p, "new session insert error, status=%d\n", status);
			goto failed;
		}
	} else if (session->flag & SESSION_DIRTY) {
        /*当前会话正在处理，立即返回到队列中，等待下次处理*/
       /*还没有实现，有待改进*/
    }
	lp->session = session;

	if (swap_flag) {
		/*包的ip1和ip2已经交换过了，所以把包的方向换过来*/
		packet->dir = (session->dir ^ SESSION_DIR_MASK);
	} else {
		packet->dir = session->dir;
	}

	__update_session_count(session, packet);
    session->flag |= SESSION_DIRTY;
	hash_table_unlock(hd, hash, 0);
	if ((session->app_type != INVALID_PROTO_ID)) {
		/*app length is 0*/
		return next_stage_tag;
	} else {
		packet->pktag = sf_plugin_tag;
		return packet->pktag;
	}
failed:
	INC_CNT(stats->session_failed);
	hash_table_unlock(hd, hash, 0);
	return 0;
}

static void* session_frm_result_get(module_info_t *this)
{
	info_local_t *info;

    info = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());
    assert(info);

    info->proto_buf.packet = info->packet;
	assert(info->session);
	info->proto_buf.state = info->session->app_state;
    /*FIXME:将流表中的协议特征缓存给下一个引擎处理，这样会导致临界区过大，需要调整*/
	info->proto_buf.protobuf_head = &info->session->protobuf_head;

	return &info->proto_buf;
}

static void session_frm_result_free(module_info_t *this)
{
    info_local_t *info;

    info = (info_local_t *)module_priv_rep_get(this, sys_thread_id_get());
    assert(info);

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

static void session_item_show(info_global_t *info, session_frm_stats_t *stats)
{
	hash_table_hd_t *session_table = info->session_table;
	uint32_t i;
	char ip0[20], ip1[20];
	uint32_t ip0_int, ip1_int;
	uint16_t port0, port1;
	uint32_t bucket, max_bucket = 0;
	sf_proto_conf_t *sf_conf = info->sf_conf;

	log_notice(syslog_p, "\n-----------------sessioninfo---------------\n");
    log_notice(syslog_p, "unknown_pkts=%llu\n", stats->unknown_pkts);
    log_notice(syslog_p, "unknown_dir=%llu\n", stats->unknown_dir);
    log_notice(syslog_p, "session_count=%llu\n", stats->session_count);
	log_notice(syslog_p, "session_failed=%llu\n", stats->session_failed);

	log_print(info->log_c, "源IP, 源端口, 目的IP, 目的端口, 协议类型, 上行包数, 下行包数, 上行字节数, 下行字节数, 协议类型\n");

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
			log_print(info->log_c, "%s,%d,%s,%d,%s,%d,%d,%d,%d,%s\n",
					   inet_ntop(AF_INET, &ip0_int, ip0, sizeof(ip0)),
					   port0,
					   inet_ntop(AF_INET, &ip1_int, ip1, sizeof(ip1)),
					   port1,
					   __get_ip_protocol_name(item->index.protocol),
					  item->flow[0].pkts, item->flow[1].pkts,
					  item->flow[0].bytes, item->flow[1].bytes,
					  (item->app_type != INVALID_PROTO_ID) ?
					  sf_conf->protos[item->app_type].name:"Unknown");
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
				protobuf_destroy(&item->protobuf_head);
				free(item);
			}
		}
		hash_table_unlock(session_table, i, 0);
	}
}

static int32_t session_frm_fini_local(module_info_t *this, uint32_t thread_id)
{
    info_local_t *info = (info_local_t *)module_priv_rep_get(this, thread_id);
    if (info) {
        free(info);
    }
    return 0;
}

static int32_t session_frm_fini_global(module_info_t *this)
{
    info_global_t *info = (info_global_t *)this->pub_rep;
    session_frm_stats_t stats;
    uint32_t i;

    memset(&stats, 0, sizeof(session_frm_stats_t));
    for(i=0; i<g_conf.thread_num; i++) {
        info_local_t *info = (info_local_t *)module_priv_rep_get(this, i);
        stats.unknown_pkts += info->stats.unknown_pkts;
        stats.unknown_dir += info->stats.unknown_dir;
        stats.session_count += info->stats.session_count;
        stats.session_failed += info->stats.session_failed;
    }

	session_item_show(info, &stats);

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
