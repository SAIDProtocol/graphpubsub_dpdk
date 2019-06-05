/* 
 * File:   test_gps_i_forwarder_logic.c
 * Author: Jiachen Chen
 */
#include <cmdline_parse_etheraddr.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <stdbool.h>
#include <urcu/urcu-qsbr.h>
#include "gps_i_forwarder_common.h"
#include "gps_i_forwarder_encap_decap.h"
#include "gps_i_forwarder_publication.h"

#define RTE_LOGTYPE_TEST_FORWARDER_LOGIC RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) \
    RTE_LOG(INFO, TEST_FORWARDER_LOGIC, "[%s():%d] " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, __VA_ARGS__)
#define FAIL(...) _FAIL(__VA_ARGS__, "dummy")
#define _FAIL(fmt, ...) \
    rte_exit(EXIT_FAILURE, "[%s():%d] " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_HEAD() \
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__)

void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void dump_mem(const char *file_name);
void test_forwarder_logic(void);

typedef void (test_forwarder_logic_generator_t) (struct rte_ring *, struct gps_i_forwarder_control_plane *);
void generator_decapsulation(struct rte_ring *processor_ring, struct gps_i_forwarder_control_plane * forwarder);
void generator_publication_upstream(struct rte_ring *processor_ring, struct gps_i_forwarder_control_plane * forwarder);
void generator_publication_downstream(struct rte_ring *processor_ring, struct gps_i_forwarder_control_plane * forwarder);

#define TEST_OUTGOING_RING_SIZE 3
#define TEST_BURST_SIZE 64

static struct rte_ring **
prepare_outgoing_rings(const char *name, uint16_t outgoing_ring_count,
        unsigned socket_id) {
    char tmp_name[RTE_MEMZONE_NAMESIZE];
    uint16_t i;
    uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct rte_ring *);
    struct rte_ring **ret;

    snprintf(tmp_name, sizeof (tmp_name), "OTR_%s", name);
    ret = rte_zmalloc_socket(tmp_name, outgoing_ring_size, 0, socket_id);
    if (unlikely(ret == NULL)) {
        DEBUG("fail to create outgoing_ring buffer, reason: %s",
                rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("ret=%p", ret);

    for (i = 0; i < outgoing_ring_count; i++) {
        snprintf(tmp_name, sizeof (tmp_name), "OTR_%s_%" PRIu16, name, i);
        ret[i] = rte_ring_create(tmp_name, GPS_I_FORWARDER_INCOMING_RING_SIZE, socket_id, RING_F_SC_DEQ);
        if (unlikely(ret[i] == NULL)) {
            DEBUG("fail to create outgoing_ring %" PRIu16 ", reason: %s",
                    i, rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("ret[%" PRIu16 "]=%p", i, ret[i]);
    }
    return ret;
fail:
    if (ret != NULL) {
        for (i = 0; i < outgoing_ring_count; i++)
            if (ret[i] != NULL) {
                DEBUG("free ret[%" PRIu16 "]=%p", i, ret[i]);
                rte_ring_free(ret[i]);
            }

        memset(ret, 0, outgoing_ring_size);
        DEBUG("free ret=%p", ret);
        rte_free(ret);
    }
    return NULL;
}

static void
destroy_outgoing_rings(struct rte_ring *outgoing_rings[],
        uint16_t outgoing_ring_count) {
    uint16_t i;
    uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct rte_ring *);
    for (i = 0; i < outgoing_ring_count; i++) {
        DEBUG("free outgoing_rings[%" PRIu16 "] %p", i, outgoing_rings[i]);
        rte_ring_free(outgoing_rings[i]);
    }

    memset(outgoing_rings, 0, outgoing_ring_size);
    DEBUG("free outgoing_rings=%p", outgoing_rings);
    rte_free(outgoing_rings);
}

volatile bool running = false;

static int
test_forwarder_logic_receive(void *param) {
    uint16_t i;
    struct rte_mbuf * pkts[TEST_BURST_SIZE];
    unsigned burst_size, j;

    struct rte_ring **rings = param;

    DEBUG("Receive start, param=%p", param);
    while (running) {
        for (i = 0; i < TEST_OUTGOING_RING_SIZE; i++) {
            burst_size = rte_ring_dequeue_burst(rings[i], (void **) pkts, TEST_BURST_SIZE, NULL);
            for (j = 0; j < burst_size; j++) {
                DEBUG("Got packet %p from output ring %" PRIu16 ", data size=%" PRIu16 ", free", pkts[j], i, rte_pktmbuf_data_len(pkts[j]));
                print_buf(rte_pktmbuf_mtod(pkts[j], void *), rte_pktmbuf_data_len(pkts[j]), 16);
                rte_pktmbuf_free(pkts[j]);
            }
        }
    }
    DEBUG("Receive end");
    return 0;
}

static int
test_forwarder_logic_control(void *param) {
    struct gps_i_forwarder_control_lcore *control_lcore = param;
    struct rte_mbuf * pkts[TEST_BURST_SIZE];
    unsigned burst_size, j;


    DEBUG("Control start, param=%p", param);
    while (running) {
        burst_size = rte_ring_dequeue_burst(control_lcore->incoming_ring, (void **) pkts, TEST_BURST_SIZE, NULL);
        for (j = 0; j < burst_size; j++) {
            control_lcore->received_count++;
            DEBUG("Got packet %p from incoming ring, data size=%" PRIu16 ", free", pkts[j], rte_pktmbuf_data_len(pkts[j]));
            print_buf(rte_pktmbuf_mtod(pkts[j], void *), rte_pktmbuf_data_len(pkts[j]), 16);
            rte_pktmbuf_free(pkts[j]);
            printf("\n");
        }
        urcu_qsbr_synchronize_rcu();
    }
    DEBUG("Control end");
    return 0;
}

static int
test_forwarder_logic_process(void *param) {
    struct gps_i_forwarder_process_lcore *process_lcore = param;
    struct rte_mbuf * pkts[TEST_BURST_SIZE];
    unsigned burst_size, j;

    urcu_qsbr_register_thread();

    DEBUG("Process start, param=%p", param);
    while (running) {
        burst_size = rte_ring_dequeue_burst(process_lcore->incoming_ring, (void **) pkts, TEST_BURST_SIZE, NULL);
        for (j = 0; j < burst_size; j++) {
            DEBUG("Got packet from incoming ring, data size=%" PRIu16, rte_pktmbuf_data_len(pkts[j]));
            gps_i_forwarder_handle_packet(process_lcore, pkts[j]);
            printf("\n");
        }
        urcu_qsbr_quiescent_state();
    }
    DEBUG("Process end");
    urcu_qsbr_unregister_thread();

    return 0;
}

static void
test_logic_master(const char *name, test_forwarder_logic_generator_t *generator) {
    DEBUG_HEAD();
    struct gps_i_forwarder_control_plane *forwarder_c = NULL;
    struct gps_i_forwarder_data_plane *forwarder_d;
    struct gps_i_forwarder_process_lcore *process_lcore;
    struct gps_i_forwarder_control_lcore *control_lcore;
    struct gps_na na;
    struct rte_ring **outgoing_rings = NULL;
    struct gps_i_neighbor_info encap[TEST_OUTGOING_RING_SIZE];
    char info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    unsigned lcore = -1;
    unsigned socket_id;
    uint16_t i;

    if (rte_lcore_count() < 4) {
        FAIL("Need at least 4 cores!");
    }


    gps_na_set(&na, 0x101);
    // set encap
    for (i = 0; i < TEST_OUTGOING_RING_SIZE; i++) {
        encap[i].port = i;
        encap[i].use_ip = true;
        encap[i].ip = rte_cpu_to_be_32(IPv4(192, 168 + i, 1, 100 + i));
        cmdline_parse_etheraddr(NULL, "ec:0d:9a:7e:90:c6", &encap[i].ether, sizeof (encap[i].ether));
        encap[i].ether.addr_bytes[5] += i;
        DEBUG("encap[%" PRIu16 "]=%s [%p]", i,
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), encap + i),
                encap + i);
    }



    socket_id = rte_socket_id();
    forwarder_c = gps_i_forwarder_control_plane_create(name, socket_id, &na, encap);
    if (forwarder_c == NULL) FAIL("Cannot create forwarder_c");
    DEBUG("forwarder_c=%p", forwarder_c);
    forwarder_d = gps_i_forwarder_control_plane_to_data_plane(forwarder_c);
    DEBUG("forwarder_d=%p", forwarder_d);

    outgoing_rings = prepare_outgoing_rings(name, TEST_OUTGOING_RING_SIZE, socket_id);
    if (unlikely(outgoing_rings == NULL)) FAIL("Cannot create rings");

    control_lcore = gps_i_forwarder_control_lcore_create(name, forwarder_c,
            outgoing_rings, TEST_OUTGOING_RING_SIZE, socket_id);
    if (unlikely(control_lcore == NULL)) FAIL("Cannot create control_lcore");

    process_lcore = gps_i_forwarder_process_lcore_create(name, forwarder_d,
            control_lcore->incoming_ring, outgoing_rings, TEST_OUTGOING_RING_SIZE,
            socket_id);
    if (unlikely(process_lcore == NULL)) FAIL("Cannot create process_lcore");
    printf("\n");

    running = true;
    lcore = rte_get_next_lcore(lcore, 1, 0);
    rte_eal_remote_launch(test_forwarder_logic_receive, outgoing_rings, lcore);

    lcore = rte_get_next_lcore(lcore, 1, 0);
    rte_eal_remote_launch(test_forwarder_logic_control, control_lcore, lcore);

    lcore = rte_get_next_lcore(lcore, 1, 0);
    rte_eal_remote_launch(test_forwarder_logic_process, process_lcore, lcore);

    rte_delay_ms(100);

    generator(process_lcore->incoming_ring, forwarder_c);
    //
    rte_delay_ms(100);
    running = false;

    RTE_LCORE_FOREACH_SLAVE(lcore) {
        rte_eal_wait_lcore(lcore);
    }
    DEBUG("Finish");

    DEBUG("process lcore stat:");
    gps_i_forwarder_process_lcore_print_stat(stdout, process_lcore, TEST_OUTGOING_RING_SIZE);
    DEBUG("control lcore stat:");
    gps_i_forwarder_control_lcore_print_stat(stdout, control_lcore, TEST_OUTGOING_RING_SIZE);

    printf("\n");
    gps_i_forwarder_process_lcore_destroy(process_lcore, TEST_OUTGOING_RING_SIZE);
    gps_i_forwarder_control_lcore_destroy(control_lcore, TEST_OUTGOING_RING_SIZE);
    destroy_outgoing_rings(outgoing_rings, TEST_OUTGOING_RING_SIZE);
    gps_i_forwarder_control_plane_destroy(forwarder_c);

}

void
generator_decapsulation(struct rte_ring *processor_ring, struct gps_i_forwarder_control_plane * forwarder) {
    struct rte_mbuf *pkt;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
    struct rte_mempool *pkt_pool = forwarder->pkt_pool;

    DEBUG(">>>> packet too small for Ether");
    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    rte_pktmbuf_append(pkt, sizeof (struct ether_hdr) - 1);
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> wrong ether type");
    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(pkt, sizeof (struct ether_hdr));
    DEBUG("eth_hdr=%p, pkt_start=%p", eth_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(eth_hdr == NULL)) FAIL("Cannot get eth_hdr, reason: %s", rte_strerror(rte_errno));
    eth_hdr->ether_type = rte_cpu_to_be_16(GPS_PROTO_TYPE_ETHER + 1);
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> correct ether packet");
    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(pkt, sizeof (struct ether_hdr));
    DEBUG("eth_hdr=%p, pkt_start=%p", eth_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(eth_hdr == NULL)) FAIL("Cannot get eth_hdr, reason: %s", rte_strerror(rte_errno));
    eth_hdr->ether_type = rte_cpu_to_be_16(GPS_PROTO_TYPE_ETHER);
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> pkt too small for IP");
    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(pkt, sizeof (struct ether_hdr));
    DEBUG("eth_hdr=%p, pkt_start=%p", eth_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(eth_hdr == NULL)) FAIL("Cannot get eth_hdr, reason: %s", rte_strerror(rte_errno));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    rte_pktmbuf_append(pkt, sizeof (struct ipv4_hdr) - 1);
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> wrong ip type");
    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(pkt, sizeof (struct ether_hdr));
    DEBUG("eth_hdr=%p, pkt_start=%p", eth_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(eth_hdr == NULL)) FAIL("Cannot get eth_hdr, reason: %s", rte_strerror(rte_errno));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ip_hdr = (struct ipv4_hdr *) rte_pktmbuf_append(pkt, sizeof (struct ipv4_hdr));
    DEBUG("ip_hdr=%p, pkt_start=%p", ip_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(ip_hdr == NULL)) FAIL("Cannot get ip_hdr, reason: %s", rte_strerror(rte_errno));
    ip_hdr->version_ihl = 0x45;
    ip_hdr->next_proto_id = GPS_PROTO_TYPE_IP + 1;
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> correct ip packet");
    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(pkt, sizeof (struct ether_hdr));
    DEBUG("eth_hdr=%p, pkt_start=%p", eth_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(eth_hdr == NULL)) FAIL("Cannot get eth_hdr, reason: %s", rte_strerror(rte_errno));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ip_hdr = (struct ipv4_hdr *) rte_pktmbuf_append(pkt, sizeof (struct ipv4_hdr));
    DEBUG("ip_hdr=%p, pkt_start=%p", ip_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(ip_hdr == NULL)) FAIL("Cannot get ip_hdr, reason: %s", rte_strerror(rte_errno));
    ip_hdr->version_ihl = 0x45;
    ip_hdr->next_proto_id = GPS_PROTO_TYPE_IP;
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> correct ip packet, but too small for ip header");
    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(pkt, sizeof (struct ether_hdr));
    DEBUG("eth_hdr=%p, pkt_start=%p", eth_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(eth_hdr == NULL)) FAIL("Cannot get eth_hdr, reason: %s", rte_strerror(rte_errno));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ip_hdr = (struct ipv4_hdr *) rte_pktmbuf_append(pkt, sizeof (struct ipv4_hdr));
    DEBUG("ip_hdr=%p, pkt_start=%p", ip_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(ip_hdr == NULL)) FAIL("Cannot get ip_hdr, reason: %s", rte_strerror(rte_errno));
    ip_hdr->version_ihl = 0x46;
    ip_hdr->next_proto_id = GPS_PROTO_TYPE_IP;
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> correct ip packet");
    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(pkt, sizeof (struct ether_hdr));
    DEBUG("eth_hdr=%p, pkt_start=%p", eth_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(eth_hdr == NULL)) FAIL("Cannot get eth_hdr, reason: %s", rte_strerror(rte_errno));
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
    ip_hdr = (struct ipv4_hdr *) rte_pktmbuf_append(pkt, sizeof (struct ipv4_hdr) + 8);
    DEBUG("ip_hdr=%p, pkt_start=%p", ip_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(ip_hdr == NULL)) FAIL("Cannot get ip_hdr, reason: %s", rte_strerror(rte_errno));
    ip_hdr->version_ihl = 0x47;
    ip_hdr->next_proto_id = GPS_PROTO_TYPE_IP;
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);
}

static inline struct rte_mbuf *
create_correct_ether_pkt(struct rte_mempool *pkt_pool) {
    struct rte_mbuf *pkt;
    struct ether_hdr *eth_hdr;

    pkt = rte_pktmbuf_alloc(pkt_pool);
    DEBUG("got pkt: %p", pkt);
    if (unlikely(pkt == NULL)) FAIL("Cannot get packet from pool, reason: %s", rte_strerror(rte_errno));
    DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(pkt, sizeof (struct ether_hdr));
    DEBUG("eth_hdr=%p, pkt_start=%p", eth_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(eth_hdr == NULL)) FAIL("Cannot get eth_hdr, reason: %s", rte_strerror(rte_errno));
    eth_hdr->ether_type = rte_cpu_to_be_16(GPS_PROTO_TYPE_ETHER);

    return pkt;
}

void
generator_publication_upstream(struct rte_ring *processor_ring, struct gps_i_forwarder_control_plane * forwarder) {
    struct rte_mbuf *pkt;
    char *gps_hdr;
    struct gps_na na, next_hop_na;
    struct gps_guid guid;
    struct gps_i_neighbor_info *info, *ret_info;
    int32_t ret;
    uint32_t distance;
    struct rte_mempool *pkt_pool = forwarder->pkt_pool;

    char na_buf[GPS_NA_FMT_SIZE], next_hop_na_buf[GPS_NA_FMT_SIZE], guid_buf[GPS_GUID_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

    info = gps_i_neighbor_table_get_entry(forwarder->neighbor_table);
    DEBUG("neighbor table get entry=%p", info);
    if (info == NULL) FAIL("Cannot get entry from neighbor table");
    cmdline_parse_etheraddr(NULL, "aa:bb:cc:dd:ee:ff", &info->ether, sizeof (info->ether));
    info->use_ip = false;
    info->port = 1;
    ret_info = gps_i_neighbor_table_set(forwarder->neighbor_table, gps_na_set(&na, 0x23456), info);
    DEBUG("neighbor table set %s -> %s, ret=%p", gps_na_format(na_buf, sizeof (na_buf), &na), gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info), ret_info);
    if (ret_info != NULL) FAIL("Cannot set entry into neighbor table, ret=%p", ret_info);

    info = gps_i_neighbor_table_get_entry(forwarder->neighbor_table);
    DEBUG("neighbor table get entry=%p", info);
    if (info == NULL) FAIL("Cannot get entry from neighbor table");
    cmdline_parse_etheraddr(NULL, "99:88:77:66:55:44", &info->ether, sizeof (info->ether));
    info->use_ip = true;
    info->ip = rte_cpu_to_be_32(IPv4(192, 123, 234, 12));
    info->port = 2;
    ret_info = gps_i_neighbor_table_set(forwarder->neighbor_table, gps_na_set(&na, 0x24567), info);
    DEBUG("neighbor table set %s -> %s, ret=%p", gps_na_format(na_buf, sizeof (na_buf), &na), gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info), ret_info);
    if (ret_info != NULL) FAIL("Cannot set entry into neighbor table, ret=%p", ret_info);
    gps_i_neighbor_table_print(forwarder->neighbor_table, stdout, "TEST_FORWARDER_LOGIC: [%s():%d] routing table", __func__, __LINE__);

    info = gps_i_neighbor_table_get_entry(forwarder->neighbor_table);
    DEBUG("neighbor table get entry=%p", info);
    if (info == NULL) FAIL("Cannot get entry from neighbor table");
    memset(&info->ether, 0, sizeof (info->ether));
    info->use_ip = false;
    info->port = 0;
    ret_info = gps_i_neighbor_table_set(forwarder->neighbor_table, &forwarder->my_na, info);
    DEBUG("neighbor table set %s -> %s, ret=%p", gps_na_format(na_buf, sizeof (na_buf), &forwarder->my_na), gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info), ret_info);
    if (ret_info != NULL) FAIL("Cannot set entry into neighbor table, ret=%p", ret_info);

    ret = gps_i_routing_table_set(forwarder->routing_table,
            gps_na_set(&na, 0x13456),
            gps_na_set(&next_hop_na, 0x23456), distance = 1);
    DEBUG("routing table set %s -> %s (%" PRIu32 "), ret=%" PRIi32, gps_na_format(na_buf, sizeof (na_buf), &na), gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), distance, ret);
    if (ret < 0) FAIL("Cannot set routing table");
    ret = gps_i_routing_table_set(forwarder->routing_table,
            gps_na_set(&na, 0x14567),
            gps_na_set(&next_hop_na, 0x24567), distance = 1);
    DEBUG("routing table set %s -> %s (%" PRIu32 "), ret=%" PRIi32, gps_na_format(na_buf, sizeof (na_buf), &na), gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), distance, ret);
    if (ret < 0) FAIL("Cannot set routing table");
    ret = gps_i_routing_table_set(forwarder->routing_table,
            &forwarder->my_na,
            &forwarder->my_na, distance = 1);
    DEBUG("routing table set %s -> %s (%" PRIu32 "), ret=%" PRIi32, gps_na_format(na_buf, sizeof (na_buf), &forwarder->my_na), gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &forwarder->my_na), distance, ret);
    if (ret < 0) FAIL("Cannot set routing table");
    gps_i_routing_table_print(forwarder->routing_table, stdout, "TEST_FORWARDER_LOGIC: [%s():%d] routing table", __func__, __LINE__);

    ret = gps_i_gnrs_cache_set(forwarder->gnrs_cache,
            gps_guid_set(&guid, 0x12345678),
            gps_na_copy(&na, &forwarder->my_na), 1);
    DEBUG("gnrs cache set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    if (ret < 0) FAIL("Cannot set gnrs cache");
    //    ret = gps_i_gnrs_cache_set(forwarder->gnrs_cache,
    //            gps_guid_set(&guid, 0x22345678),
    //            gps_na_set(&na, 0x87654321), 1);
    //    DEBUG("gnrs cache set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    //    if (ret < 0) FAIL("Cannot set gnrs cache");
    //    ret = gps_i_gnrs_cache_set(forwarder->gnrs_cache,
    //            gps_guid_set(&guid, 0x32345678),
    //            gps_na_set(&na, 0x11234), 1);
    //    DEBUG("gnrs cache set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    //    if (ret < 0) FAIL("Cannot set gnrs cache");
    ret = gps_i_gnrs_cache_set(forwarder->gnrs_cache,
            gps_guid_set(&guid, 0x42345678),
            gps_na_set(&na, 0x13456), 1);
    DEBUG("gnrs cache set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    if (ret < 0) FAIL("Cannot set gnrs cache");
    ret = gps_i_gnrs_cache_set(forwarder->gnrs_cache,
            gps_guid_set(&guid, 0x52345678),
            gps_na_set(&na, 0x14567), 1);
    DEBUG("gnrs cache set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    if (ret < 0) FAIL("Cannot set gnrs cache");
    gps_i_gnrs_cache_print(forwarder->gnrs_cache, stdout, "TEST_FORWARDER_LOGIC: [%s():%d] gnrs cache", __func__, __LINE__);

    printf("\n");

    rte_delay_ms(20);

    DEBUG(">>>> error packet type");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, 4);
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, 0xd0);
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> too small publication");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, 4);
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication size not match");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 20);
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication upstream first hop, cannot find guid");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x87654321); // cannot find guid
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    //    DEBUG(">>>> publication upstream first hop, can find guid, but cannot find nexthop na");
    //    pkt = create_correct_ether_pkt(pkt_pool);
    //    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    //    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    //    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    //    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    //    gps_pkt_publication_set_size(gps_hdr, 0);
    //    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    //    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    //    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x22345678); // can find guid, but cannot find nexthop na
    //    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    //    rte_ring_enqueue(processor_ring, pkt);
    //
    //    rte_delay_ms(20);
    //
    //    DEBUG(">>>> publication upstream first hop, can find guid, can find nexthop na, not self, next_hop_na not in neighbor table");
    //    pkt = create_correct_ether_pkt(pkt_pool);
    //    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    //    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    //    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    //    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    //    gps_pkt_publication_set_size(gps_hdr, 0);
    //    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    //    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    //    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x32345678); // can find guid, can find nexthop na, not self, next_hop_na not in neighbor table
    //    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    //    rte_ring_enqueue(processor_ring, pkt);
    //
    //    rte_delay_ms(20);
    //
    DEBUG(">>>> publication upstream first hop, can find guid, can find nexthop na, not self, next_hop_na uses ether");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x42345678); // can find guid, can find nexthop na, not self, next_hop_na uses ether
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication upstream first hop, can find guid, can find nexthop na, not self, next_hop_na uses ip");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x52345678); // can find guid, can find nexthop na, not self, next_hop_na uses ip
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x52345678); // can find guid, can find nexthop na, not self, next_hop_na uses ip
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication upstream not first hop, cannot find next hop na");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0x87654321); // not first hop, cannot find next hop na
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication upstream not first hop, can find next hop na");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0x13456); // not first hop, cannot find next hop na
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication upstream first hop, can find guid, can find nexthop na, self, rp does not serve");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x12345678); //can find guid, can find nexthop na, self, rp does not serve
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication upstream not first hop, self, rp does not serve");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(&na, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0); // upstream
    gps_na_copy(gps_pkt_publication_get_dst_na(gps_hdr), &forwarder->my_na); // not first hop, self
    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x12345678); // rp does not serve
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication upstream first hop, can find guid, can find nexthop na, self, rp serves");
}

void
generator_publication_downstream(struct rte_ring *processor_ring, struct gps_i_forwarder_control_plane *forwarder) {
    struct rte_mbuf *pkt;
    char *gps_hdr;
    struct gps_na na;
    struct gps_guid guid;
    struct gps_i_neighbor_info *neighbor_info, *ret_info;
    int32_t ret;
    struct rte_mempool *pkt_pool = forwarder->pkt_pool;

    char na_buf[GPS_NA_FMT_SIZE], guid_buf[GPS_GUID_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    
    neighbor_info = gps_i_neighbor_table_get_entry(forwarder->neighbor_table);
    DEBUG("neighbor table get entry=%p", neighbor_info);
    if (neighbor_info == NULL) FAIL("Cannot get entry from neighbor table");
    cmdline_parse_etheraddr(NULL, "aa:bb:cc:dd:ee:ff", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->use_ip = false;
    neighbor_info->port = 0;
    ret_info = gps_i_neighbor_table_set(forwarder->neighbor_table, gps_na_set(&na, 0x12345), neighbor_info);
    DEBUG("neighbor table set %s -> %s, ret=%p", gps_na_format(na_buf, sizeof (na_buf), &na), gps_i_neighbor_info_format(info_buf, sizeof (info_buf), neighbor_info), ret_info);
    if (ret_info != NULL) FAIL("Cannot set entry into neighbor table, ret=%p", ret_info);
    neighbor_info = gps_i_neighbor_table_get_entry(forwarder->neighbor_table);
    DEBUG("neighbor table get entry=%p", neighbor_info);
    if (neighbor_info == NULL) FAIL("Cannot get entry from neighbor table");
    cmdline_parse_etheraddr(NULL, "bb:cc:dd:ee:ff:00", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->use_ip = false;
    neighbor_info->port = 1;
    ret_info = gps_i_neighbor_table_set(forwarder->neighbor_table, gps_na_set(&na, 0x23456), neighbor_info);
    DEBUG("neighbor table set %s -> %s, ret=%p", gps_na_format(na_buf, sizeof (na_buf), &na), gps_i_neighbor_info_format(info_buf, sizeof (info_buf), neighbor_info), ret_info);
    if (ret_info != NULL) FAIL("Cannot set entry into neighbor table, ret=%p", ret_info);
    neighbor_info = gps_i_neighbor_table_get_entry(forwarder->neighbor_table);
    DEBUG("neighbor table get entry=%p", neighbor_info);
    if (neighbor_info == NULL) FAIL("Cannot get entry from neighbor table");
    cmdline_parse_etheraddr(NULL, "cc:dd:ee:ff:00:11", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->use_ip = false;
    neighbor_info->port = 2;
    ret_info = gps_i_neighbor_table_set(forwarder->neighbor_table, gps_na_set(&na, 0x34567), neighbor_info);
    DEBUG("neighbor table set %s -> %s, ret=%p", gps_na_format(na_buf, sizeof (na_buf), &na), gps_i_neighbor_info_format(info_buf, sizeof (info_buf), neighbor_info), ret_info);
    if (ret_info != NULL) FAIL("Cannot set entry into neighbor table, ret=%p", ret_info);
    gps_i_neighbor_table_print(forwarder->neighbor_table, stdout, "TEST_FORWARDER_LOGIC: [%s():%d] routing table", __func__, __LINE__);

    
    ret = gps_i_subscription_table_set(forwarder->subscription_table,
            gps_guid_set(&guid, 0x12345678),
            gps_na_set(&na, 0x12345));
    DEBUG("subscription set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    if (ret < 0) FAIL("Cannot set subscription table");
    ret = gps_i_subscription_table_set(forwarder->subscription_table,
            gps_guid_set(&guid, 0x23456789),
            gps_na_set(&na, 0x12345));
    DEBUG("subscription set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    if (ret < 0) FAIL("Cannot set subscription table");
    ret = gps_i_subscription_table_set(forwarder->subscription_table,
            gps_guid_set(&guid, 0x23456789),
            gps_na_set(&na, 0x23456));
    DEBUG("subscription set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    if (ret < 0) FAIL("Cannot set subscription table");
    ret = gps_i_subscription_table_set(forwarder->subscription_table,
            gps_guid_set(&guid, 0x23456789),
            gps_na_set(&na, 0x34567));
    DEBUG("subscription set %s -> %s, ret=%" PRIi32, gps_guid_format(guid_buf, sizeof (guid_buf), &guid), gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    if (ret < 0) FAIL("Cannot set subscription table");
    gps_i_subscription_table_print(forwarder->subscription_table, stdout, "TEST_FORWARDER_LOGIC: [%s():%d] after set", __func__, __LINE__);


    printf("\n");


    DEBUG(">>>> publication downstream 1 next hop");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0xdead); // downstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x12345678); // 1 next hop
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);

    DEBUG(">>>> publication downstream 3 next hops");
    pkt = create_correct_ether_pkt(pkt_pool);
    gps_hdr = rte_pktmbuf_append(pkt, sizeof (struct gps_pkt_publication));
    DEBUG("gps_hdr=%p, pkt_start=%p", gps_hdr, rte_pktmbuf_mtod(pkt, void *));
    if (unlikely(gps_hdr == NULL)) FAIL("Cannot get gps_hdr, reason: %s", rte_strerror(rte_errno));
    gps_pkt_set_type(gps_hdr, GPS_PKT_TYPE_PUBLICATION);
    gps_pkt_publication_set_size(gps_hdr, 0);
    gps_na_set(gps_pkt_publication_get_src_na(gps_hdr), 0xdead); // downstream
    gps_na_set(gps_pkt_publication_get_dst_na(gps_hdr), 0); // first hop
    gps_guid_set(gps_pkt_publication_get_dst_guid(gps_hdr), 0x23456789); // 3 next hops
    print_buf(rte_pktmbuf_mtod(pkt, void *), rte_pktmbuf_data_len(pkt), 16);
    rte_ring_enqueue(processor_ring, pkt);

    rte_delay_ms(20);
}

void
test_forwarder_logic(void) {
    dump_mem("dmp_test_forwarder_logic_0.txt");
    //    test_logic_master("decap", generator_decapsulation);
    dump_mem("dmp_test_forwarder_logic_1.txt");
    //    test_logic_master("decap", generator_publication_upstream);
    dump_mem("dmp_test_forwarder_logic_2.txt");
    test_logic_master("decap", generator_publication_downstream);
    dump_mem("dmp_test_forwarder_logic_3.txt");
}