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

typedef void (test_forwarder_logic_generator_t) (struct rte_mempool *, struct rte_ring *);

#define TEST_OUTGOING_RING_SIZE 3
#define TEST_RING_SIZE 1024
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
        ret[i] = rte_ring_create(tmp_name, TEST_RING_SIZE, socket_id, RING_F_SC_DEQ);
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

static struct gps_i_forwarder_control_lcore *
prepare_control_lcore(const char *name,
        struct gps_i_forwarder_control_plane *forwarder,
        struct rte_ring *outgoing_rings[],
        uint16_t outgoing_ring_count,
        unsigned socket_id) {
    char tmp_name[RTE_MEMZONE_NAMESIZE];
    struct gps_i_forwarder_control_lcore *control_lcore;
    uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct rte_ring *);
    uint32_t size = sizeof (struct gps_i_forwarder_control_lcore) +outgoing_ring_size;
    DEBUG("outgoing_ring count=%" PRIu16 ", size=%" PRIu32 ", control_lcore_size=%" PRIu32,
            outgoing_ring_count, outgoing_ring_size, size);

    snprintf(tmp_name, sizeof (tmp_name), "CCORE_%s", name);
    DEBUG("control_lcore name: %s", tmp_name);
    control_lcore = rte_zmalloc_socket(tmp_name, size, 0, socket_id);
    if (unlikely(control_lcore == NULL)) {
        DEBUG("fail to create gps_i_forwarder_control_lcore, reason: %s",
                rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("control_lcore=%p, forwarder=%p, outgoing_rings=%p",
            control_lcore, forwarder, outgoing_rings);

    snprintf(tmp_name, sizeof (tmp_name), "CTR_%s", name);
    DEBUG("incoming_ring name: %s", tmp_name);
    control_lcore->incoming_ring = rte_ring_create(tmp_name,
            TEST_RING_SIZE, socket_id, RING_F_SC_DEQ);
    if (unlikely(control_lcore->incoming_ring == NULL)) {
        DEBUG("fail to create incoming_ring, reason: %s",
                rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("incoming_ring=%p", control_lcore->incoming_ring);

    control_lcore->forwarder = forwarder;
    memcpy(control_lcore->outgoing_rings, outgoing_rings, outgoing_ring_size);
    return control_lcore;
fail:
    if (control_lcore != NULL) {
        if (control_lcore->incoming_ring != NULL) {
            DEBUG("free incoming_ring=%p", control_lcore->incoming_ring);
            rte_ring_free(control_lcore->incoming_ring);
        }
        memset(control_lcore, 0, size);
        DEBUG("free control_lcore=%p", control_lcore);
        rte_free(control_lcore);
    }
    return NULL;
}

static void
destroy_control_lcore(struct gps_i_forwarder_control_lcore *control_lcore,
        uint16_t outgoing_ring_count) {
    uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct rte_ring *);
    uint32_t size = sizeof (struct gps_i_forwarder_control_lcore) +outgoing_ring_size;

    DEBUG("free control_lcore=%p, incoming_ring=%p",
            control_lcore, control_lcore->incoming_ring);
    rte_ring_free(control_lcore->incoming_ring);
    memset(control_lcore, 0, size);
    rte_free(control_lcore);
}

static struct gps_i_forwarder_process_lcore *
prepare_process_lcore(const char *name,
        struct gps_i_forwarder_data_plane *forwarder,
        struct rte_ring *control_ring,
        struct rte_ring *outgoing_rings[],
        uint16_t outgoing_ring_count,
        unsigned socket_id) {
    char tmp_name[RTE_MEMZONE_NAMESIZE];
    struct gps_i_forwarder_process_lcore *process_lcore;
    uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct rte_ring *);
    uint32_t size = sizeof (struct gps_i_forwarder_process_lcore) +outgoing_ring_size;
    DEBUG("outgoing_ring count=%" PRIu16 ", size=%" PRIu32 ", process_lcore_size=%" PRIu32,
            outgoing_ring_count, outgoing_ring_size, size);

    snprintf(tmp_name, sizeof (tmp_name), "PCORE_%s", name);
    DEBUG("process_lcore name: %s", tmp_name);
    process_lcore = rte_zmalloc(tmp_name, size, 0);
    if (unlikely(process_lcore == NULL)) {
        DEBUG("fail to create process_lcore, reason: %s",
                rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("process_lcore=%p, forwarder=%p, control_ring=%p, outgoing_rings=%p",
            process_lcore, forwarder, control_ring, outgoing_rings);

    snprintf(tmp_name, sizeof (tmp_name), "INR_%s", name);
    DEBUG("incoming_ring name: %s", tmp_name);
    process_lcore->incoming_ring = rte_ring_create(tmp_name,
            TEST_RING_SIZE, socket_id, RING_F_SC_DEQ);
    if (unlikely(process_lcore->incoming_ring == NULL)) {
        DEBUG("fail to create incoming_ring, reason: %s",
                rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("incoming_ring=%p", process_lcore->incoming_ring);

    process_lcore->forwarder = forwarder;
    process_lcore->control_ring = control_ring;
    memcpy(process_lcore->outgoing_rings, outgoing_rings, outgoing_ring_size);
    return process_lcore;

fail:
    if (process_lcore != NULL) {

        if (process_lcore->incoming_ring != NULL) {
            DEBUG("free incoming_ring=%p", process_lcore->incoming_ring);
            rte_ring_free(process_lcore->incoming_ring);
        }
        memset(process_lcore, 0, size);
        DEBUG("free process_lcore=%p", process_lcore);
        rte_free(process_lcore);
    }
    return NULL;
}

static void
destroy_process_lcore(struct gps_i_forwarder_process_lcore *process_lcore,
        uint16_t outgoing_ring_count) {
    uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct rte_ring *);
    uint32_t size = sizeof (struct gps_i_forwarder_process_lcore) +outgoing_ring_size;

    DEBUG("free process_lcore=%p, incoming_ring=%p",
            process_lcore, process_lcore->incoming_ring);
    rte_ring_free(process_lcore->incoming_ring);
    memset(process_lcore, 0, size);
    rte_free(process_lcore);
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
                DEBUG("Got packet from output ring %" PRIu16 ", data size=%" PRIu16, i, rte_pktmbuf_data_len(pkts[j]));
                rte_pktmbuf_free(pkts[j]);
            }
        }
    }
    DEBUG("Receive end");
    return 0;
}

static int
test_forwarder_logic_control(void *param) {
    struct gps_i_forwarder_control_lcore *controllcore = param;
    struct rte_mbuf * pkts[TEST_BURST_SIZE];
    unsigned burst_size, j;


    DEBUG("Control start, param=%p", param);
    while (running) {
        burst_size = rte_ring_dequeue_burst(controllcore->incoming_ring, (void **) pkts, TEST_BURST_SIZE, NULL);
        for (j = 0; j < burst_size; j++) {
            DEBUG("Got packet from incoming ring, data size=%" PRIu16, rte_pktmbuf_data_len(pkts[j]));
            rte_pktmbuf_free(pkts[j]);
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

    DEBUG("Process start, param=%p", param);
    while (running) {
        burst_size = rte_ring_dequeue_burst(process_lcore->incoming_ring, (void **) pkts, TEST_BURST_SIZE, NULL);
        for (j = 0; j < burst_size; j++) {
            DEBUG("Got packet from incoming ring, data size=%" PRIu16, rte_pktmbuf_data_len(pkts[j]));
            gps_i_forwarder_decapsulate(process_lcore, pkts[j]);
            printf("\n");
        }
        urcu_qsbr_quiescent_state();
    }
    DEBUG("Process end");
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
    struct gps_i_neighbor_info encap = {
        .port = 0,
        .use_ip = true,
        .ip = IPv4(192, 168, 123, 231)
    };
    unsigned lcore = -1;
    unsigned socket_id;

    if (rte_lcore_count() < 4) {
        FAIL("Need at least 4 cores!");
    }


    gps_na_set(&na, 0x101);
    // set encap
    cmdline_parse_etheraddr(NULL, "ec:0d:9a:7e:90:c6", &encap.ether, sizeof (encap.ether));



    socket_id = rte_socket_id();
    forwarder_c = gps_i_forwarder_control_plane_create(name, socket_id, &na, &encap);
    if (forwarder_c == NULL) FAIL("Cannot create forwarder_c");
    DEBUG("forwarder_c=%p", forwarder_c);
    forwarder_d = gps_i_forwarder_control_plane_to_data_plane(forwarder_c);
    DEBUG("forwarder_d=%p", forwarder_d);

    outgoing_rings = prepare_outgoing_rings(name, TEST_OUTGOING_RING_SIZE, socket_id);
    if (unlikely(outgoing_rings == NULL)) FAIL("Cannot create rings");

    control_lcore = prepare_control_lcore(name, forwarder_c,
            outgoing_rings, TEST_OUTGOING_RING_SIZE, socket_id);
    if (unlikely(control_lcore == NULL)) FAIL("Cannot create control_lcore");

    process_lcore = prepare_process_lcore(name, forwarder_d,
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

    generator(forwarder_c->pkt_pool, process_lcore->incoming_ring);
    //
    rte_delay_ms(100);
    running = false;

    RTE_LCORE_FOREACH_SLAVE(lcore) {
        rte_eal_wait_lcore(lcore);
    }
    DEBUG("Finish");

    printf("\n");
    destroy_process_lcore(process_lcore, TEST_OUTGOING_RING_SIZE);
    destroy_control_lcore(control_lcore, TEST_OUTGOING_RING_SIZE);
    destroy_outgoing_rings(outgoing_rings, TEST_OUTGOING_RING_SIZE);
    gps_i_forwarder_control_plane_destroy(forwarder_c);

}

static void generator_decapsulation(struct rte_mempool *pkt_pool, struct rte_ring *processor_ring) {
    struct rte_mbuf *pkt;
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;

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

void
test_forwarder_logic(void) {
    dump_mem("dmp_test_forwarder_logic_0.txt");
    test_logic_master("decap", generator_decapsulation);
    dump_mem("dmp_test_forwarder_logic_1.txt");
}