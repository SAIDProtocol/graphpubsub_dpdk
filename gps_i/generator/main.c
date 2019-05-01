/* 
 * File:   main.c
 * Author: Jiachen Chen
 */

#include <cmdline_parse_etheraddr.h>
#include <gps_headers.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "link_helper.h"

#define RTE_LOGTYPE_MAIN RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) \
    RTE_LOG(INFO, MAIN, "[%s():%d] " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, __VA_ARGS__)
#define FAIL(...) _FAIL(__VA_ARGS__, "dummy")
#define _FAIL(fmt, ...) \
    rte_exit(EXIT_FAILURE, "[%s():%d] " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_HEAD() \
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__)


#define PKT_MBUF_SIZE 8192
#define PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define MAX_PKT_BURST 64
#define PKT_SIZE 64
#define NUM_PKT_TO_SEND 500000000

static void
print_buf(const void *buf, uint32_t size, uint32_t wrap) {
    uint32_t i, j;
    for (i = 0; i < size;) {
        printf("  %04X:", i);
        for (j = 0; i < size && j < wrap; i++, j++) {
            printf(" %02X", ((const uint8_t *) buf)[i]);
        }
        printf("\n");
    }
}

struct candidate_buf {
    uint32_t size;
    struct rte_mbuf *pkts[];
};

static struct candidate_buf *
generate_packets(const struct ether_addr *src, const struct ether_addr *dst,
        struct rte_mempool *pkt_pool) {
    int ret;
    int to_create = 1;
    struct candidate_buf *candidates = rte_malloc_socket("candidates",
            sizeof (struct candidate_buf) +to_create * sizeof (struct rte_mbuf *),
            0,
            pkt_pool->socket_id);
    if (candidates == NULL)
        FAIL("Cannot candidate_buf ret, reason: %s", rte_strerror(rte_errno));

    candidates->size = to_create;

    struct ether_hdr *eth_hdr;
    struct gps_pkt_publication *pub_hdr;
    struct gps_guid src_guid, dst_guid;
    struct gps_na src_na, dst_na;
    uint32_t payload_size;

    ret = rte_pktmbuf_alloc_bulk(pkt_pool, candidates->pkts, candidates->size);
    if (ret != 0) FAIL("Alloc bulk failed, ret=%d", ret);

    eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(candidates->pkts[0], sizeof (struct ether_hdr));
    ether_addr_copy(src, &eth_hdr->s_addr);
    ether_addr_copy(dst, &eth_hdr->d_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(GPS_PROTO_TYPE_ETHER);

    pub_hdr = (struct gps_pkt_publication *) rte_pktmbuf_append(candidates->pkts[0], sizeof (struct gps_pkt_publication));
    payload_size = PKT_SIZE - rte_pktmbuf_data_len(candidates->pkts[0]);

    gps_pkt_publication_init(pub_hdr,
            gps_guid_set(&src_guid, 0x89abcdef),
            gps_guid_set(&dst_guid, 0xdeadbeef),
            gps_na_set(&src_na, 0),
            gps_na_set(&dst_na, 0x134567),
            payload_size);

    rte_pktmbuf_append(candidates->pkts[0], payload_size);

    print_buf(rte_pktmbuf_mtod(candidates->pkts[0], void *), rte_pktmbuf_data_len(candidates->pkts[0]), 16);
    return candidates;
}

struct generator_param {
    struct candidate_buf *candidates;
    struct rte_mempool *clone_pool;
};

static int
main_loop_generator(void *param) {
    struct generator_param *p = (struct generator_param *) param;

    struct rte_mbuf * pkts_burst[MAX_PKT_BURST], *pkt;
    uint64_t total = 0, dropped = 0, start, end;
    uint16_t i, remain;

    rte_delay_ms(2000);
    start = rte_get_timer_cycles();
    remain = 0;

    while (likely(total < NUM_PKT_TO_SEND)) {
        for (i = remain; i < MAX_PKT_BURST; i++) {
            pkt = rte_pktmbuf_alloc(p->clone_pool);
            if (unlikely(pkt == NULL))
                FAIL("Cannot allocate packet buffer, total=%" PRIu64 ".\n", total);
            pkts_burst[i] = pkt;

            //            rte_memcpy(rte_pktmbuf_append(pkt, PKT_SIZE),
            //                    rte_pktmbuf_mtod(p->candidates->pkts[lrand48() % p->candidates->size], void *), PKT_SIZE);
            rte_memcpy(rte_pktmbuf_append(pkt, PKT_SIZE),
                    rte_pktmbuf_mtod(p->candidates->pkts[0], void *), PKT_SIZE);

            *rte_pktmbuf_mtod_offset(pkt, uint8_t *, PKT_SIZE - sizeof (uint64_t) - 1) = 1;
            *rte_pktmbuf_mtod_offset(pkt, uint64_t *, PKT_SIZE - sizeof (uint64_t)) =
                    rte_cpu_to_be_64(total + i - remain);
        }
        i = rte_eth_tx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
        total += i;
        remain = MAX_PKT_BURST - i;
        if (unlikely(remain > 0)) {
            dropped += remain;
            for (i = 0; i < remain; i++) {
                pkts_burst[i] = pkts_burst[MAX_PKT_BURST - remain];
            }
        }


    }
    end = rte_get_timer_cycles();
    DEBUG("%" PRIu64 "\t%"PRIu64 "\t%"PRIu64 "\t%"PRIu64 "\t%"PRIu64, total, start, end, rte_get_timer_hz(), dropped);

    DEBUG("clone_pool=%p, candidates=%p", p->clone_pool, p->candidates);
}

int main(int argc, char **argv) {
    int ret;
    struct rte_mempool *pkt_pool;
    struct ether_addr src, dst;
    struct generator_param param;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) FAIL("Invalid EAL parameters.");
    argc -= ret;
    argv += ret;


    cmdline_parse_etheraddr(NULL, "ec:0d:9a:7e:91:96", &dst, sizeof (dst));
    cmdline_parse_etheraddr(NULL, "ec:0d:9a:7e:90:c6", &src, sizeof (src));

    pkt_pool = rte_pktmbuf_pool_create("pkt_pool", PKT_MBUF_SIZE, 32, 0, PKT_MBUF_DATA_SIZE, rte_socket_id());
    param.candidates = generate_packets(&src, &dst, pkt_pool);
    param.clone_pool = rte_pktmbuf_pool_create("clone_pool", PKT_MBUF_SIZE, 32, 0, PKT_MBUF_DATA_SIZE, rte_socket_id());

    enable_port(0, 1, pkt_pool);
    check_all_ports_link_status();

    main_loop_generator(&param);

    rte_eth_dev_stop(0);
    rte_eth_dev_close(0);

    return 0;
}
