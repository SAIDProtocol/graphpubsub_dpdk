/* 
 * File:   main.c
 * Author: Jiachen Chen
 */

#include <cmdline_parse_etheraddr.h>
#include <gps_headers.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <stdio.h>
#include <stdlib.h>

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


#define PKT_MBUF_SIZE 81920
#define PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define MAX_PKT_BURST 64
#define PKT_SIZE 64
#define USE_BUILT_IN_RANDOM

#ifdef USE_BUILT_IN_RANDOM
#define NUM_PKT_TO_SEND 50000000
#else
#define NUM_PKT_TO_SEND 100000000
#endif

struct candidate_buf *
generate_packets_single(const struct ether_addr *src, const struct ether_addr *dst,
        struct rte_mempool *pkt_pool);
struct candidate_buf *
generate_packets_routing(const struct ether_addr *src, const struct ether_addr *dst,
        struct rte_mempool *pkt_pool);
struct candidate_buf *
generate_packets_gnrs(const struct ether_addr *src, const struct ether_addr *dst,
        struct rte_mempool *pkt_pool);
struct candidate_buf *
generate_packets_st(const struct ether_addr *src, const struct ether_addr *dst,
        struct rte_mempool *pkt_pool);

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

struct candidate_buf *
generate_packets_single(const struct ether_addr *src, const struct ether_addr *dst,
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
            gps_na_set(&dst_na, 0x3FC95060),
            payload_size);

    rte_pktmbuf_append(candidates->pkts[0], payload_size);

    print_buf(rte_pktmbuf_mtod(candidates->pkts[0], void *), rte_pktmbuf_data_len(candidates->pkts[0]), 16);
    return candidates;
}

struct na_list {
    struct gps_na na;
    struct na_list *next;
};

struct candidate_buf *
generate_packets_routing(const struct ether_addr *src, const struct ether_addr *dst,
        struct rte_mempool *pkt_pool) {
    const char *routing_file = "../test_read_routing_table.txt";
    const char *delim = "\t ";
    struct na_list *head, *tail, *tmp;
    char *line = NULL, *token, *end;
    unsigned line_id = 0;
    long int value;
    size_t len;
    ssize_t read;
    uint32_t count = 0;
    char dst_na_buf[GPS_NA_FMT_SIZE];
    int ret;
#ifndef USE_BUILT_IN_RANDOM
    uint32_t rnd;
    struct rte_mbuf *pkt;
#endif

    head = rte_zmalloc_socket(NULL, sizeof (struct na_list), 0, pkt_pool->socket_id);
    if (head == NULL) FAIL("Cannot malloc head");
    tail = head;

    FILE *f = fopen(routing_file, "r");
    if (f == NULL) FAIL("Cannot open file %s.", routing_file);

    while ((read = getline(&line, &len, f)) != -1) {
        line_id++;
        if (line[read - 1] == '\n') line[--read] = '\0';
        if (line[read - 1] == '\r') line[--read] = '\0';
        DEBUG("getline %u read=%zu, len=%zu", line_id, read, len);
        DEBUG("line=\"%s\"", line);

        token = strtok(line, delim);

        if (token == NULL) {
            DEBUG("Cannot read line %u, cannot find dst_na, skip.", line_id);
            continue;
        }
        value = strtol(token, &end, 0);
        if (*end != '\0') {
            DEBUG("Cannot read line %u, dst_na not pure number, skip.", line_id);
            continue;
        }

        tmp = rte_zmalloc_socket(NULL, sizeof (struct na_list), 0, pkt_pool->socket_id);
        if (tmp == NULL) FAIL("Cannot malloc tmp");
        tail->next = tmp;
        tail = tmp;

        gps_na_set(&tmp->na, (uint32_t) value);
        DEBUG("DST_NA=%s", gps_na_format(dst_na_buf, sizeof (dst_na_buf), &tmp->na));
        count++;
    }
    free(line);
    fclose(f);

    DEBUG("Count=%" PRIu32, count);


    struct candidate_buf *candidates = rte_malloc_socket("candidates",
            sizeof (struct candidate_buf) +count * sizeof (struct rte_mbuf *),
            0,
            pkt_pool->socket_id);
    if (candidates == NULL)
        FAIL("Cannot candidate_buf ret, reason: %s", rte_strerror(rte_errno));
    candidates->size = count;

    struct ether_hdr *eth_hdr;
    struct gps_pkt_publication *pub_hdr;
    struct gps_guid src_guid, dst_guid;
    struct gps_na src_na;
    uint32_t payload_size;

    ret = rte_pktmbuf_alloc_bulk(pkt_pool, candidates->pkts, candidates->size);
    if (ret != 0) FAIL("Alloc bulk failed, ret=%d", ret);

    count = 0;
    for (tmp = head->next; tmp != NULL; tmp = tmp->next) {
        eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(candidates->pkts[count], sizeof (struct ether_hdr));
        ether_addr_copy(src, &eth_hdr->s_addr);
        ether_addr_copy(dst, &eth_hdr->d_addr);
        eth_hdr->ether_type = rte_cpu_to_be_16(GPS_PROTO_TYPE_ETHER);

        pub_hdr = (struct gps_pkt_publication *) rte_pktmbuf_append(candidates->pkts[count], sizeof (struct gps_pkt_publication));
        payload_size = PKT_SIZE - rte_pktmbuf_data_len(candidates->pkts[count]);

        gps_pkt_publication_init(pub_hdr,
                gps_guid_set(&src_guid, 0x89abcdef),
                gps_guid_set(&dst_guid, 0xdeadbeef),
                gps_na_set(&src_na, 0),
                &tmp->na,
                payload_size);
        rte_pktmbuf_append(candidates->pkts[count], payload_size);
        //        print_buf(rte_pktmbuf_mtod(candidates->pkts[count], void *), rte_pktmbuf_data_len(candidates->pkts[count]), 16);
        count++;
    }
    DEBUG("Count=%" PRIu32, count);

#ifndef USE_BUILT_IN_RANDOM
    for (count = 0; count < candidates->size; count++) {
        rnd = ((uint32_t) lrand48()) % candidates->size;
        pkt = candidates->pkts[rnd];
        candidates->pkts[rnd] = candidates->pkts[count];
        candidates->pkts[count] = pkt;
    }
#endif

    count = 0;
    tmp = head-> next;
    for (;;) {
        rte_free(head);
        count++;
        head = tmp;
        if (head == NULL) break;
        tmp = tmp->next;
    }
    DEBUG("Count=%" PRIu32, count);

    return candidates;
}

struct guid_list {
    struct gps_guid guid;
    struct guid_list *next;
};

struct candidate_buf *
generate_packets_gnrs(const struct ether_addr *src, const struct ether_addr *dst,
        struct rte_mempool *pkt_pool) {
    const char *cache_file_name = "../test_read_gnrs_cache.txt";
    const char *delim = "\t ";
    struct guid_list *head, *tail, *tmp;
    char *line = NULL, *token, *end;
    unsigned line_id = 0;
    long int value;
    size_t len;
    ssize_t read;
    uint32_t count = 0;
    uint32_t prefix = rte_cpu_to_be_32(0xdeadbeef);

    char dst_guid_buf[GPS_GUID_FMT_SIZE];
    int ret;
#ifndef USE_BUILT_IN_RANDOM
    uint32_t rnd;
    struct rte_mbuf *pkt;
#endif

    head = rte_zmalloc_socket(NULL, sizeof (struct guid_list), 0, pkt_pool->socket_id);
    if (head == NULL) FAIL("Cannot malloc head");
    tail = head;

    FILE *f = fopen(cache_file_name, "r");
    if (f == NULL) FAIL("Cannot open file %s.", cache_file_name);

    while ((read = getline(&line, &len, f)) != -1) {
        line_id++;
        if (line[read - 1] == '\n') line[--read] = '\0';
        if (line[read - 1] == '\r') line[--read] = '\0';
        DEBUG("getline %u read=%zu, len=%zu", line_id, read, len);
        DEBUG("line=\"%s\"", line);

        token = strtok(line, delim);

        if (token == NULL) {
            DEBUG("Cannot read line %u, cannot find dst_guid, skip.", line_id);
            continue;
        }
        value = strtol(token, &end, 0);
        if (*end != '\0') {
            DEBUG("Cannot read line %u, dst_guid not pure number, skip.", line_id);
            continue;
        }

        tmp = rte_zmalloc_socket(NULL, sizeof (struct guid_list), 0, pkt_pool->socket_id);
        if (tmp == NULL) FAIL("Cannot malloc tmp");
        tail->next = tmp;
        tail = tmp;

        gps_guid_set(&tmp->guid, (uint32_t) value);
        memcpy(&tmp->guid, &prefix, sizeof (uint32_t));

        DEBUG("DST_GUID=%s", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &tmp->guid));
        count++;
    }
    free(line);
    fclose(f);

    DEBUG("Count=%" PRIu32, count);


    struct candidate_buf *candidates = rte_malloc_socket("candidates",
            sizeof (struct candidate_buf) +count * sizeof (struct rte_mbuf *),
            0,
            pkt_pool->socket_id);
    if (candidates == NULL)
        FAIL("Cannot candidate_buf ret, reason: %s", rte_strerror(rte_errno));
    candidates->size = count;

    struct ether_hdr *eth_hdr;
    struct gps_pkt_publication *pub_hdr;
    struct gps_guid src_guid;
    struct gps_na src_na, dst_na;
    uint32_t payload_size;

    ret = rte_pktmbuf_alloc_bulk(pkt_pool, candidates->pkts, candidates->size);
    if (ret != 0) FAIL("Alloc bulk failed, ret=%d", ret);

    count = 0;
    for (tmp = head->next; tmp != NULL; tmp = tmp->next) {
        eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(candidates->pkts[count], sizeof (struct ether_hdr));
        ether_addr_copy(src, &eth_hdr->s_addr);
        ether_addr_copy(dst, &eth_hdr->d_addr);
        eth_hdr->ether_type = rte_cpu_to_be_16(GPS_PROTO_TYPE_ETHER);

        pub_hdr = (struct gps_pkt_publication *) rte_pktmbuf_append(candidates->pkts[count], sizeof (struct gps_pkt_publication));
        payload_size = PKT_SIZE - rte_pktmbuf_data_len(candidates->pkts[count]);

        gps_pkt_publication_init(pub_hdr,
                gps_guid_set(&src_guid, 0x89abcdef),
                &tmp->guid,
                gps_na_set(&src_na, 0),
                gps_na_set(&dst_na, 0),
                payload_size);
        rte_pktmbuf_append(candidates->pkts[count], payload_size);
        //        print_buf(rte_pktmbuf_mtod(candidates->pkts[count], void *), rte_pktmbuf_data_len(candidates->pkts[count]), 16);
        count++;
    }
    DEBUG("Count=%" PRIu32, count);

#ifndef USE_BUILT_IN_RANDOM
    for (count = 0; count < candidates->size; count++) {
        rnd = ((uint32_t) lrand48()) % candidates->size;
        pkt = candidates->pkts[rnd];
        candidates->pkts[rnd] = candidates->pkts[count];
        candidates->pkts[count] = pkt;
    }
#endif

    count = 0;
    tmp = head-> next;
    for (;;) {
        rte_free(head);
        count++;
        head = tmp;
        if (head == NULL) break;
        tmp = tmp->next;
    }
    DEBUG("Count=%" PRIu32, count);

    return candidates;
}

struct candidate_buf *
generate_packets_st(const struct ether_addr *src, const struct ether_addr *dst,
        struct rte_mempool *pkt_pool) {
    const char *cache_file_name = "../test_read_subscription_table_1.txt";
    const char *delim = "\t ";
    struct guid_list *head, *tail, *tmp;
    char *line = NULL, *token, *end;
    unsigned line_id = 0;
    long int value;
    size_t len;
    ssize_t read;
    uint32_t count = 0;
    uint32_t prefix = rte_cpu_to_be_32(0xbeefdead);

    char dst_guid_buf[GPS_GUID_FMT_SIZE];
    int ret;
#ifndef USE_BUILT_IN_RANDOM
    uint32_t rnd;
    struct rte_mbuf *pkt;
#endif

    head = rte_zmalloc_socket(NULL, sizeof (struct guid_list), 0, pkt_pool->socket_id);
    if (head == NULL) FAIL("Cannot malloc head");
    tail = head;

    FILE *f = fopen(cache_file_name, "r");
    if (f == NULL) FAIL("Cannot open file %s.", cache_file_name);

    while ((read = getline(&line, &len, f)) != -1) {
        line_id++;
        if (line[read - 1] == '\n') line[--read] = '\0';
        if (line[read - 1] == '\r') line[--read] = '\0';
        DEBUG("getline %u read=%zu, len=%zu", line_id, read, len);
        DEBUG("line=\"%s\"", line);

        token = strtok(line, delim);

        if (token == NULL) {
            DEBUG("Cannot read line %u, cannot find dst_guid, skip.", line_id);
            continue;
        }
        value = strtol(token, &end, 0);
        if (*end != '\0') {
            DEBUG("Cannot read line %u, dst_guid not pure number, skip.", line_id);
            continue;
        }

        tmp = rte_zmalloc_socket(NULL, sizeof (struct guid_list), 0, pkt_pool->socket_id);
        if (tmp == NULL) FAIL("Cannot malloc tmp");
        tail->next = tmp;
        tail = tmp;

        gps_guid_set(&tmp->guid, (uint32_t) value);
        rte_memcpy(&tmp->guid, &prefix, sizeof (uint32_t));

        DEBUG("DST_GUID=%s", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &tmp->guid));
        count++;
    }
    free(line);
    fclose(f);

    DEBUG("Count=%" PRIu32, count);


    struct candidate_buf *candidates = rte_malloc_socket("candidates",
            sizeof (struct candidate_buf) +count * sizeof (struct rte_mbuf *),
            0,
            pkt_pool->socket_id);
    if (candidates == NULL)
        FAIL("Cannot candidate_buf ret, reason: %s", rte_strerror(rte_errno));
    candidates->size = count;

    struct ether_hdr *eth_hdr;
    struct gps_pkt_publication *pub_hdr;
    struct gps_guid src_guid;
    struct gps_na src_na, dst_na;
    uint32_t payload_size;

    ret = rte_pktmbuf_alloc_bulk(pkt_pool, candidates->pkts, candidates->size);
    if (ret != 0) FAIL("Alloc bulk failed, ret=%d", ret);

    count = 0;
    for (tmp = head->next; tmp != NULL; tmp = tmp->next) {
        eth_hdr = (struct ether_hdr*) rte_pktmbuf_append(candidates->pkts[count], sizeof (struct ether_hdr));
        ether_addr_copy(src, &eth_hdr->s_addr);
        ether_addr_copy(dst, &eth_hdr->d_addr);
        eth_hdr->ether_type = rte_cpu_to_be_16(GPS_PROTO_TYPE_ETHER);

        pub_hdr = (struct gps_pkt_publication *) rte_pktmbuf_append(candidates->pkts[count], sizeof (struct gps_pkt_publication));
        payload_size = PKT_SIZE - rte_pktmbuf_data_len(candidates->pkts[count]);

        gps_pkt_publication_init(pub_hdr,
                gps_guid_set(&src_guid, 0x89abcdef),
                &tmp->guid,
                gps_na_set(&src_na, 0x1234),
                gps_na_set(&dst_na, 0x1234),
                payload_size);
        rte_pktmbuf_append(candidates->pkts[count], payload_size);
        //        print_buf(rte_pktmbuf_mtod(candidates->pkts[count], void *), rte_pktmbuf_data_len(candidates->pkts[count]), 16);
        count++;
    }
    DEBUG("Count=%" PRIu32, count);

#ifndef USE_BUILT_IN_RANDOM
    for (count = 0; count < candidates->size; count++) {
        rnd = ((uint32_t) lrand48()) % candidates->size;
        pkt = candidates->pkts[rnd];
        candidates->pkts[rnd] = candidates->pkts[count];
        candidates->pkts[count] = pkt;
    }
#endif

    count = 0;
    tmp = head-> next;
    for (;;) {
        rte_free(head);
        count++;
        head = tmp;
        if (head == NULL) break;
        tmp = tmp->next;
    }
    DEBUG("Count=%" PRIu32, count);

    return candidates;
}

struct generator_param {
    struct candidate_buf *candidates;
    struct rte_mempool *packet_pool;
    uint16_t queue_id;
};

volatile bool running = false;

static int
main_loop_generator_slave(void *param) {
    struct generator_param *p = (struct generator_param *) param;
    DEBUG("lcore=%u, queue=%" PRIu16, rte_lcore_id(), p->queue_id);

    struct rte_mbuf * pkts_burst[MAX_PKT_BURST], *pkt;
    uint64_t total = 0, dropped = 0, start, end;
    uint16_t i, remain;
#ifndef USE_BUILT_IN_RANDOM
    uint32_t pos = lrand48() % p->candidates->size;
    int32_t skip = mrand48() % 10;
#endif

    while (!unlikely(running));
    start = rte_get_timer_cycles();
    remain = 0;

    while (likely(running)) {
        for (i = remain; i < MAX_PKT_BURST; i++) {
            pkt = rte_pktmbuf_alloc(p->packet_pool);
            if (unlikely(pkt == NULL))
                FAIL("Cannot allocate packet buffer, total=%" PRIu64 ".\n", total);
            pkts_burst[i] = pkt;

#ifdef USE_BUILT_IN_RANDOM
            rte_memcpy(rte_pktmbuf_append(pkt, PKT_SIZE),
                    rte_pktmbuf_mtod(p->candidates->pkts[lrand48() % p->candidates->size], void *), PKT_SIZE);
#else
            rte_memcpy(rte_pktmbuf_append(pkt, PKT_SIZE),
                    rte_pktmbuf_mtod(p->candidates->pkts[pos], void *), PKT_SIZE);
            pos = pos + skip + p->candidates-> size;
            pos %= p->candidates->size;
#endif

            *rte_pktmbuf_mtod_offset(pkt, uint8_t *, PKT_SIZE - sizeof (uint64_t) - 1) = (uint8_t) p->queue_id;
            *rte_pktmbuf_mtod_offset(pkt, uint64_t *, PKT_SIZE - sizeof (uint64_t)) =
                    rte_cpu_to_be_64(total + i - remain);
        }
        i = rte_eth_tx_burst(0, p->queue_id, pkts_burst, MAX_PKT_BURST);
        total += i;
        remain = MAX_PKT_BURST - i;
        if (unlikely(remain > 0)) {
            dropped += remain;
            for (i = 0; i < remain; i++) {
                pkts_burst[i] = pkts_burst[MAX_PKT_BURST - remain + i];
            }
        }
    }
    end = rte_get_timer_cycles();
    DEBUG("%u\t%" PRIu64 "\t%"PRIu64 "\t%"PRIu64 "\t%"PRIu64 "\t%"PRIu64,
            rte_lcore_id(), total, start, end, rte_get_timer_hz(), dropped);
}

static int
main_loop_generator_mastr(void *param) {
    struct generator_param *p = (struct generator_param *) param;
    DEBUG("lcore=%u, queue=%" PRIu16, rte_lcore_id(), p->queue_id);

    struct rte_mbuf * pkts_burst[MAX_PKT_BURST], *pkt;
    uint64_t total = 0, dropped = 0, start, end;
    uint16_t i, remain;
#ifndef USE_BUILT_IN_RANDOM
    uint32_t pos = lrand48() % p->candidates->size;
    int32_t skip = mrand48() % 10;
#endif

    rte_delay_ms(2000);
    running = true;
    start = rte_get_timer_cycles();
    remain = 0;

    while (likely(total < NUM_PKT_TO_SEND)) {
        for (i = remain; i < MAX_PKT_BURST; i++) {
            pkt = rte_pktmbuf_alloc(p->packet_pool);
            if (unlikely(pkt == NULL))
                FAIL("Cannot allocate packet buffer, total=%" PRIu64 ".\n", total);
            pkts_burst[i] = pkt;

#ifdef USE_BUILT_IN_RANDOM
            rte_memcpy(rte_pktmbuf_append(pkt, PKT_SIZE),
                    rte_pktmbuf_mtod(p->candidates->pkts[lrand48() % p->candidates->size], void *), PKT_SIZE);
#else
            rte_memcpy(rte_pktmbuf_append(pkt, PKT_SIZE),
                    rte_pktmbuf_mtod(p->candidates->pkts[pos], void *), PKT_SIZE);
            pos = pos + skip + p->candidates-> size;
            pos %= p->candidates->size;
#endif

            *rte_pktmbuf_mtod_offset(pkt, uint8_t *, PKT_SIZE - sizeof (uint64_t) - 1) = (uint8_t) p->queue_id;
            *rte_pktmbuf_mtod_offset(pkt, uint64_t *, PKT_SIZE - sizeof (uint64_t)) =
                    rte_cpu_to_be_64(total + i - remain);
        }
        i = rte_eth_tx_burst(0, p->queue_id, pkts_burst, MAX_PKT_BURST);
        total += i;
        remain = MAX_PKT_BURST - i;
        if (unlikely(remain > 0)) {
            dropped += remain;
            for (i = 0; i < remain; i++) {
                pkts_burst[i] = pkts_burst[MAX_PKT_BURST - remain + i];
            }
        }
    }
    running = false;
    end = rte_get_timer_cycles();
    DEBUG("%u\t%" PRIu64 "\t%"PRIu64 "\t%"PRIu64 "\t%"PRIu64 "\t%"PRIu64,
            rte_lcore_id(), total, start, end, rte_get_timer_hz(), dropped);
}

int main(int argc, char **argv) {
    int ret;
    unsigned lcore;
    struct rte_mempool *pkt_pool;
    struct ether_addr src, dst;
    struct generator_param *params;
    struct candidate_buf *candidates;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) FAIL("Invalid EAL parameters.");
    argc -= ret;
    argv += ret;


    pkt_pool = rte_pktmbuf_pool_create("pkt_pool", PKT_MBUF_SIZE, 32, 0, PKT_MBUF_DATA_SIZE, rte_socket_id());
    if (pkt_pool == NULL)
        FAIL("Cannot create pkt_pool, reason: %s", rte_strerror(rte_errno));

    cmdline_parse_etheraddr(NULL, "ec:0d:9a:7e:91:96", &src, sizeof (src));
    cmdline_parse_etheraddr(NULL, "ec:0d:9a:7e:90:c6", &dst, sizeof (dst));
    //    candidates = generate_packets_routing(&src, &dst, pkt_pool);
    //    candidates = generate_packets_gnrs(&src, &dst, pkt_pool);
    //    candidates = generate_packets_single(&src, &dst, pkt_pool);
    candidates = generate_packets_st(&src, &dst, pkt_pool);


    lcore = rte_lcore_count();
    params = rte_zmalloc_socket("params", sizeof (struct generator_param) * lcore, 0, rte_socket_id());
    if (params == NULL)
        FAIL("Cannot create params, reason: %s", rte_strerror(rte_errno));

    enable_port(0, lcore, pkt_pool);
    check_all_ports_link_status();

    ret = 0;

    RTE_LCORE_FOREACH_SLAVE(lcore) {
        params[ret].candidates = candidates;
        params[ret].packet_pool = pkt_pool;
        params[ret].queue_id = ret;
        rte_eal_remote_launch(main_loop_generator_slave, &params[ret], lcore);
        ret++;
    }

    params[ret].candidates = candidates;
    params[ret].packet_pool = pkt_pool;
    params[ret].queue_id = ret;
    main_loop_generator_mastr(&params[ret]);

    RTE_LCORE_FOREACH_SLAVE(lcore) {
        rte_eal_wait_lcore(lcore);
    }

    rte_free(params);
    rte_mempool_free(pkt_pool);

    rte_eth_dev_stop(0);
    rte_eth_dev_close(0);

    return 0;
}

