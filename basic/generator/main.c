#include <stdbool.h>
#include <getopt.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include "helper.h"

#define PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define NB_PKT_MBUF 8192
#define MAX_PKT_BURST 64
#define DEFAULT_ETH_TYPE 0x27c1
#define DEFAULT_PKT_SIZE 125
#define DEFAULT_PKT_COUNT 64


static struct rte_mempool *packet_pool;
static struct ether_addr dst_addr;
static uint16_t ether_type, pkt_size = DEFAULT_PKT_SIZE;
static uint64_t pkt_count = DEFAULT_PKT_COUNT;
static bool use_ref = false;

static void print_usage(char *prgname) {
    printf("usage: %s %s -- -d %s [-t %s -s %s -c %s]\n", prgname,
            "%dpdk_params%", "%dst_mac_as_hex%", "%ether_type%", "%pkt_size%", "%pkt_count%");
    printf("  pkt_size should be from %zd to %d\n", sizeof (struct ether_hdr), RTE_MBUF_DEFAULT_DATAROOM);
}

static int parse_args(int argc, char **argv) {
    int opt;
    char **argvopt = argv;

    union {
        uint64_t as_long;
        struct ether_addr as_addr;
    } tmp_dst_mac;
    char *end;

    tmp_dst_mac.as_long = 0;
    ether_type = rte_cpu_to_be_16(DEFAULT_ETH_TYPE);


    while ((opt = getopt(argc, argvopt, "d:t:s:c:r")) != EOF) {
        switch (opt) {
            case 'd':
                end = NULL;
                tmp_dst_mac.as_long = rte_cpu_to_be_64(strtoull(optarg, &end, 16)) >> 16;
                if (optarg[0] == '\0' || (end == NULL) || (*end != '\0')) {
                    print_usage(argv[0]);
                    return -1;
                }
                dst_addr = tmp_dst_mac.as_addr;
                break;
            case 't':
                end = NULL;
                ether_type = rte_cpu_to_be_16(strtoul(optarg, &end, 0));
                if (optarg[0] == '\0' || (end == NULL) || (*end != '\0')) {
                    print_usage(argv[0]);
                    return -1;
                }
                break;
            case 's':
                end = NULL;
                pkt_size = strtoul(optarg, &end, 0);
                if (optarg[0] == '\0' || (end == NULL) || (*end != '\0')) {
                    print_usage(argv[0]);
                    return -1;
                }
                break;
            case 'c':
                end = NULL;
                pkt_count = strtoul(optarg, &end, 0);
                if (optarg[0] == '\0' || (end == NULL) || (*end != '\0')) {
                    print_usage(argv[0]);
                    return -1;
                }
                break;
            case 'r':
                use_ref = true;
                break;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    if (!tmp_dst_mac.as_long) {
        print_usage(argv[0]);
        return -1;
    }
    print_ethaddr("DST_ADDR=", &dst_addr);
    printf(", ether_type=0x%04" PRIx16 ", pkt_size=%" PRIu16
            ", pkt_count=%" PRIu64 ", use_ref=%s\n",
            rte_be_to_cpu_16(ether_type), pkt_size, pkt_count, use_ref ? "True" : "False");

    return 0;
}

static void fill_hdr(uint64_t port, struct ether_hdr *hdr) {
    rte_eth_macaddr_get(port, &hdr->s_addr);
    printf("lcore=%u, port=%" PRIu16, rte_lcore_id(), 0);
    print_ethaddr(", mac=", &hdr->s_addr);
    printf("\n");
    printf("rte_socket_id=%u\n", rte_socket_id());

    hdr->d_addr = dst_addr;
    hdr->ether_type = ether_type;
}

static int main_loop_single(__rte_unused void *dummy) {
    struct rte_mbuf * pkts_burst[MAX_PKT_BURST], *pkt;
    struct ether_hdr *hdr;

    uint64_t total = 0, dropped = 0, start, end;
    uint16_t i, sent;

    hdr = (struct ether_hdr *) rte_malloc("ether_hdr", sizeof (struct ether_hdr), 0);
    if (unlikely(!hdr)) rte_exit(EXIT_FAILURE, "Cannot allocate hdr.\n");

    fill_hdr(0, hdr);

    rte_delay_ms(2000);

    start = rte_get_timer_cycles();
    sent = MAX_PKT_BURST;

    while (likely(total < pkt_count)) {
        for (i = 0; i < sent; i++) {
            pkt = rte_pktmbuf_alloc(packet_pool);
            if (unlikely(!pkt)) rte_exit(EXIT_FAILURE, "Cannot allocate packet buffer, total=%" PRIu64 ".\n", total);
            pkts_burst[i] = pkt;

            char *data = rte_pktmbuf_append(pkt, pkt_size);
            struct ether_hdr *pkt_hdr = (struct ether_hdr *) data;
            rte_memcpy(pkt_hdr, hdr, sizeof (struct ether_hdr));
        }

        sent = rte_eth_tx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
        total += sent;
        if (unlikely(sent < MAX_PKT_BURST)) {
            dropped += MAX_PKT_BURST - sent;
        }

    }

    end = rte_get_timer_cycles();

    printf("sent\tduration\thz\tdropped\n%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n",
            total, end - start, rte_get_timer_hz(), dropped);

    return 0;
}

static int main_loop_single_ref(__rte_unused void *dummy) {
    struct rte_mbuf * pkts_burst[MAX_PKT_BURST], *pkt;
    struct ether_hdr *hdr;

    int ret, i;
    uint64_t total = 0, dropped = 0, start, end;

    hdr = (struct ether_hdr *) rte_malloc("ether_hdr", sizeof (struct ether_hdr), 0);
    if (unlikely(!hdr)) rte_exit(EXIT_FAILURE, "Cannot allocate hdr.\n");

    fill_hdr(0, hdr);

    rte_delay_ms(1000);

    start = rte_get_timer_cycles();

    while (likely(total < pkt_count)) {
        pkt = rte_pktmbuf_alloc(packet_pool);
        if (unlikely(!pkt)) rte_exit(EXIT_FAILURE, "Cannot allocate packet buffer, total=%" PRIu64 ", dropped=%" PRIu64 ".\n", total, dropped);
        char *data = rte_pktmbuf_append(pkt, pkt_size);
        struct ether_hdr *pkt_hdr = (struct ether_hdr *) data;
        rte_memcpy(pkt_hdr, hdr, sizeof (struct ether_hdr));
        //        rte_mbuf_refcnt_set(pkt, MAX_PKT_BURST);

        for (i = 0; i < MAX_PKT_BURST; i++) {
            pkts_burst[i] = pkt;
        }

        ret = rte_eth_tx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
        total += ret;
        if (unlikely(ret < MAX_PKT_BURST)) {
            dropped += MAX_PKT_BURST - ret;
            //            rte_mbuf_refcnt_update(pkt, -ret);
            rte_pktmbuf_free(pkt);
        }

    }

    end = rte_get_timer_cycles();

    printf("sent\tduration\thz\tdropped\n%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n",
            total, end - start, rte_get_timer_hz(), dropped);

    return 0;
}

static volatile bool stop = false;

static int main_loop_waste(__rte_unused void *dummy) {
    printf("lcore=%u, waste, rte_socket_id=%u\n", rte_lcore_id(), rte_socket_id());
    while (!stop) {
        rte_delay_ms(1000);
    }
    return 0;
}

int main(int argc, char **argv) {
    int ret;
    uint16_t nb_ports;
    unsigned lcore;
    //    uint64_t portid;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    ret = parse_args(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid generator parameters\n");

    printf("rte_socket_id=%u\n", rte_socket_id());
    /* create the mbuf pools */
    packet_pool = rte_pktmbuf_pool_create("packet_pool", NB_PKT_MBUF, 32, 0, PKT_MBUF_DATA_SIZE, rte_socket_id());

    if (!unlikely(packet_pool)) rte_exit(EXIT_FAILURE, "Cannot init packet mbuf pool\n");

    nb_ports = rte_eth_dev_count_avail();
    printf("nb_ports=%" PRIu16 "\n", nb_ports);
    //    if (!unlikely(nb_ports)) rte_exit(EXIT_FAILURE, "No physical ports!\n");
    if (unlikely(nb_ports != 1)) rte_exit(EXIT_FAILURE, "Only supports 1 port, use -w to specify the interface you need.\n");

    //    RTE_ETH_FOREACH_DEV(portid) {
    //        enable_port(portid, 1, packet_pool);
    //    }
    enable_port(0, 1, packet_pool);

    check_all_ports_link_status();

    lcore = -1;
    for (;;) {
        lcore = rte_get_next_lcore(lcore, 1, 0);
        if (lcore == RTE_MAX_LCORE) break;
        rte_eal_remote_launch(main_loop_waste, NULL, lcore);
    }

    if (use_ref) {
        main_loop_single_ref(NULL);
    } else {
        main_loop_single(NULL);
    }
    stop = true;

    RTE_LCORE_FOREACH_SLAVE(lcore) {
        if (rte_eal_wait_lcore(lcore) < 0)
            return -1;
    }



    return 0;
}