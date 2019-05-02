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
#include <rte_prefetch.h>
#include <cmdline_parse_etheraddr.h>
#include "helper.h"

#define PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define NB_PKT_MBUF 8192
#define MAX_PKT_BURST 32
#define DEFAULT_ETH_TYPE 0x27c1
#define DEFAULT_PKT_SIZE 125
#define DEFAULT_PKT_COUNT 64
#define PREFETCH_OFFSET 3


static struct rte_mempool *packet_pool;
static struct ether_addr src_addr;
static uint16_t ether_type;
static volatile uint64_t count = 0, hit = 0, full = 0, n_full = 0;

static void print_usage(char *prgname) {
    printf("usage: %s %s -- -s %s [-t %s]\n", prgname,
            "%dpdk_params%", "%src_mac_as_hex%", "%ether_type%");
}

static int parse_args(int argc, char **argv) {
    int opt;
    char **argvopt = argv;

    bool has_source = false;
    char *end;

    ether_type = rte_cpu_to_be_16(DEFAULT_ETH_TYPE);


    while ((opt = getopt(argc, argvopt, "s:t:")) != EOF) {
        switch (opt) {
            case 's':
                if (cmdline_parse_etheraddr(NULL, optarg, src_addr.addr_bytes, sizeof (src_addr.addr_bytes)) < 0)
                    rte_exit(EXIT_FAILURE, "Invalid ethernet address: %s\n", optarg);
                has_source = true;
                break;
            case 't':
                end = NULL;
                ether_type = rte_cpu_to_be_16(strtoul(optarg, &end, 0));
                if (optarg[0] == '\0' || (end == NULL) || (*end != '\0')) {
                    print_usage(argv[0]);
                    return -1;
                }
                break;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    if (!has_source) {
        print_usage(argv[0]);
        return -1;
    }
    print_ethaddr("SRC_ADDR=", &src_addr);
    printf(", ether_type=0x%04" PRIx16 "\n", rte_be_to_cpu_16(ether_type));

    return 0;
}

static inline void calculate_hit(struct rte_mbuf *pkt) {
    struct ether_hdr *hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    if (is_same_ether_addr(&hdr->s_addr, &src_addr) && hdr->ether_type == ether_type) {
        hit++;
    }
    rte_pktmbuf_free(pkt);
}

__attribute__ ((noreturn))
static int main_loop(__rte_unused void *dummy) {
    struct rte_mbuf * pkts_burst[MAX_PKT_BURST];
    uint16_t received;
    int j;

    printf("lcore=%u, port=%" PRIu16 ", rte_socket_id=%u\n", rte_lcore_id(), 0, rte_socket_id());


    for (;;) {
        received = rte_eth_rx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
        count += received;
        /* Prefetch first packets */
        for (j = 0; j < PREFETCH_OFFSET && j < (int)received; j++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
        }
        /* Prefetch and forward already prefetched packets */
        for (j = 0; j < ((int)received - PREFETCH_OFFSET); j++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[ j + PREFETCH_OFFSET], void *));
            calculate_hit(pkts_burst[j]);
        }
        /* Forward remaining prefetched packets */
        for (; j < received; j++) {
            calculate_hit(pkts_burst[j]);
        }
    }
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

    lcore = rte_get_next_lcore(-1, 1, 0);
    if (unlikely(lcore == RTE_MAX_LCORE)) rte_exit(EXIT_FAILURE, "Require at least 2 cores.\n");

    rte_eal_remote_launch(main_loop, NULL, lcore);

    for (;;) {
        lcore = rte_get_next_lcore(lcore, 1, 0);
        if (lcore == RTE_MAX_LCORE) break;
        rte_eal_remote_launch(main_loop_waste, NULL, lcore);
    }

    for (;;) {
        printf("%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n", count, hit, full, n_full);
        rte_delay_ms(1000);
    }
    return 0;
}
