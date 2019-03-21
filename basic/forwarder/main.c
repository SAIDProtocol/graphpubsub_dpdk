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
#include "helper.h"

#define PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define NB_PKT_MBUF 8192
#define MAX_PKT_BURST 64
#define DEFAULT_ETH_TYPE 0x27c1
#define DEFAULT_PKT_SIZE 125
#define DEFAULT_PKT_COUNT 64
#define PREFETCH_OFFSET 3
#define BURST_TX_DRAIN_US 100


static struct rte_mempool *packet_pool;
static struct ether_addr dst_addr;
static uint16_t ether_type;
static volatile uint64_t received = 0, hit = 0, sent = 0, dropped = 0;
struct ether_hdr *hdr_template;

static void print_usage(char *prgname) {
    printf("usage: %s %s -- -d %s [-t %s]\n", prgname,
            "%dpdk_params%", "%dst_mac_as_hex%", "%ether_type%");
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


    while ((opt = getopt(argc, argvopt, "d:t:")) != EOF) {
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
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    if (!tmp_dst_mac.as_long) {
        print_usage(argv[0]);
        return -1;
    }
    print_ethaddr("SRC_ADDR=", &dst_addr);
    printf(", ether_type=0x%04" PRIx16 "\n", rte_be_to_cpu_16(ether_type));

    return 0;
}

static uint16_t pkt_count = 0;
static struct rte_mbuf *to_send[MAX_PKT_BURST];
static uint64_t last_send_time = 0;

static inline void send_burst(void) {
    uint16_t ret;
    ret = rte_eth_tx_burst(0, 0, to_send, pkt_count);
    sent += ret;
    if (unlikely(ret < pkt_count)) {
        dropped += pkt_count - ret;
        while (unlikely(ret < pkt_count)) {
            rte_pktmbuf_free(to_send[ret]);
            ret++;
        }
    }
    pkt_count = 0;
    last_send_time = rte_rdtsc();
}

/* Send burst of outgoing packet, if timeout expires. */
static inline void send_timeout_burst(void) {
    uint64_t cur_tsc;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

    cur_tsc = rte_rdtsc();
    if (likely(cur_tsc < last_send_time + drain_tsc))
        return;

    send_burst();
}

static inline void forward_packet(struct rte_mbuf *pkt) {
    struct ether_hdr *hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    if (likely(hdr->ether_type == ether_type)) {
        hit++;

        to_send[pkt_count++] = pkt;
        rte_memcpy(hdr, hdr_template, sizeof (struct ether_hdr));

        if (unlikely(pkt_count == MAX_PKT_BURST))
            send_burst();

    } else {
        rte_pktmbuf_free(pkt);
    }
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

__attribute__ ((noreturn))
static int main_loop(__rte_unused void *dummy) {
    struct rte_mbuf * pkts_burst[MAX_PKT_BURST];
    uint16_t nb_burst, j, nb_burst_send;

    hdr_template = (struct ether_hdr *) rte_malloc("ether_hdr", sizeof (struct ether_hdr), 0);
    if (unlikely(!hdr_template)) rte_exit(EXIT_FAILURE, "Cannot allocate hdr_template.\n");

    fill_hdr(0, hdr_template);
    //    printf("lcore=%u, port=%" PRIu16 ", rte_socket_id=%u\n", rte_lcore_id(), 0, rte_socket_id());


    for (;;) {
        nb_burst = rte_eth_rx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
        received += nb_burst;
        /* Prefetch first packets */
        for (j = 0; j < PREFETCH_OFFSET && j < nb_burst; j++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
        }
        /* Prefetch and forward already prefetched packets */
        for (j = 0; j < (nb_burst - PREFETCH_OFFSET); j++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[ j + PREFETCH_OFFSET], void *));
            forward_packet(pkts_burst[j]);
        }
        /* Forward remaining prefetched packets */
        for (; j < nb_burst; j++) {
            forward_packet(pkts_burst[j]);
        }
        //        nb_burst_send = rte_eth_tx_burst(0, 0, pkts_burst, nb_burst);
        //        sent += nb_burst;
        //        if (unlikely(nb_burst_send < nb_burst)) {
        //            dropped += nb_burst - nb_burst_send;
        //            while (unlikely(nb_burst_send < nb_burst)) {
        //                rte_pktmbuf_free(pkts_burst[nb_burst_send]);
        //                nb_burst_send++;
        //            }
        //        }
        send_timeout_burst();
    }
}

__attribute__ ((noreturn))
static int main_loop_waste(__rte_unused void *dummy) {
    printf("lcore=%u, waste, rte_socket_id=%u\n", rte_lcore_id(), rte_socket_id());
    for (;;) {
        rte_delay_ms(1000);
    }
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
    if (unlikely(lcore == RTE_MAX_LCORE)) rte_exit(EXIT_FAILURE, "Require at least 3 cores.\n");
    rte_eal_remote_launch(main_loop, NULL, lcore);

    for (;;) {
        lcore = rte_get_next_lcore(lcore, 1, 0);
        if (lcore == RTE_MAX_LCORE) break;
        rte_eal_remote_launch(main_loop_waste, NULL, lcore);
    }

    printf("Received\tHit\tSent\tDropped\n");
    for (;;) {
        printf("%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n", received, hit, sent, dropped);
        rte_delay_ms(1000);
    }
    return 0;
}