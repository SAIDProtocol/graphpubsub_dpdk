#include <signal.h>
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
#include <rte_ring.h>
#include <cmdline_parse_etheraddr.h>
#include "helper.h"

#define PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define NB_PKT_MBUF 81920
#define MAX_PKT_BURST 64
#define DEFAULT_ETH_TYPE 0x27c1
#define DEFAULT_PKT_SIZE 125
#define DEFAULT_PKT_COUNT 64
#define PREFETCH_OFFSET 3
#define BURST_TX_DRAIN_US 100
#define PIPELINE_MSGQ_SIZE 4096

static struct rte_mempool *packet_pool;
static struct ether_addr dst_addr;
static uint16_t ether_type;
struct ether_hdr *hdr_template;
static unsigned long int hanoi_level = 0;

static void print_usage(char *prgname) {
    printf("usage: %s %s -- -d %s -h %s [-t %s]\n", prgname,
            "%dpdk_params%", "%dst_mac_as_hex%", "%hanoi_level%", "%ether_type%");
    printf("\thanoi_level should be between [1, 15]");
}

static int parse_args(int argc, char **argv) {
    int opt;
    char **argvopt = argv;

    bool has_destination = false;
    char *end;

    ether_type = rte_cpu_to_be_16(DEFAULT_ETH_TYPE);


    while ((opt = getopt(argc, argvopt, "d:t:h:")) != EOF) {
        switch (opt) {
            case 'd':
                if (cmdline_parse_etheraddr(NULL, optarg, dst_addr.addr_bytes, sizeof (dst_addr.addr_bytes)) < 0)
                    rte_exit(EXIT_FAILURE, "Invalid ethernet address: %s\n", optarg);
                has_destination = true;
                break;
            case 't':
                end = NULL;
                ether_type = rte_cpu_to_be_16(strtoul(optarg, &end, 0));
                if (optarg[0] == '\0' || (end == NULL) || (*end != '\0')) {
                    print_usage(argv[0]);
                    return -1;
                }
                break;
            case 'h':
                end = NULL;
                hanoi_level = strtoul(optarg, &end, 0);
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

    if (!has_destination) {
        print_usage(argv[0]);
        return -1;
    }
    if (hanoi_level < 1 || hanoi_level > 15) {
        print_usage(argv[0]);
        return -1;
    }
    print_ethaddr("DST_ADDR=", &dst_addr);
    printf(", ether_type=0x%04" PRIx16 ", hanoi_level=%lu\n", rte_be_to_cpu_16(ether_type), hanoi_level);

    return 0;
}

static void fill_hdr(uint64_t port, struct ether_hdr *hdr) {
    rte_eth_macaddr_get(port, &hdr->s_addr);
    hdr->d_addr = dst_addr;
    hdr->ether_type = ether_type;
}


struct rte_ring *ring_pro_send;
static volatile uint64_t received = 0, hit = 0, to_send = 0, from_pro = 0, sent = 0, drain = 0;

//__attribute__ ((noreturn))
//static int main_loop_receive(__rte_unused void *dummy) {
//    struct rte_mbuf * pkts_burst[MAX_PKT_BURST];
//    uint16_t nb_rcv, nb_sent;
//
//    printf("lcore: %u, receive\n", rte_lcore_id());
//    for (;;) {
//        nb_rcv = rte_eth_rx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
//        received += nb_rcv;
//
//        //        while (unlikely(nb_rcv > 0)) {
//        //            rte_pktmbuf_free(pkts_burst[--nb_rcv]);
//        //        }
//
//        nb_sent = rte_ring_enqueue_burst(ring_rcv_pro, (void **) pkts_burst, nb_rcv, NULL);
//        to_pro += nb_sent;
//
//        while (unlikely(nb_sent < nb_rcv)) {
//            rte_pktmbuf_free(pkts_burst[nb_sent++]);
//        }
//    }
//}

static int hanoi(int from, int to, int level) {
    if (level == 0) return 0;
    int middle = 3 - from - to;
    return hanoi(from, middle, level - 1) + 1 + hanoi(middle, to, level - 1);
}

static __rte_always_inline void process_packet(struct rte_mbuf *pkt, const struct ether_hdr *ether_template) {
    struct ether_hdr *hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
    int ret;
    if (likely(hdr->ether_type == ether_type)) {
        hit++;

        //        to_send[pkt_count++] = pkt;
        rte_memcpy(hdr, ether_template, sizeof (struct ether_hdr));
        hanoi(0, 2, hanoi_level);
        //        rte_delay_us(1);
        ret = rte_ring_enqueue(ring_pro_send, pkt);
        if (likely(ret == 0)) {
            to_send++;
        } else {
            rte_pktmbuf_free(pkt);
        }

        //        if (unlikely(pkt_count == MAX_PKT_BURST))
        //            send_burst();

        //    } else {
        //        rte_pktmbuf_free(pkt);
    }
}

static uint64_t receive_counts[MAX_PKT_BURST + 1];

__attribute__ ((noreturn))
static int main_loop_receive_process(__rte_unused void *dummy) {
    struct rte_mbuf * pkts_burst[MAX_PKT_BURST];
    uint16_t nb_rcv, j;
    struct ether_hdr ether_template;

    fill_hdr(0, &ether_template);

    printf("lcore: %u, receive & process", rte_lcore_id());
    print_ethaddr(", mac=", &ether_template.s_addr);
    printf("\n");

    for (;;) {
        //        rte_delay_ms(1);
        nb_rcv = rte_eth_rx_burst(0, 0, pkts_burst, MAX_PKT_BURST);
        received += nb_rcv;
        receive_counts[nb_rcv]++;

        for (j = 0; j < PREFETCH_OFFSET && j < nb_rcv; j++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
        }
        /* Prefetch and forward already prefetched packets */
        for (j = 0; j < (nb_rcv - PREFETCH_OFFSET); j++) {
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[ j + PREFETCH_OFFSET], void *));
            process_packet(pkts_burst[j], &ether_template);
        }
        /* Forward remaining prefetched packets */
        for (; j < nb_rcv; j++) {
            process_packet(pkts_burst[j], &ether_template);
        }

        //        while (unlikely(nb_rcv > 0)) {
        //            rte_pktmbuf_free(pkts_burst[--nb_rcv]);
        //        }
        //        nb_sent = rte_ring_enqueue_burst(ring_pro_send, (void **) pkts_burst, nb_rcv, NULL);
        //        to_send += nb_sent;
        //
        //        while (unlikely(nb_sent < nb_rcv)) {
        //            rte_pktmbuf_free(pkts_burst[nb_sent++]);
        //        }
    }
}

__attribute__ ((noreturn))
static int main_loop_send(__rte_unused void *dummy) {
    struct rte_mbuf * pkts_burst[MAX_PKT_BURST];
    uint16_t nb_rcv, nb_sent;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    uint64_t last_send_time = 0, cur_tsc;


    printf("lcore: %u, send, drain_tsc=%" PRIu64 "\n", rte_lcore_id(), drain_tsc);
    for (;;) {
        nb_rcv = rte_ring_dequeue_bulk(ring_pro_send, (void *) pkts_burst, MAX_PKT_BURST, NULL);
        cur_tsc = rte_rdtsc();

        // not a buffer yet
        if (unlikely(!nb_rcv)) {
            // not till drain yet
            if (likely(cur_tsc < last_send_time + drain_tsc)) continue;
            nb_rcv = rte_ring_dequeue_burst(ring_pro_send, (void *) pkts_burst, MAX_PKT_BURST, NULL);
            // no data to send
            if (unlikely(!nb_rcv)) {
                last_send_time = cur_tsc;
                //                printf("last_send_time=%" PRIu64 "\n", last_send_time);
                continue;
            }
            //            printf("last_send_time=%" PRIu64 ", rcv=%" PRIu16 "\n", last_send_time, nb_rcv);
            drain++;
        }

        from_pro += nb_rcv;

        nb_sent = rte_eth_tx_burst(0, 0, pkts_burst, nb_rcv);
        last_send_time = cur_tsc;
        sent += nb_sent;

        while (unlikely(nb_sent < nb_rcv)) {
            rte_pktmbuf_free(pkts_burst[nb_sent++]);
        }
    }
}

__attribute__ ((noreturn))
static int main_loop_waste(__rte_unused void *dummy) {
    printf("lcore: %u, waste\n", rte_lcore_id());
    for (;;) {
        rte_delay_ms(1000);
    }
}

static void sig_int_handler(__rte_unused int signal) {
#define LINE_COUNT 8
    int i, j;
    printf("\n");
    for (i = 0; i <= MAX_PKT_BURST; i += LINE_COUNT) {
        for (j = 0; j < LINE_COUNT && i + j <= MAX_PKT_BURST; j++) {
            printf("[%d]%" PRIu64 "\t", i + j, receive_counts[i + j]);
        }
        printf("\n");
    }
    printf("\n");

    rte_exit(EXIT_SUCCESS, "Done!\n");
}

int main(int argc, char **argv) {
    int ret;
    uint16_t nb_ports;
    unsigned lcore;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    printf("sizeof receive_counts=%zd\n", sizeof (receive_counts));
    memset(receive_counts, 0, sizeof (receive_counts));
    signal(SIGINT, sig_int_handler);

    ret = parse_args(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid generator parameters\n");

    printf("rte_socket_id=%u\n", rte_socket_id());
    /* create the mbuf pools */
    packet_pool = rte_pktmbuf_pool_create("packet_pool", NB_PKT_MBUF, 32, 0, PKT_MBUF_DATA_SIZE, rte_socket_id());
    if (!unlikely(packet_pool)) rte_exit(EXIT_FAILURE, "Cannot init packet mbuf pool.\n");

    ring_pro_send = rte_ring_create("pro_send", PIPELINE_MSGQ_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!unlikely(ring_pro_send)) rte_exit(EXIT_FAILURE, "Cannot create ring for pro_send.\n");

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
    if (unlikely(lcore == RTE_MAX_LCORE)) rte_exit(EXIT_FAILURE, "Require at least 4 cores.\n");
    rte_eal_remote_launch(main_loop_receive_process, NULL, lcore);


    lcore = rte_get_next_lcore(lcore, 1, 0);
    if (unlikely(lcore == RTE_MAX_LCORE)) rte_exit(EXIT_FAILURE, "Require at least 4 cores.\n");
    rte_eal_remote_launch(main_loop_send, NULL, lcore);
    //    rte_eal_remote_launch(main_loop_waste, NULL, lcore);

    //
    for (;;) {
        lcore = rte_get_next_lcore(lcore, 1, 0);
        if (lcore == RTE_MAX_LCORE) break;
        rte_eal_remote_launch(main_loop_waste, NULL, lcore);
    }
    //
    printf("Received\tHit\tToSend\tFromPro\tSent\tDrain\n");
    for (;;) {
        printf("%" PRIu64"\t%" PRIu64"\t%" PRIu64"\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\n", received, hit, to_send, from_pro, sent, drain);
        rte_delay_ms(1000);
    }
    return 0;
}
