/* 
 * File:   main.c
 * Author: Jiachen Chen
 */


#include <cmdline_parse_etheraddr.h>
#include <inttypes.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_memzone.h>
#include <rte_ring.h>
#include <rte_lcore.h>
#include <signal.h>
#include <stdbool.h>
#include <urcu-qsbr.h>
#include "link_helper.h"
#include "gps_i_forwarder_common.h"
#include "gps_i_forwarder_encap_decap.h"
#include "gps_i_forwarder_publication.h"

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

#define DEFAULT_BURST_SIZE 64
#define PREFETCH_OFFSET 3
#define BURST_TX_DRAIN_US 100
#define NEIGHBOR_TABLE_FILE "../test_read_neighbor_table.txt"
#define ROUTING_TABLE_FILE "../test_read_routing_table.txt"
#define GNRS_CACHE_FILE "../test_read_gnrs_cache.txt"
#define SUBSCRIPTION_TABLE_FILE_1 "../test_read_subscription_table_1.txt"
#define SUBSCRIPTION_TABLE_FILE_2 "../test_read_subscription_table_2.txt"
#define SUBSCRIPTION_TABLE_FILE_3 "../test_read_subscription_table_3.txt"

struct receiver_params {
    uint16_t port_id;
    struct rte_ring *to_processor;
    uint64_t received_count;
    uint64_t sent_count;
};

struct sender_params {
    uint16_t port_id;
    struct rte_ring *from_processor;
    uint64_t received_count;
    uint64_t sent_count;
};

volatile bool running = true;

static void sig_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        DEBUG("Signal %d received. preparing to exit...", signum);
        running = false;
    }
}

static void
dump_mem(const char *file_name) {
    FILE *fp = fopen(file_name, "w");
    if (fp == NULL) rte_exit(EXIT_FAILURE, "Cannot open file for dump: %s", file_name);
    rte_malloc_dump_heaps(fp);
    rte_memzone_dump(fp);
    rte_mempool_list_dump(fp);
    fflush(fp);
    fclose(fp);
}

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

static int
main_loop_receiver(void *params) {
    struct receiver_params *lcore = (struct receiver_params *) params;
    struct rte_mbuf * pkts_burst[DEFAULT_BURST_SIZE];
    uint16_t nb_rcv, nb_sent;


    DEBUG("lcore=%u, receive port=%" PRIu16, rte_lcore_id(), lcore->port_id);
    DEBUG("to_process=%p", lcore->to_processor);
    while (running) {
        nb_rcv = rte_eth_rx_burst(lcore->port_id, 0, pkts_burst, DEFAULT_BURST_SIZE);
        lcore->received_count += nb_rcv;

        nb_sent = rte_ring_enqueue_burst(lcore->to_processor, (void **) pkts_burst, nb_rcv, NULL);
        lcore->sent_count += nb_sent;

        while (unlikely(nb_sent < nb_rcv)) {
            rte_pktmbuf_free(pkts_burst[nb_sent++]);
        }
    }
    DEBUG("Receiver on lcore %u, port %" PRIu16 " exit!", rte_lcore_id(), lcore->port_id);
}

static int
main_loop_sender(void *params) {
    struct sender_params *lcore = (struct sender_params *) params;
    struct rte_mbuf * pkts_burst[DEFAULT_BURST_SIZE];
    uint16_t nb_rcv, nb_sent;
    const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
    uint64_t last_send_time = 0, cur_tsc;


    DEBUG("lcore=%u, send port=%" PRIu16, rte_lcore_id(), lcore->port_id);
    while (running) {
        nb_rcv = rte_ring_dequeue_bulk(lcore->from_processor, (void *) pkts_burst, DEFAULT_BURST_SIZE, NULL);
        cur_tsc = rte_rdtsc();

        // not a buffer yet
        if (unlikely(!nb_rcv)) {
            // not till drain yet
            if (likely(cur_tsc < last_send_time + drain_tsc)) continue;
            nb_rcv = rte_ring_dequeue_burst(lcore->from_processor, (void *) pkts_burst, DEFAULT_BURST_SIZE, NULL);
            // no data to send
            if (unlikely(!nb_rcv)) {
                last_send_time = cur_tsc;
                continue;
            }
        }
        lcore->received_count += nb_rcv;
        nb_sent = rte_eth_tx_burst(0, 0, pkts_burst, nb_rcv);
        last_send_time = cur_tsc;
        lcore->sent_count += nb_sent;
        while (unlikely(nb_sent < nb_rcv)) {
            rte_pktmbuf_free(pkts_burst[nb_sent++]);
        }
    }
    DEBUG("Sender on lcore %u, port %" PRIu16 " exit!", rte_lcore_id(), lcore->port_id);
}

static int
main_loop_processor(void *params) {
    struct gps_i_forwarder_process_lcore *lcore = (struct gps_i_forwarder_process_lcore *) params;
    struct rte_mbuf * pkts_burst[DEFAULT_BURST_SIZE];
    unsigned burst_size;
    int j;

    DEBUG("lcore=%u, process, ring:%p", rte_lcore_id(), lcore->incoming_ring);
    while (running) {
        burst_size = rte_ring_dequeue_burst(lcore->incoming_ring, (void **) pkts_burst, DEFAULT_BURST_SIZE, NULL);
        //        DEBUG("burst_size=%" PRIu16, burst_size);

        for (j = 0; j < PREFETCH_OFFSET && j < (int) burst_size; j++) {
            //            DEBUG("prefetch=%" PRIu16, j);
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
        }
        for (j = 0; j < (int) (burst_size - PREFETCH_OFFSET); j++) {
            //            DEBUG("prefetch=%" PRIu16, j + PREFETCH_OFFSET);
            rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));
            gps_i_forwarder_handle_packet(lcore, pkts_burst[j]);
        }
        for (; j < (int) burst_size; j++) {
            gps_i_forwarder_handle_packet(lcore, pkts_burst[j]);
        }
    }
    DEBUG("Process on lcore %u exit!", rte_lcore_id());
}

static int
main_loop_control(void *params) {
    struct gps_i_forwarder_control_lcore *lcore = (struct gps_i_forwarder_control_lcore *) params;
    struct rte_mbuf * pkts[DEFAULT_BURST_SIZE];
    unsigned burst_size, j;

    DEBUG("lcore=%u, control", rte_lcore_id());

    //    rte_delay_ms(70000);
    //    running = false;

    while (running) {
        burst_size = rte_ring_dequeue_burst(lcore->incoming_ring, (void **) pkts, DEFAULT_BURST_SIZE, NULL);
        for (j = 0; j < burst_size; j++) {
            lcore->received_count++;
            DEBUG("Got packet %p from incoming ring, data size=%" PRIu16 ", free", pkts[j], rte_pktmbuf_data_len(pkts[j]));
            print_buf(rte_pktmbuf_mtod(pkts[j], void *), rte_pktmbuf_data_len(pkts[j]), 16);
            rte_pktmbuf_free(pkts[j]);
        }
        urcu_qsbr_synchronize_rcu();
        gps_i_forwarder_control_plane_cleanup(lcore->forwarder);
    }

    DEBUG("Control on lcore %u exit!", rte_lcore_id());
}

static void print_receiver_stat(struct receiver_params *p) {
    DEBUG("receiver on port %" PRIu16 "\n  received: %" PRIu64 ", sent: %" PRIu64,
            p->port_id, p->received_count, p->sent_count);
}

static void print_sender_stat(struct sender_params *p) {
    DEBUG("sender on port %" PRIu16 "\n  received: %" PRIu64 ", sent: %" PRIu64,
            p->port_id, p->received_count, p->sent_count);
}

int main(int argc, char **argv) {
    int ret;
    uint16_t port, port_count;
    unsigned lcore_count, lcore = -1;
    struct gps_i_forwarder_control_plane *forwarder_c;
    struct gps_i_forwarder_data_plane *forwarder_d;
    struct gps_na forwarder_na;
    struct gps_i_neighbor_info *encap_info;
    struct rte_ring **outgoing_rings;
    struct gps_i_forwarder_process_lcore **process_lcores;
    struct gps_i_forwarder_control_lcore *control_lcore;
    struct sender_params *sender_params;
    struct receiver_params *receiver_params;
    FILE *f;

    char info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    char tmp_name[RTE_MEMZONE_NAMESIZE];

    ret = rte_eal_init(argc, argv);
    if (ret < 0) FAIL("Invalid EAL parameters.");
    argc -= ret;
    argv += ret;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    dump_mem("dmp_main_0.txt");

    DEBUG("=======================CREATE PHASE=======================");
    port_count = rte_eth_dev_count_avail();
    lcore_count = rte_lcore_count();
    DEBUG("port_count=%" PRIu16 ", lcore_count=%u", port_count, lcore_count);
    if (lcore_count < port_count * 3u + 1u) {
        FAIL("For %" PRIu16 "ports, need at least %" PRIu16 " cores, now: %u.",
                port_count, port_count * 3 + 1, lcore_count);
    }

    encap_info = rte_zmalloc_socket("encap_info", sizeof (struct gps_i_neighbor_info) * port_count, 0, rte_socket_id());
    if (unlikely(encap_info == NULL)) {
        FAIL("Cannot malloc encap_info, reason: %s", rte_strerror(rte_errno));
    }
    outgoing_rings = rte_zmalloc_socket("outgoing_rings", sizeof (struct rte_ring *) * port_count, 0, rte_socket_id());
    if (unlikely(outgoing_rings == NULL)) {
        FAIL("Cannot malloc outgoing_rings, reason: %s", rte_strerror(rte_errno));
    }
    sender_params = rte_zmalloc_socket("sender_params", sizeof (struct sender_params) * port_count, 0, rte_socket_id());
    if (unlikely(sender_params == NULL)) {
        FAIL("Cannot malloc sender_params, reason: %s", rte_strerror(rte_errno));
    }
    receiver_params = rte_zmalloc_socket("receiver_params", sizeof (struct receiver_params) * port_count, 0, rte_socket_id());
    if (unlikely(receiver_params == NULL)) {
        FAIL("Cannot malloc receiver_params, reason: %s", rte_strerror(rte_errno));
    }

    DEBUG("encap_info=%p, outgoing_rings=%p, sender_params=%p, receiver_params=%p",
            encap_info, outgoing_rings, sender_params, receiver_params);

    for (port = 0; port < port_count; port++) {
        encap_info[port].port = port;
        rte_eth_macaddr_get(port, &encap_info[port].ether);
        encap_info[port].ip = rte_cpu_to_be_32(IPv4(192, 168 + port, 1, 10 + port));
        encap_info[port].use_ip = true;
        snprintf(tmp_name, sizeof (tmp_name), "OTR_%" PRIu16, port);
        outgoing_rings[port] = rte_ring_create(tmp_name,
                GPS_I_FORWARDER_INCOMING_RING_SIZE, rte_socket_id(), RING_F_SC_DEQ);
        if (outgoing_rings[port] == NULL) {
            FAIL("Cannot create ring for port %" PRIu16, port);
        }
        DEBUG("port: %" PRIu16 ", info: %s, socket: %d, outgoing_ring: %p", port,
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), encap_info + port),
                rte_eth_dev_socket_id(port), outgoing_rings[port]);
    }
    check_all_ports_link_status();

    gps_na_set(&forwarder_na, 0x101);

    forwarder_c = gps_i_forwarder_control_plane_create("forwarder",
            rte_socket_id(), &forwarder_na, encap_info);
    forwarder_d = gps_i_forwarder_control_plane_to_data_plane(forwarder_c);
    for (port = 0; port < port_count; port++) {
        enable_port(port, 1, forwarder_c->pkt_pool);
    }


    f = fopen(NEIGHBOR_TABLE_FILE, "r");
    if (f == NULL) {
        DEBUG("Cannot find file %s, skip.", NEIGHBOR_TABLE_FILE);
    } else {
        gps_i_neighbor_table_read(forwarder_c->neighbor_table, f);
        fclose(f);
    }
    gps_i_neighbor_table_print(forwarder_c->neighbor_table, stdout, "");

    f = fopen(ROUTING_TABLE_FILE, "r");
    if (f == NULL) {
        DEBUG("Cannot find file %s, skip.", ROUTING_TABLE_FILE);
    } else {
        gps_i_routing_table_read(forwarder_c->routing_table, f, GPS_I_FORWARDER_ROUTING_TABLE_ENTRYS_TO_FREE);
        fclose(f);
    }
    gps_i_routing_table_print(forwarder_c->routing_table, stdout, "");

    f = fopen(GNRS_CACHE_FILE, "r");
    if (f == NULL) {
        DEBUG("Cannot find file %s, skip.", GNRS_CACHE_FILE);
    } else {
        gps_i_gnrs_cache_read(forwarder_c->gnrs_cache, f, GPS_I_FORWARDER_GNRS_CACHE_ENTRY_SIZE);
        fclose(f);
    }
    gps_i_gnrs_cache_print(forwarder_c->gnrs_cache, stdout, "");

    f = fopen(SUBSCRIPTION_TABLE_FILE_1, "r");
    if (f == NULL) {
        DEBUG("Cannot find file %s, skip.", SUBSCRIPTION_TABLE_FILE_1);
    } else {
        gps_i_subscription_table_read(forwarder_c->subscription_table, f, GPS_I_FORWARDER_SUBSCRIPTION_TABLE_ENTRIRS_TO_FREE);
        fclose(f);
    }
    f = fopen(SUBSCRIPTION_TABLE_FILE_2, "r");
    if (f == NULL) {
        DEBUG("Cannot find file %s, skip.", SUBSCRIPTION_TABLE_FILE_2);
    } else {
        gps_i_subscription_table_read(forwarder_c->subscription_table, f, GPS_I_FORWARDER_SUBSCRIPTION_TABLE_ENTRIRS_TO_FREE);
        fclose(f);
    }
    f = fopen(SUBSCRIPTION_TABLE_FILE_3, "r");
    if (f == NULL) {
        DEBUG("Cannot find file %s, skip.", SUBSCRIPTION_TABLE_FILE_3);
    } else {
        gps_i_subscription_table_read(forwarder_c->subscription_table, f, GPS_I_FORWARDER_SUBSCRIPTION_TABLE_ENTRIRS_TO_FREE);
        fclose(f);
    }
    gps_i_subscription_table_print(forwarder_c->subscription_table, stdout, "");


    //    struct gps_na dst_na, next_hop_na;
    //    gps_i_routing_table_set(forwarder_c->routing_table,
    //            gps_na_set(&dst_na, 0x14567),
    //            gps_na_set(&next_hop_na, 0x24567),
    //            1);
    //    gps_i_routing_table_print(forwarder_c->routing_table, stdout, "MAIN: [%s():%d] routing table", __func__, __LINE__);
    //    struct gps_i_neighbor_info * neighbor =
    //            gps_i_neighbor_table_get_entry(forwarder_c->neighbor_table);
    //    cmdline_parse_etheraddr(NULL, "ec:0d:9a:7e:90:c2", &neighbor->ether, sizeof (neighbor->ether));
    //    gps_i_neighbor_table_set(forwarder_c->neighbor_table, &next_hop_na, neighbor);
    //    gps_i_neighbor_table_print(forwarder_c->neighbor_table, stdout, "MAIN: [%s():%d] neighbor table", __func__, __LINE__);


    control_lcore = gps_i_forwarder_control_lcore_create("ctrl", forwarder_c, outgoing_rings, port_count, rte_socket_id());
    if (unlikely(control_lcore == NULL)) {
        FAIL("Cannot create control_lcore");
    }

    process_lcores = rte_zmalloc_socket(NULL, sizeof (struct gps_i_forwarder_process_lcore *) * port_count, 0, rte_socket_id());
    if (unlikely(process_lcores == NULL)) {
        FAIL("Cannot malloc process_lcores, reason: %s", rte_strerror(rte_errno));
    }

    for (port = 0; port < port_count; port++) {
        // start send core
        lcore = rte_get_next_lcore(lcore, 1, 0);
        sender_params[port].from_processor = outgoing_rings[port];
        sender_params[port].port_id = port;
        rte_eal_remote_launch(main_loop_sender, &sender_params[port], lcore);

        // start process core
        lcore = rte_get_next_lcore(lcore, 1, 0);
        snprintf(tmp_name, sizeof (tmp_name), "fwd_%d", port);
        process_lcores[port] = gps_i_forwarder_process_lcore_create(tmp_name,
                forwarder_d, control_lcore->incoming_ring, outgoing_rings,
                port_count, rte_socket_id());
        rte_eal_remote_launch(main_loop_processor, process_lcores[port], lcore);

        receiver_params[port].to_processor = process_lcores[port]->incoming_ring;
        receiver_params[port].port_id = port;

        // start receive core
        lcore = rte_get_next_lcore(lcore, 1, 0);
        rte_eal_remote_launch(main_loop_receiver, &receiver_params[port], lcore);
    }

#if GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_COPY
    DEBUG("publication action using copy");
#elif GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_CLONE
#error "Not supporte now"
#elif GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE
    DEBUG("publication action using ref_cnt");
#else
#error "Need to specify a correct GPS_I_FORWARDER_PUBLICATION_ACTION"
#endif

    DEBUG("=======================MAIN LOOP=======================");
    main_loop_control(control_lcore);

    RTE_LCORE_FOREACH_SLAVE(lcore) {
        rte_eal_wait_lcore(lcore);
    }
    DEBUG("=======================DESTROY PHASE=======================");

    for (port = 0; port < port_count; port++) {
        DEBUG("stat on port %" PRIu16, port);
        gps_i_forwarder_process_lcore_print_stat(stdout, process_lcores[port], port_count);
        gps_i_forwarder_process_lcore_destroy(process_lcores[port], port_count);

    }
    DEBUG("free process_lcores: %p", process_lcores);
    rte_free(process_lcores);
    gps_i_forwarder_control_lcore_destroy(control_lcore, port_count);
    gps_i_forwarder_control_plane_destroy(forwarder_c);

    for (port = 0; port < port_count; port++) {
        DEBUG("free outgoing_ring[%" PRIu16 "]: %p", port, outgoing_rings[port]);
        rte_ring_free(outgoing_rings[port]);
        rte_eth_dev_stop(port);
        rte_eth_dev_close(port);
        print_receiver_stat(&receiver_params[port]);
        print_sender_stat(&sender_params[port]);
    }
    DEBUG("receiver_params: %p", receiver_params);
    rte_free(receiver_params);
    DEBUG("sender_params: %p", sender_params);
    rte_free(sender_params);
    DEBUG("free outgoing_rings: %p", outgoing_rings);
    rte_free(outgoing_rings);
    DEBUG("free encap_info: %p", encap_info);
    rte_free(encap_info);

    dump_mem("dmp_main_1.txt");
    return 0;
}

