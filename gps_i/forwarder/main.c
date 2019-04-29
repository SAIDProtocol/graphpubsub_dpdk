/* 
 * File:   main.c
 * Author: Jiachen Chen
 */


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

struct receiver_params {
    uint16_t port_id;
    struct rte_ring *to_processor;
    uint64_t received_count;
    uint64_t discarded_count;
    uint64_t sent_count;
};

struct sender_params {
    uint16_t port_id;
    struct rte_ring *from_processor;
    uint64_t received_count;
    uint64_t discarded_count;
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
static int
main_loop_receiver(void *params) {
    struct receiver_params *lcore = (struct receiver_params *) params;
    DEBUG("lcore=%u, receive port=%" PRIu16, rte_lcore_id(), lcore->port_id);
    while(running) {
        
    }
    DEBUG("Receiver on lcore %u, port %" PRIu16 " exit!", rte_lcore_id(), lcore->port_id);
}

static int
main_loop_sender(void *params) {
    struct sender_params *lcore = (struct sender_params *) params;
    DEBUG("lcore=%u, send port=%" PRIu16, rte_lcore_id(), lcore->port_id);
    while(running) {
        
    }
    DEBUG("Sender on lcore %u, port %" PRIu16 " exit!", rte_lcore_id(), lcore->port_id);
}

static int
main_loop_processor(void *params) {
    struct gps_i_forwarder_process_lcore *lcore = (struct gps_i_forwarder_process_lcore *) params;
    DEBUG("lcore=%u, process", rte_lcore_id());
    RTE_SET_USED(lcore);
    while(running) {
        
    }
    DEBUG("Process on lcore %u exit!", rte_lcore_id());
}

static int
main_loop_control(void *params) {
    struct gps_i_forwarder_control_lcore *lcore = (struct gps_i_forwarder_control_lcore *) params;
    DEBUG("lcore=%u, control", rte_lcore_id());
    RTE_SET_USED(lcore);
    while(running) {
        
    }
    DEBUG("Control on lcore %u exit!", rte_lcore_id());
}

static void print_receiver_stat(struct receiver_params *p) {
    DEBUG("receiver on port %" PRIu16 "\n  received: %" PRIu64 ", sent: %" PRIu64 ", discarded: %" PRIu64,
            p->port_id, p->received_count, p->sent_count, p->discarded_count);
}

static void print_sender_stat(struct sender_params *p) {
    DEBUG("sender on port %" PRIu16 "\n  received: %" PRIu64 ", sent: %" PRIu64 ", discarded: %" PRIu64,
            p->port_id, p->received_count, p->sent_count, p->discarded_count);
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

    char info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    char tmp_name[RTE_MEMZONE_NAMESIZE];

    ret = rte_eal_init(argc, argv);
    if (ret < 0) FAIL("Invalid EAL parameters.");
    argc -= ret;
    argv += ret;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    dump_mem("dmp_main_0.txt");

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
        rte_eal_remote_launch(main_loop_processor, &process_lcores[port], lcore);

        receiver_params[port].to_processor = process_lcores[port]->incoming_ring;
        receiver_params[port].port_id = port;

        // start receive core
        lcore = rte_get_next_lcore(lcore, 1, 0);
        rte_eal_remote_launch(main_loop_receiver, &receiver_params[port], lcore);
    }

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

