/* 
 * File:   link_helper.c
 * Author: Jiachen Chen
 */

#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include "link_helper.h"

#define LINK_HELPER_DEBUG

#ifdef LINK_HELPER_DEBUG
#include <rte_log.h>

#define RTE_LOGTYPE_LINK_HELPER RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, LINK_HELPER, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#define FAIL(...) _FAIL(__VA_ARGS__, "dummy")
#define _FAIL(fmt, ...) \
    rte_exit(EXIT_FAILURE, "[%s():%d] " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, __VA_ARGS__)

void
enable_port(uint16_t portid, uint16_t nb_tx_queue, struct rte_mempool *packet_pool) {
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_rxconf rxq_conf;

    int ret;
    uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT,
            nb_txd = RTE_TEST_TX_DESC_DEFAULT,
            queueid;

    rte_eth_dev_info_get(portid, &dev_info);
    DEBUG("portid=%" PRIu16 ", dev_info.default_txconf.offloads=0x%" PRIx64
            ", max_rx_pktlen=%" PRIu32 ", local.max_rx_pktlen=%" PRIu32,
            portid, dev_info.default_txconf.offloads,
            dev_info.max_rx_pktlen, local_port_conf.rxmode.max_rx_pkt_len);
    local_port_conf.rxmode.max_rx_pkt_len =
            RTE_MIN(dev_info.max_rx_pktlen, local_port_conf.rxmode.max_rx_pkt_len);

    ret = rte_eth_dev_configure(portid, 1, nb_tx_queue, &local_port_conf);
    if (unlikely(ret < 0))
        FAIL("Cannot configure device: err=%d, port=%" PRIu16, ret, portid);

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
    if (unlikely(ret < 0))
        FAIL("Cannot adjust number of descriptors: err=%d, port=%" PRIu16, ret, portid);
    DEBUG("  nb_rxd=%" PRIu16 ", nb_txd=%" PRIu16, nb_rxd, nb_txd);

    DEBUG("  rxq=%" PRIu16 ", socket=%d", 0, rte_eth_dev_socket_id(portid));
    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, packet_pool);
    if (unlikely(ret < 0))
        FAIL("rte_eth_rx_queue_setup: err=%d, port=%" PRIu16, ret, portid);

    dev_info.default_txconf.offloads = local_port_conf.txmode.offloads;
    for (queueid = 0; queueid < nb_tx_queue; queueid++) {
        DEBUG("  txq=%" PRIu16 ", socket=%d", queueid, rte_eth_dev_socket_id(portid));
        DEBUG("  dev tx.offloads=%" PRIx64 ", %" PRIx64 ", tx.offloads=%" PRIx64, dev_info.tx_offload_capa, dev_info.default_txconf.offloads, local_port_conf.txmode.offloads);
        ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd, rte_eth_dev_socket_id(portid), &dev_info.default_txconf);
        if (unlikely(ret < 0))
            FAIL("rte_eth_tx_queue_setup: err=%d, port=%" PRIu16, ret, portid);
    }
    ret = rte_eth_dev_start(portid);
    if (unlikely(ret < 0)) FAIL("rte_eth_dev_start: err=%d, port=%" PRIu16, ret, portid);
    DEBUG("--started!");
}

/* Check the link status of all ports in up to 9s, and print them finally */
void check_all_ports_link_status(void) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
    uint16_t portid;
    uint8_t count, all_ports_up;
    struct rte_eth_link link;

    DEBUG("Checking link status");
    fflush(stdout);
    for (count = 0; count <= MAX_CHECK_TIME; count++) {
        all_ports_up = 1;

        RTE_ETH_FOREACH_DEV(portid) {
            memset(&link, 0, sizeof (link));
            rte_eth_link_get_nowait(portid, &link);
            /* clear all_ports_up flag if any link down */
            if (link.link_status == ETH_LINK_DOWN) {
                all_ports_up = 0;
                break;
            }
        }
        if (all_ports_up) {
            DEBUG("All ports up");
            break;
        }
        rte_delay_ms(CHECK_INTERVAL);
    }

    RTE_ETH_FOREACH_DEV(portid) {
        memset(&link, 0, sizeof (link));
        rte_eth_link_get_nowait(portid, &link);
        /* print link status if flag set */
        if (link.link_status)
            DEBUG("Port%" PRIu16 " Link Up. Speed %" PRIu32 " Mbps - %s",
                portid, link.link_speed,
                (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex"));
        else
            DEBUG("Port %" PRIu16 " Link Down", portid);
    }
}
