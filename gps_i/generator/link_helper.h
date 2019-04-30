/* 
 * File:   link_helper.h
 * Author: Jiachen Chen
 */

#ifndef LINK_HELPER_H
#define LINK_HELPER_H

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>

#ifdef __cplusplus
extern "C" {
#endif

    static const struct rte_eth_conf port_conf = {
        .rxmode =
        {
            .max_rx_pkt_len = 2048,
            .split_hdr_size = 0,
            .offloads = DEV_RX_OFFLOAD_JUMBO_FRAME,
        },
        .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
            .offloads = DEV_TX_OFFLOAD_MULTI_SEGS,
            //        .offloads = 0,
        },
    };
#define RTE_TEST_RX_DESC_DEFAULT 4096
#define RTE_TEST_TX_DESC_DEFAULT 4096

    void enable_port(uint16_t portid, uint16_t nb_tx_queue, struct rte_mempool *packet_pool);

    void check_all_ports_link_status(void);


#ifdef __cplusplus
}
#endif

#endif /* LINK_HELPER_H */

