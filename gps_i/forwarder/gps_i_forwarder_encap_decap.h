/* 
 * File:   gps_i_forwarder_encap_decap.h
 * Author: Jiachen Chen
 */

#ifndef GPS_I_FORWARDER_ENCAP_DECAP_H
#define GPS_I_FORWARDER_ENCAP_DECAP_H

#include "gps_i_anno.h"
#include "gps_i_forwarder_common.h"
#include <gps_headers.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_ip.h>

#ifdef __cplusplus
extern "C" {
#endif
#define GPS_I_FORWARDER_ENCAP_DECAP_DEBUG

#ifdef GPS_I_FORWARDER_ENCAP_DECAP_DEBUG
#include <rte_log.h>

#define RTE_LOGTYPE_FORWARDER_ENCAP_DECAP RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, FORWARDER_ENCAP_DECAP, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)
#else
#define DEBUG(...)
#define _DEBUG(fmt, ...)
#endif

    static __rte_always_inline void
    gps_i_forwarder_decapsulate(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt) {
        struct ether_hdr *eth_hdr;
        struct ipv4_hdr *ip_hdr;
        struct gps_i_anno *anno;
        uint16_t data_len, ether_proto;
        uint16_t hdr_len;

        data_len = rte_pktmbuf_data_len(pkt);

        DEBUG("Got pkt %p, data_len=%" PRIu16, pkt, data_len);
        // data size too small
        if (unlikely(data_len < ETHER_HDR_LEN)) {
            DEBUG("data len=%" PRIu16 " smaller than ether_hdr size %d!", data_len, ETHER_HDR_LEN);
            goto discard;
        }
        eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

        ether_proto = rte_be_to_cpu_16(eth_hdr->ether_type);
        DEBUG("Ether proto=0x%04X", ether_proto);
        switch (ether_proto) {
            case GPS_PROTO_TYPE_ETHER:
                // TODO: check neighbor table
                // TODO: if not found in neighbor table, forward to control ring
                // remove ether header
                rte_pktmbuf_adj(pkt, ETHER_HDR_LEN);
                DEBUG("Decapsulate ether header, new data_len=%" PRIu16, rte_pktmbuf_data_len(pkt));
                goto success;
            case ETHER_TYPE_IPv4:
                if (unlikely(data_len < ETHER_HDR_LEN + sizeof (struct ipv4_hdr))) {
                    DEBUG("data len=%" PRIu16 " smaller than ether_hdr+ip_hdr size %zu!",
                            data_len, ETHER_HDR_LEN + sizeof (struct ipv4_hdr));
                    goto discard;
                }
                ip_hdr = rte_pktmbuf_mtod_offset(pkt, struct ipv4_hdr *, ETHER_HDR_LEN);
                DEBUG("IP proto=0x%02X", ip_hdr->next_proto_id);
                switch (ip_hdr->next_proto_id) {
                    case GPS_PROTO_TYPE_IP:
                        // TODO: check neighbor table
                        // TODO: if not found in neighbor table, forward to control ring
                        // remove ip and ether header
                        hdr_len = ETHER_HDR_LEN + (ip_hdr->version_ihl & IPV4_HDR_IHL_MASK) * IPV4_IHL_MULTIPLIER;
                        DEBUG("hdr_len=%" PRIu32, hdr_len);
                        if (unlikely(data_len < hdr_len)) {
                            DEBUG("data len=%" PRIu16 " smaller than ether_hdr+ip_hdr size %" PRIu16,
                                    data_len, hdr_len);
                            goto discard;
                        }
                        rte_pktmbuf_adj(pkt, hdr_len);
                        DEBUG("Decapsulate ether and ip header, new data_len=%" PRIu16, rte_pktmbuf_data_len(pkt));
                        goto success;
                    default:
                        DEBUG("Error IP proto");
                        goto discard;
                }
            default:
                DEBUG("Error Ether proto");
                goto discard;
        }
discard:
        DEBUG("Free pkt: %p", pkt);
        rte_pktmbuf_free(pkt);
        return;

success:
        anno = rte_mbuf_to_priv(pkt);
        anno->is_decapsulated = 1;
        gps_i_forwarder_handle_gps_packet(lcore, pkt);
        return;
    }

    static __rte_always_inline void
    gps_i_forwarder_encapsulate(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt) {
        RTE_SET_USED(lcore);
        RTE_SET_USED(pkt);
    }


#undef DEBUG
#undef _DEBUG

#ifdef __cplusplus
}
#endif

#endif /* GPS_I_FORWARDER_ENCAP_DECAP_H */

