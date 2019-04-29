/* 
 * File:   gps_i_forwarder_encap_decap.h
 * Author: Jiachen Chen
 */

#ifndef GPS_I_FORWARDER_ENCAP_DECAP_H
#define GPS_I_FORWARDER_ENCAP_DECAP_H

#include "gps_i_forwarder_common.h"
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
        struct gps_i_anno *anno;
        const struct gps_i_neighbor_info *neighbor_info, *local_info;
        struct ether_hdr *eth_hdr;
        struct ipv4_hdr *ip_hdr;
#ifdef GPS_I_FORWARDER_ENCAP_DECAP_DEBUG
        char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
#endif
        anno = rte_mbuf_to_priv(pkt);
        DEBUG("encapsulate, next_hop_na=%s", gps_na_format(na_buf, sizeof (na_buf), &anno->next_hop_na));

        neighbor_info = gps_i_neighbor_table_lookup(lcore->forwarder->neighbor_table, &anno->next_hop_na);
        DEBUG("lookup neighbor table neighbor_info=%s [%p]",
                neighbor_info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), neighbor_info),
                neighbor_info);
        if (unlikely(neighbor_info == NULL)) {
            DEBUG("Cannot find next hop, discard pkt: %p", pkt);
            rte_pktmbuf_free(pkt);
            return;
        }

        DEBUG("pkt_start=%p", rte_pktmbuf_mtod(pkt, void *));
        local_info = &lcore->forwarder->my_encap_info[neighbor_info->port];
        if (unlikely(neighbor_info->use_ip)) {
            eth_hdr = (struct ether_hdr *) (rte_pktmbuf_prepend(pkt, sizeof (struct ether_hdr) + sizeof (struct ipv4_hdr)));
            ip_hdr = (struct ipv4_hdr *) (eth_hdr + 1);
            DEBUG("pkt_start=%p, eth_hdr=%p, ip_hdr=%p", rte_pktmbuf_mtod(pkt, void *), eth_hdr, ip_hdr);
            if (unlikely(eth_hdr == NULL)) {
                DEBUG("Cannot prepend ether header, free pkt=%p", pkt);
                rte_pktmbuf_free(pkt);
                return;
            }
            eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
            // populate ip_hdr
            ip_hdr->version_ihl = 0x40 | (sizeof (struct ipv4_hdr) >> 2);
            ip_hdr->type_of_service = 0x10;
            ip_hdr->total_length = rte_cpu_to_be_16(rte_pktmbuf_data_len(pkt) - sizeof (struct ether_hdr));
            ip_hdr->packet_id = rte_cpu_to_be_16(++lcore->ip_id);
            ip_hdr->fragment_offset = rte_cpu_to_be_16(0x4000); // don't fragment
            ip_hdr->time_to_live = 64;
            ip_hdr->next_proto_id = GPS_PROTO_TYPE_IP;
            ip_hdr->src_addr = local_info->ip;
            ip_hdr->dst_addr = neighbor_info->ip;
            ip_hdr->hdr_checksum = rte_ipv4_phdr_cksum(ip_hdr, pkt->ol_flags);
        } else {
            eth_hdr = (struct ether_hdr *) (rte_pktmbuf_prepend(pkt, sizeof (struct ether_hdr)));
            DEBUG("pkt_start=%p, eth_hdr=%p", rte_pktmbuf_mtod(pkt, void *), eth_hdr);
            if (unlikely(eth_hdr == NULL)) {
                DEBUG("Cannot prepend ether header, free pkt=%p", pkt);
                rte_pktmbuf_free(pkt);
                return;
            }
            eth_hdr->ether_type = rte_cpu_to_be_16(GPS_PROTO_TYPE_ETHER);
        }
        ether_addr_copy(&local_info->ether, &eth_hdr->s_addr);
        ether_addr_copy(&neighbor_info->ether, &eth_hdr->d_addr);
        if (unlikely(!gps_i_forwarder_try_send_to_ring(lcore->outgoing_rings + neighbor_info->port, pkt))) {
            DEBUG("outgoing ring %" PRIu16 " full, discard pkt: %p", neighbor_info->port, pkt);
        }
    }


#undef DEBUG
#undef _DEBUG

#ifdef __cplusplus
}
#endif

#endif /* GPS_I_FORWARDER_ENCAP_DECAP_H */

