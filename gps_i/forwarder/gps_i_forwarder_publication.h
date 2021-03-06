/* 
 * File:   gps_i_forwarder_publication.h
 * Author: Jiachen Chen
 */

#ifndef GPS_I_FORWARDER_PUBLICATION_H
#define GPS_I_FORWARDER_PUBLICATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "gps_i_forwarder_common.h"

    //#define GPS_I_FORWARDER_PUBLICATION_DEBUG

#ifdef GPS_I_FORWARDER_PUBLICATION_DEBUG
#include <rte_log.h>

#define RTE_LOGTYPE_FORWARDER_PUBLICATION RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, FORWARDER_PUBLICATION, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)
#else
#define DEBUG(...)
#define _DEBUG(fmt, ...)
#endif
    static __rte_always_inline void
    gps_i_forwarder_handle_publication_upstream(struct gps_i_forwarder_process_lcore *lcore,
            struct rte_mbuf *pkt, struct gps_pkt_publication *publication);
    static __rte_always_inline void
    gps_i_forwarder_handle_publication_downstream(struct gps_i_forwarder_process_lcore *lcore,
            struct rte_mbuf *pkt, struct gps_pkt_publication *publication);

    static __rte_always_inline void
    gps_i_forwarder_handle_publication_rp(struct gps_i_forwarder_process_lcore *lcore,
            struct rte_mbuf *pkt, struct gps_pkt_publication *publication);

    static __rte_always_inline void
    gps_i_forwarder_handle_publication_upstream(struct gps_i_forwarder_process_lcore *lcore,
            struct rte_mbuf *pkt, struct gps_pkt_publication *publication) {
        struct gps_na *dst_na;
        const struct gps_na *target_na;
        const struct gps_guid *dst_guid;
        struct gps_i_anno *anno;
#ifdef GPS_I_FORWARDER_PUBLICATION_DEBUG
        char na_buf[GPS_NA_FMT_SIZE], guid_buf[GPS_GUID_FMT_SIZE];
#endif

        DEBUG("Publication upstream!");

        dst_na = gps_pkt_publication_get_dst_na(publication);
        DEBUG("dst_na=%s", gps_na_format(na_buf, sizeof (na_buf), dst_na));

        if (gps_na_is_empty(dst_na)) {
            dst_guid = gps_pkt_publication_const_get_dst_guid(publication);
            DEBUG("dst_guid=%s", gps_guid_format(guid_buf, sizeof (guid_buf), dst_guid));
            target_na = gps_i_gnrs_cache_lookup(lcore->forwarder->gnrs_cache, dst_guid, NULL);
            DEBUG("Lookup GNRS cache, got=%s [%p]",
                    target_na == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), target_na),
                    target_na);
            if (target_na == NULL) {
                DEBUG("Cannot find target_na, send to control ring");
                if (unlikely(!gps_i_forwarder_try_send_to_ring(&lcore->control_ring, pkt))) {
                    DEBUG("control ring full, discard pkt: %p", pkt);
                }
                return;
            }
            gps_na_copy(dst_na, target_na);
        }
        if (gps_na_cmp(dst_na, &lcore->forwarder->my_na) == 0) {
            DEBUG("I'm the RP, handle with RP logic");
            gps_i_forwarder_handle_publication_rp(lcore, pkt, publication);
            return;
        }
        target_na = gps_i_routing_table_get_next_hop(lcore->forwarder->routing_table, dst_na, NULL);
        if (unlikely(target_na == NULL)) {
            DEBUG("Lookup dst_na in routing table, cannot find. Free packet: %p", pkt);
            rte_pktmbuf_free(pkt);
            return;
        }
        anno = rte_mbuf_to_priv(pkt);
        gps_na_copy(&anno->next_hop_na, target_na);
        DEBUG("set next_hop_na=%s in anno", gps_na_format(na_buf, sizeof (na_buf), &anno->next_hop_na));
        gps_i_forwarder_encapsulate(lcore, pkt);
    }

    static __rte_always_inline void
    gps_i_forwarder_handle_publication_downstream(struct gps_i_forwarder_process_lcore *lcore,
            struct rte_mbuf *pkt, struct gps_pkt_publication *publication) {
        const struct gps_guid *dst_guid;
        const struct gps_i_subscription_entry *entry;
        struct gps_i_anno *anno;
        uint32_t i;
#ifdef GPS_I_FORWARDER_PUBLICATION_DEBUG
        char dst_guid_buf[GPS_GUID_FMT_SIZE], na_buf[GPS_NA_FMT_SIZE];
#endif

        DEBUG("Publication downstream!");
        dst_guid = gps_pkt_publication_get_dst_guid(publication);
        DEBUG("dst_guid=%s", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), dst_guid));

        entry = gps_i_subscription_table_lookup(lcore->forwarder->subscription_table, dst_guid);

        if (entry == NULL) {
            DEBUG("Lookup guid found nothing, free publication packet: %p", pkt);
            rte_pktmbuf_free(pkt);
            return;
        }

#if GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_COPY
        struct rte_mbuf *created;
        char *data;
        rte_pktmbuf_linearize(pkt);
        for (i = 0; i < entry->count - 1; i++) {
            created = rte_pktmbuf_alloc(lcore->forwarder->pkt_pool);
            if (created == NULL) {
                DEBUG("Cannot allocate a new packet!");
                break;
            }
            DEBUG("created=%p", created);
            created->port = pkt->port;
            created->vlan_tci = pkt->vlan_tci;
            created->vlan_tci_outer = pkt->vlan_tci_outer;
            created->tx_offload = pkt->tx_offload;
            created->hash = pkt->hash;
            data = rte_pktmbuf_append(created, rte_pktmbuf_data_len(pkt));
            DEBUG("data=%p", data);
            rte_memcpy(data, publication, rte_pktmbuf_data_len(pkt));
            anno = rte_mbuf_to_priv(created);
            gps_na_copy(&anno->next_hop_na, entry->next_hops + i);
            DEBUG("next_hop=%s", gps_na_format(na_buf, sizeof (na_buf), entry->next_hops + i));
            gps_i_forwarder_encapsulate(lcore, created);
        }
        // handle the last packet, use pkt itself.
        anno = rte_mbuf_to_priv(pkt);
        gps_na_copy(&anno->next_hop_na, entry->next_hops + i);
        DEBUG("next_hop=%s", gps_na_format(na_buf, sizeof (na_buf), entry->next_hops + i));
        gps_i_forwarder_encapsulate(lcore, pkt);

#elif GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_CLONE
        struct rte_mbuf *cloned;
        for (i = 0; i < entry->count - 1; i++) {
            cloned = rte_pktmbuf_clone(pkt, lcore->forwarder->pkt_pool);
            if (cloned == NULL) {
                DEBUG("Cannot clone a new packet!");
                break;
            }
            DEBUG("cloned=%p", cloned);
            anno = rte_mbuf_to_priv(cloned);
            gps_na_copy(&anno->next_hop_na, entry->next_hops + i);
            DEBUG("next_hop=%s", gps_na_format(na_buf, sizeof (na_buf), entry->next_hops + i));
            gps_i_forwarder_encapsulate(lcore, cloned);
        }
        // handle the last packet, use pkt itself.
        anno = rte_mbuf_to_priv(pkt);
        gps_na_copy(&anno->next_hop_na, entry->next_hops + i);
        DEBUG("next_hop=%s", gps_na_format(na_buf, sizeof (na_buf), entry->next_hops + i));
        gps_i_forwarder_encapsulate(lcore, pkt);
#elif GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE
        struct rte_mbuf *hdr;
        rte_pktmbuf_refcnt_update(pkt, (uint16_t) entry->count - 1);
        for (i = 0; i < entry->count; i++) {
            if (unlikely((hdr = rte_pktmbuf_alloc(lcore->forwarder->hdr_pool)) == NULL)) {
                DEBUG("Cannot create a new header!");
                break;
            }
            hdr->next = pkt;
            hdr->pkt_len = (uint16_t) (hdr->data_len + pkt->pkt_len);
            hdr->nb_segs = pkt->nb_segs + 1;
            hdr->port = pkt->port;
            hdr->vlan_tci = pkt->vlan_tci;
            hdr->vlan_tci_outer = pkt->vlan_tci_outer;
            hdr->tx_offload = pkt->tx_offload;
            hdr->hash = pkt->hash;
//            gps_na_copy((struct gps_na *)rte_pktmbuf_prepend(hdr, sizeof(struct gps_na)), entry->next_hops + i);
            anno = rte_mbuf_to_priv(hdr);
            gps_na_copy(&anno->next_hop_na, entry->next_hops + i);
            DEBUG("next_hop=%s", gps_na_format(na_buf, sizeof (na_buf), entry->next_hops + i));
            gps_i_forwarder_encapsulate(lcore, hdr);
        }
//        rte_pktmbuf_free(pkt);
#else
#error "Need to specify a correct GPS_I_FORWARDER_PUBLICATION_ACTION"
#endif
    }

    static __rte_always_inline void
    gps_i_forwarder_handle_publication_rp(struct gps_i_forwarder_process_lcore *lcore,
            struct rte_mbuf *pkt, struct gps_pkt_publication *publication) {
        RTE_SET_USED(lcore);
        RTE_SET_USED(pkt);
        RTE_SET_USED(publication);
        DEBUG("At RP!");
        DEBUG("Free publication packet: %p", pkt);
        rte_pktmbuf_free(pkt);
        //        rte_pktmbuf_free(pkt);

        // if I'm not serving, clear dst_na and send to control
        // expand, for each guid
        //    if I'm serving, clone, set dst_guid and src_na, handle publication downstream
        //    if I'm not serving, clone, set dst_guid and clear dst_na, handle publication upstream
    }

    static __rte_always_inline void
    gps_i_forwarder_handle_publication(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt) {

        uint16_t data_len;
        uint32_t data_size;
        struct gps_pkt_publication *publication;

        data_len = rte_pktmbuf_data_len(pkt);
        if (unlikely(data_len < sizeof (struct gps_pkt_publication))) {
            DEBUG("data_len(%" PRIu16 ") < gps_pkt_publication size(%zd), free pkt %p", data_len, sizeof (struct gps_pkt_publication), pkt);
            rte_pktmbuf_free(pkt);
            return;
        }

        publication = rte_pktmbuf_mtod(pkt, struct gps_pkt_publication *);
        data_size = gps_pkt_publication_const_get_size(publication);

        if (unlikely(data_len < data_size + sizeof (struct gps_pkt_publication))) {
            DEBUG("data_len(%" PRIu16 ") < gps_pkt_publication size (%zd) + data size (%" PRIu32"), free pkt %p",
                    data_len, sizeof (struct gps_pkt_publication), data_size, pkt);
            rte_pktmbuf_free(pkt);
            return;
        }

        if (gps_pkt_publication_const_is_upstream(publication)) {
            gps_i_forwarder_handle_publication_upstream(lcore, pkt, publication);
        } else {
            gps_i_forwarder_handle_publication_downstream(lcore, pkt, publication);
        }

    }

    static __rte_always_inline void
    gps_i_forwarder_control_handle_publication(struct gps_i_forwarder_control_lcore *lcore, struct rte_mbuf *pkt) {
        RTE_SET_USED(lcore);
        RTE_SET_USED(pkt);
        DEBUG("control handle publication, free pkt: %p", pkt);
        rte_pktmbuf_free(pkt);
    }

#undef _DEBUG
#undef DEBUG


#ifdef __cplusplus
}
#endif

#endif /* GPS_I_FORWARDER_PUBLICATION_H */

