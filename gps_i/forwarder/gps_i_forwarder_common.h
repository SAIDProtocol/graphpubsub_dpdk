/* 
 * File:   gps_i_forwarder_common.h
 * Author: Jiachen Chen
 */

#ifndef GPS_I_FORWARDER_COMMON_H
#define GPS_I_FORWARDER_COMMON_H

#include "gps_i_anno.h"
#include <gps_headers.h>
#include "gps_i_gnrs_cache.h"
#include "gps_i_neighbor_table.h"
#include "gps_i_routing_table.h"
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GPS_I_FORWARDER_COMMON_DEBUG

#ifdef GPS_I_FORWARDER_COMMON_DEBUG
#include <rte_log.h>

#define RTE_LOGTYPE_FORWARDER_COMMON RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, FORWARDER_COMMON, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)
#else
#define DEBUG(...)
#define _DEBUG(fmt, ...)
#endif

#define GPS_I_FORWARDER_NEIGHBOR_TABLE_SIZE 63
#define GPS_I_FORWARDER_NEIGHBOR_TABLE_ENTRY_SIZE 128
#define GPS_I_FORWARDER_ROUTING_TABLE_SIZE 1023
#define GPS_I_FORWARDER_ROUTING_TABLE_ENTRYS_TO_FREE 1024
#define GPS_I_FORWARDER_GNRS_CACHE_SIZE 1023
#define GPS_I_FORWARDER_GNRS_CACHE_ENTRY_SIZE 2048
#define GPS_I_FORWARDER_SUBSCRIPTION_TABLE_SIZE 1023
#define GPS_I_FORWARDER_SUBSCRIPTION_TABLE_ENTRY_SIZE 2048
#define GPS_I_FORWARDER_PKT_MBUF_SIZE 8192
#define GPS_I_FORWARDER_PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE

    struct gps_i_forwarder_control_plane {
        struct gps_i_neighbor_table *neighbor_table;
        struct gps_i_routing_table *routing_table;
        struct gps_i_gnrs_cache *gnrs_cache;
        // subscription table
        // rp
        struct gps_na my_na;
        struct gps_i_neighbor_info my_encap_info;
        struct rte_mempool *pkt_pool;
        // values that will not appear in const forwarder
        // gnrs pending table: will always change value, therefore, will not be in const forwarder
    };

    /* The constant counter-part of gps_i_forwarder_control_plane */
    struct gps_i_forwarder_data_plane {
        const struct gps_i_neighbor_table *neighbor_table;
        const struct gps_i_routing_table *routing_table;
        const struct gps_i_gnrs_cache *gnrs_cache;
        // subscription table
        // rp
        const struct gps_na my_na;
        const struct gps_i_neighbor_info my_encap_info;
        struct rte_mempool *pkt_pool;
    };

    static __rte_always_inline struct gps_i_forwarder_control_plane *
    gps_i_forwarder_control_plane_create(const char *name, unsigned socket_id,
            struct gps_na *na, struct gps_i_neighbor_info *encap_info) {

        char tmp_name[RTE_MEMZONE_NAMESIZE];
        struct gps_i_forwarder_control_plane *forwarder;
#ifdef  GPS_I_FORWARDER_COMMON_DEBUG
        char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
#endif

        snprintf(tmp_name, sizeof (tmp_name), "FWD_%s", name);
        DEBUG("forwarder name: %s", tmp_name);
        forwarder = rte_zmalloc_socket(tmp_name, sizeof (*forwarder), 0, socket_id);
        if (unlikely(forwarder == NULL)) {
            DEBUG("fail to malloc forwarder, reason: %s", rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("forwarder=%p", forwarder);

        forwarder->neighbor_table = gps_i_neighbor_table_create(name,
                GPS_I_FORWARDER_NEIGHBOR_TABLE_SIZE,
                GPS_I_FORWARDER_NEIGHBOR_TABLE_ENTRY_SIZE,
                socket_id);
        if (unlikely(forwarder->neighbor_table == NULL)) {
            DEBUG("fail to create neighbor_table, reason: %s", rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("neighbor_table=%p", forwarder->neighbor_table);

        forwarder->routing_table = gps_i_routing_table_create(name,
                GPS_I_FORWARDER_ROUTING_TABLE_SIZE,
                GPS_I_FORWARDER_ROUTING_TABLE_ENTRYS_TO_FREE,
                socket_id);
        if (unlikely(forwarder->routing_table == NULL)) {
            DEBUG("fail to create routing_table, reason: %s", rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("routing_table=%p", forwarder->routing_table);

        forwarder->gnrs_cache = gps_i_gnrs_cache_create(name,
                GPS_I_FORWARDER_GNRS_CACHE_SIZE,
                GPS_I_FORWARDER_GNRS_CACHE_ENTRY_SIZE,
                socket_id);
        if (unlikely(forwarder->gnrs_cache == NULL)) {
            DEBUG("fail to create gnrs_cache, reason: %s", rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("gnrs_cache=%p", forwarder->gnrs_cache);

        // subscription table
        // rp
        // gnrs_pending_table


        snprintf(tmp_name, sizeof (tmp_name), "POL_%s", name);
        DEBUG("pkt_pool name: %s", tmp_name);
        forwarder->pkt_pool = rte_pktmbuf_pool_create(tmp_name,
                GPS_I_FORWARDER_PKT_MBUF_SIZE, 32, sizeof (struct gps_i_anno),
                GPS_I_FORWARDER_PKT_MBUF_DATA_SIZE, socket_id);
        if (unlikely(forwarder->pkt_pool == NULL)) {
            DEBUG("fail to create pkt_pool, reason: %s", rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("pkt_pool: %p, n=%d, priv_size=%zd, data_size=%d",
                forwarder->pkt_pool, GPS_I_FORWARDER_PKT_MBUF_SIZE,
                sizeof (struct gps_i_anno), GPS_I_FORWARDER_PKT_MBUF_DATA_SIZE);

        gps_na_copy(&forwarder->my_na, na);
        DEBUG("na=%s", gps_na_format(na_buf, sizeof (na_buf), &forwarder->my_na));
        rte_memcpy(&forwarder->my_encap_info, encap_info, sizeof (struct gps_i_neighbor_info));
        DEBUG("encap=%s",
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), &forwarder->my_encap_info));

        return forwarder;
fail:
        if (forwarder != NULL) {
            if (forwarder->neighbor_table != NULL) {
                DEBUG("destroy neighbor_table=%p", forwarder->neighbor_table);
                gps_i_neighbor_table_destroy(forwarder->neighbor_table);
            }
            if (forwarder->routing_table != NULL) {
                DEBUG("destroy routing_table=%p", forwarder->routing_table);
                gps_i_routing_table_destroy(forwarder->routing_table);
            }
            if (forwarder->gnrs_cache != NULL) {
                DEBUG("destroy gnrs_cache=%p", forwarder->gnrs_cache);
                gps_i_gnrs_cache_destroy(forwarder->gnrs_cache);
            }

            // subscription table
            // rp
            // gnrs_pending_table

            if (forwarder->pkt_pool != NULL) {
                DEBUG("free pkt_pool=%p", forwarder->pkt_pool);
                rte_mempool_free(forwarder->pkt_pool);
            }
            memset(forwarder, 0, sizeof (struct gps_i_forwarder_control_plane));
            rte_free(forwarder);
        }
        return NULL;
    }

    static __rte_always_inline struct gps_i_forwarder_data_plane *
    gps_i_forwarder_control_plane_to_data_plane(struct gps_i_forwarder_control_plane *control_plane) {
        return (struct gps_i_forwarder_data_plane *) control_plane;
    }

    static __rte_always_inline void
    gps_i_forwarder_control_plane_destroy(struct gps_i_forwarder_control_plane * forwarder) {

        DEBUG("destroy neighbor_table=%p", forwarder->neighbor_table);
        gps_i_neighbor_table_destroy(forwarder->neighbor_table);

        DEBUG("destroy routing_table=%p", forwarder->routing_table);
        gps_i_routing_table_destroy(forwarder->routing_table);

        DEBUG("destroy gnrs_cache=%p", forwarder->gnrs_cache);
        gps_i_gnrs_cache_destroy(forwarder->gnrs_cache);

        // subscription table
        // rp
        // gnrs_pending_table

        DEBUG("free pkt_pool=%p", forwarder->pkt_pool);
        rte_mempool_free(forwarder->pkt_pool);

        memset(forwarder, 0, sizeof (struct gps_i_forwarder_control_plane));
        DEBUG("free forwarder=%p", forwarder);
        rte_free(forwarder);
    }

    static __rte_always_inline void
    gps_i_forwarder_control_plane_cleanup(struct gps_i_forwarder_control_plane * forwarder) {
        gps_i_neighbor_table_cleanup(forwarder->neighbor_table);
        gps_i_routing_table_cleanup(forwarder->routing_table);
        gps_i_gnrs_cache_cleanup(forwarder->gnrs_cache);

        // subscription table
        // rp

        // gnrs_pending_table doesn't need RCU, no cleanup needed.

        memset(forwarder, 0, sizeof (struct gps_i_forwarder_control_plane));
        rte_free(forwarder);
    }

    struct gps_i_forwarder_process_lcore {
        struct gps_i_forwarder_data_plane * forwarder; // should only use lookup functions in the structure
        struct rte_ring *incoming_ring;
        struct rte_ring *control_ring;
        struct rte_ring *outgoing_rings[];
    };

    struct gps_i_forwarder_control_lcore {
        struct gps_i_forwarder_control_plane *forwarder;
        struct rte_ring *incoming_ring;
        struct rte_ring *outgoing_rings[];
    };

    static __rte_always_inline void
    gps_i_forwarder_decapsulate(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt);

    static __rte_always_inline void
    gps_i_forwarder_handle_gps_packet(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt) {
        RTE_SET_USED(lcore);
        uint16_t data_len;

        data_len = rte_pktmbuf_data_len(pkt);
        if (unlikely(data_len < sizeof (struct gps_pkt_common))) {
            DEBUG("pkt %p data_len=%" PRIu16 ", too small for gps_pkt (%zd), free",
                    pkt, data_len, sizeof (struct gps_pkt_common));
            DEBUG("free pkt: %p", pkt);
            rte_pktmbuf_free(pkt);
            return;
        }
        DEBUG("free pkt: %p", pkt);
        rte_pktmbuf_free(pkt);
    }

    //    static __rte_always_inline void
    //    gps_i_forwarder_handle_publication(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt);
    //
    //    static __rte_always_inline void
    //    gps_i_forwarder_control_handle_publication(struct gps_i_forwarder_control_lcore, struct rte_mbuf *pkt);
    //
    //    static __rte_always_inline void
    //    gps_i_forwarder_control_handle_subscription(struct gps_i_forwarder_control_lcore, struct rte_mbuf *pkt);
    //
    //    static __rte_always_inline void
    //    gps_i_forwarder_control_handle_gnrs_request(struct gps_i_forwarder_control_lcore, struct rte_mbuf *pkt);
    //
    //    static __rte_always_inline void
    //    gps_i_forwarder_control_handle_gnrs_response(struct gps_i_forwarder_control_lcore, struct rte_mbuf *pkt);

    static __rte_always_inline void
    gps_i_forwarder_encapsulate(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt);

#undef _DEBUG
#undef DEBUG

#ifdef __cplusplus
}
#endif

#endif /* GPS_I_FORWARDER_COMMON_H */

