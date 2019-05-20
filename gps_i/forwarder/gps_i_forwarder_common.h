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
#include "gps_i_subscription_table.h"
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

#define GPS_I_FORWARDER_NEIGHBOR_TABLE_SIZE 511
#define GPS_I_FORWARDER_NEIGHBOR_TABLE_ENTRY_SIZE 1024
#define GPS_I_FORWARDER_ROUTING_TABLE_SIZE 2047
#define GPS_I_FORWARDER_ROUTING_TABLE_ENTRYS_TO_FREE 2048
#define GPS_I_FORWARDER_GNRS_CACHE_SIZE 2047
#define GPS_I_FORWARDER_GNRS_CACHE_ENTRY_SIZE 4096
#define GPS_I_FORWARDER_SUBSCRIPTION_TABLE_SIZE 2047
#define GPS_I_FORWARDER_SUBSCRIPTION_TABLE_ENTRIRS_TO_FREE 2048
#define GPS_I_FORWARDER_PKT_MBUF_SIZE 16383
#define GPS_I_FORWARDER_PKT_MBUF_DATA_SIZE RTE_MBUF_DEFAULT_BUF_SIZE
#define GPS_I_FORWARDER_HDR_MBUF_SIZE 65535
#define GPS_I_FORWARDER_HDR_MBUF_DATA_SIZE (2 * RTE_PKTMBUF_HEADROOM)
#define GPS_I_FORWARDER_INCOMING_RING_SIZE 4096

#define GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE 0
#define GPS_I_FORWARDER_PUBLICATION_ACTION_CLONE 1
#define GPS_I_FORWARDER_PUBLICATION_ACTION_COPY 2

#define GPS_I_FORWARDER_PUBLICATION_ACTION GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE

    struct gps_i_forwarder_control_plane {
        struct gps_i_neighbor_table *neighbor_table;
        struct gps_i_routing_table *routing_table;
        struct gps_i_gnrs_cache *gnrs_cache;
        struct gps_i_subscription_table *subscription_table;
        // rp
        struct gps_na my_na;
        struct gps_i_neighbor_info *my_encap_info; // one info for each outgoing port
        struct rte_mempool *pkt_pool;
#if GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE
        struct rte_mempool *hdr_pool;
#endif
        // values that will not appear in const forwarder
        // gnrs pending table: will always change value, therefore, will not be in const forwarder
    };

    /* The constant counter-part of gps_i_forwarder_control_plane */
    struct gps_i_forwarder_data_plane {
        const struct gps_i_neighbor_table *neighbor_table;
        const struct gps_i_routing_table *routing_table;
        const struct gps_i_gnrs_cache *gnrs_cache;
        const struct gps_i_subscription_table *subscription_table;
        // rp
        const struct gps_na my_na;
        const struct gps_i_neighbor_info *my_encap_info;
        struct rte_mempool *pkt_pool;
#if GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE
        struct rte_mempool *hdr_pool;
#endif
    };

    static __rte_always_inline struct gps_i_forwarder_control_plane *
    gps_i_forwarder_control_plane_create(const char *name, unsigned socket_id,
            struct gps_na *na, struct gps_i_neighbor_info *encap_info) {

        char tmp_name[RTE_MEMZONE_NAMESIZE];
        struct gps_i_forwarder_control_plane *forwarder;
#ifdef  GPS_I_FORWARDER_COMMON_DEBUG
        char na_buf[GPS_NA_FMT_SIZE];
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
                socket_id,
                forwarder->neighbor_table);
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

        forwarder->subscription_table = gps_i_subscription_table_create(name,
                GPS_I_FORWARDER_SUBSCRIPTION_TABLE_SIZE,
                GPS_I_FORWARDER_SUBSCRIPTION_TABLE_ENTRIRS_TO_FREE,
                socket_id);
        if (unlikely(forwarder->subscription_table == NULL)) {
            DEBUG("fail to create subscription table, reason: %s", rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("subscription_table=%p", forwarder->subscription_table);


        // rp
        // gnrs_pending_table


        snprintf(tmp_name, sizeof (tmp_name), "POLP_%s", name);
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
#if GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE
        snprintf(tmp_name, sizeof (tmp_name), "POLH_%s", name);
        DEBUG("hdr_pool name: %s", tmp_name);
        forwarder->hdr_pool = rte_pktmbuf_pool_create(tmp_name,
                GPS_I_FORWARDER_HDR_MBUF_SIZE, 32, sizeof (struct gps_i_anno),
                GPS_I_FORWARDER_HDR_MBUF_DATA_SIZE, socket_id);
        if (unlikely(forwarder->hdr_pool == NULL)) {
            DEBUG("fail to create hdr_pool, reason: %s", rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("hdr_pool: %p, n=%d, priv_size=%zd, data_size=%d",
                forwarder->hdr_pool, GPS_I_FORWARDER_HDR_MBUF_SIZE,
                sizeof (struct gps_i_anno), GPS_I_FORWARDER_HDR_MBUF_DATA_SIZE);
#endif

        gps_na_copy(&forwarder->my_na, na);
        DEBUG("na=%s", gps_na_format(na_buf, sizeof (na_buf), &forwarder->my_na));
        forwarder->my_encap_info = encap_info;
        DEBUG("encap=%p", forwarder->my_encap_info);

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

            if (forwarder->subscription_table != NULL) {
                DEBUG("destroy subscription_table=%p", forwarder->subscription_table);
                gps_i_subscription_table_destroy(forwarder->subscription_table);
            }
            // rp
            // gnrs_pending_table

            if (forwarder->pkt_pool != NULL) {
                DEBUG("free pkt_pool=%p", forwarder->pkt_pool);
                rte_mempool_free(forwarder->pkt_pool);
            }
#if GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE
            if (forwarder->hdr_pool != NULL) {
                DEBUG("free hdr_pool=%p", forwarder->hdr_pool);
                rte_mempool_free(forwarder->hdr_pool);
            }
#endif
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

        DEBUG("destroy subscription_table=%p", forwarder->subscription_table);
        gps_i_subscription_table_destroy(forwarder->subscription_table);
        // rp
        // gnrs_pending_table

        DEBUG("free pkt_pool=%p", forwarder->pkt_pool);
        rte_mempool_free(forwarder->pkt_pool);

#if GPS_I_FORWARDER_PUBLICATION_ACTION == GPS_I_FORWARDER_PUBLICATION_ACTION_REFERENCE
        DEBUG("free hdr_pool=%p", forwarder->hdr_pool);
        rte_mempool_free(forwarder->hdr_pool);
#endif

        memset(forwarder, 0, sizeof (struct gps_i_forwarder_control_plane));
        DEBUG("free forwarder=%p", forwarder);
        rte_free(forwarder);
    }

    static __rte_always_inline void
    gps_i_forwarder_control_plane_cleanup(struct gps_i_forwarder_control_plane * forwarder) {
        gps_i_neighbor_table_cleanup(forwarder->neighbor_table);
        gps_i_routing_table_cleanup(forwarder->routing_table);
        gps_i_gnrs_cache_cleanup(forwarder->gnrs_cache);
        gps_i_subscription_table_cleanup(forwarder->subscription_table);
        // rp

        // gnrs_pending_table doesn't need RCU, no cleanup needed.
    }

    struct gps_i_forwarder_ring_with_stat {
        struct rte_ring *ring;
        uint64_t sent_count;
        uint64_t discarded_count;
    };

    static __rte_always_inline bool
    gps_i_forwarder_try_send_to_ring(struct gps_i_forwarder_ring_with_stat *ring, struct rte_mbuf *pkt) {
        int ret;
        ret = rte_ring_enqueue(ring->ring, pkt);
        if (unlikely(ret < 0)) {
            ring->discarded_count++;
            rte_pktmbuf_free(pkt);
            return false;
        } else {
            ring->sent_count++;
            return true;
        }
    }

    struct gps_i_forwarder_process_lcore {
        struct gps_i_forwarder_data_plane * forwarder; // should only use lookup functions in the structure
        struct rte_ring *incoming_ring;
        struct gps_i_forwarder_ring_with_stat control_ring;
        uint16_t ip_id;
        uint64_t received_count;
        struct gps_i_forwarder_ring_with_stat outgoing_rings[];
    };

    struct gps_i_forwarder_control_lcore {
        struct gps_i_forwarder_control_plane *forwarder;
        struct rte_ring *incoming_ring;
        uint16_t ip_id;
        uint64_t received_count;
        struct gps_i_forwarder_ring_with_stat outgoing_rings[];
    };

    static __rte_always_inline struct gps_i_forwarder_control_lcore *
    gps_i_forwarder_control_lcore_create(const char *name,
            struct gps_i_forwarder_control_plane *forwarder,
            struct rte_ring *outgoing_rings[],
            uint16_t outgoing_ring_count,
            unsigned socket_id) {
        char tmp_name[RTE_MEMZONE_NAMESIZE];
        struct gps_i_forwarder_control_lcore *control_lcore;
        uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct gps_i_forwarder_ring_with_stat);
        uint32_t size = sizeof (struct gps_i_forwarder_control_lcore) +outgoing_ring_size;
        uint16_t i;
        DEBUG("outgoing_ring count=%" PRIu16 ", size=%" PRIu32 ", control_lcore_size=%" PRIu32,
                outgoing_ring_count, outgoing_ring_size, size);

        snprintf(tmp_name, sizeof (tmp_name), "CCORE_%s", name);
        DEBUG("control_lcore name: %s", tmp_name);
        control_lcore = rte_zmalloc_socket(tmp_name, size, 0, socket_id);
        if (unlikely(control_lcore == NULL)) {
            DEBUG("fail to create gps_i_forwarder_control_lcore, reason: %s",
                    rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("control_lcore=%p, forwarder=%p, outgoing_rings=%p",
                control_lcore, forwarder, outgoing_rings);

        snprintf(tmp_name, sizeof (tmp_name), "CTR_%s", name);
        DEBUG("incoming_ring name: %s", tmp_name);
        control_lcore->incoming_ring = rte_ring_create(tmp_name,
                GPS_I_FORWARDER_INCOMING_RING_SIZE, socket_id, RING_F_SC_DEQ);
        if (unlikely(control_lcore->incoming_ring == NULL)) {
            DEBUG("fail to create incoming_ring, reason: %s",
                    rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("incoming_ring=%p", control_lcore->incoming_ring);

        control_lcore->forwarder = forwarder;
        control_lcore->ip_id = (uint16_t) rte_rand();
        for (i = 0; i < outgoing_ring_count; i++) {
            control_lcore->outgoing_rings[i].ring = outgoing_rings[i];
        }
        return control_lcore;
fail:
        if (control_lcore != NULL) {
            if (control_lcore->incoming_ring != NULL) {
                DEBUG("free incoming_ring=%p", control_lcore->incoming_ring);
                rte_ring_free(control_lcore->incoming_ring);
            }
            memset(control_lcore, 0, size);
            DEBUG("free control_lcore=%p", control_lcore);
            rte_free(control_lcore);
        }
        return NULL;
    }

    static __rte_always_inline void
    gps_i_forwarder_control_lcore_print_stat(FILE *stream,
            struct gps_i_forwarder_control_lcore *lcore, uint16_t outgoing_ring_count) {
        uint16_t i;
        fprintf(stream, "  received: %" PRIu64 "\n", lcore->received_count);
        for (i = 0; i < outgoing_ring_count; i++) {
            fprintf(stream, "  to outgoing %" PRIu16 ": sent: %" PRIu64 ", discarded: %" PRIu64 "\n",
                    i, lcore->outgoing_rings[i].sent_count, lcore->outgoing_rings[i].discarded_count);
        }
    }

    static __rte_always_inline void
    gps_i_forwarder_control_lcore_destroy(struct gps_i_forwarder_control_lcore *control_lcore,
            uint16_t outgoing_ring_count) {
        uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct rte_ring *);
        uint32_t size = sizeof (struct gps_i_forwarder_control_lcore) +outgoing_ring_size;

        DEBUG("free control_lcore=%p, incoming_ring=%p",
                control_lcore, control_lcore->incoming_ring);
        rte_ring_free(control_lcore->incoming_ring);
        memset(control_lcore, 0, size);
        rte_free(control_lcore);
    }

    static __rte_always_inline struct gps_i_forwarder_process_lcore *
    gps_i_forwarder_process_lcore_create(const char *name,
            struct gps_i_forwarder_data_plane *forwarder,
            struct rte_ring *control_ring,
            struct rte_ring *outgoing_rings[],
            uint16_t outgoing_ring_count,
            unsigned socket_id) {
        char tmp_name[RTE_MEMZONE_NAMESIZE];
        struct gps_i_forwarder_process_lcore *process_lcore;
        uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct gps_i_forwarder_ring_with_stat);
        uint32_t size = sizeof (struct gps_i_forwarder_process_lcore) +outgoing_ring_size;
        uint16_t i;
        DEBUG("outgoing_ring count=%" PRIu16 ", size=%" PRIu32 ", process_lcore_size=%" PRIu32,
                outgoing_ring_count, outgoing_ring_size, size);

        snprintf(tmp_name, sizeof (tmp_name), "PCORE_%s", name);
        DEBUG("process_lcore name: %s", tmp_name);
        process_lcore = rte_zmalloc(tmp_name, size, 0);
        if (unlikely(process_lcore == NULL)) {
            DEBUG("fail to create process_lcore, reason: %s",
                    rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("process_lcore=%p, forwarder=%p, control_ring=%p, outgoing_rings=%p",
                process_lcore, forwarder, control_ring, outgoing_rings);

        snprintf(tmp_name, sizeof (tmp_name), "INR_%s", name);
        DEBUG("incoming_ring name: %s", tmp_name);
        process_lcore->incoming_ring = rte_ring_create(tmp_name,
                GPS_I_FORWARDER_INCOMING_RING_SIZE, socket_id, RING_F_SC_DEQ);
        if (unlikely(process_lcore->incoming_ring == NULL)) {
            DEBUG("fail to create incoming_ring, reason: %s",
                    rte_strerror(rte_errno));
            goto fail;
        }
        DEBUG("incoming_ring=%p", process_lcore->incoming_ring);

        process_lcore->forwarder = forwarder;
        process_lcore->control_ring.ring = control_ring;
        process_lcore->ip_id = (uint16_t) rte_rand();
        for (i = 0; i < outgoing_ring_count; i++) {
            process_lcore->outgoing_rings[i].ring = outgoing_rings[i];
        }
        return process_lcore;

fail:
        if (process_lcore != NULL) {

            if (process_lcore->incoming_ring != NULL) {
                DEBUG("free incoming_ring=%p", process_lcore->incoming_ring);
                rte_ring_free(process_lcore->incoming_ring);
            }
            memset(process_lcore, 0, size);
            DEBUG("free process_lcore=%p", process_lcore);
            rte_free(process_lcore);
        }
        return NULL;
    }

    static __rte_always_inline void
    gps_i_forwarder_process_lcore_destroy(struct gps_i_forwarder_process_lcore *process_lcore,
            uint16_t outgoing_ring_count) {
        uint32_t outgoing_ring_size = outgoing_ring_count * sizeof (struct rte_ring *);
        uint32_t size = sizeof (struct gps_i_forwarder_process_lcore) +outgoing_ring_size;

        DEBUG("free process_lcore=%p, incoming_ring=%p",
                process_lcore, process_lcore->incoming_ring);
        rte_ring_free(process_lcore->incoming_ring);
        memset(process_lcore, 0, size);
        rte_free(process_lcore);
    }

    static __rte_always_inline void
    gps_i_forwarder_process_lcore_print_stat(FILE *stream,
            struct gps_i_forwarder_process_lcore *lcore, uint16_t outgoing_ring_count) {
        uint16_t i;
        fprintf(stream, "  received: %" PRIu64 "\n", lcore->received_count);
        fprintf(stream, "  to control: sent: %" PRIu64 ", discarded: %" PRIu64 "\n",
                lcore->control_ring.sent_count, lcore->control_ring.discarded_count);
        for (i = 0; i < outgoing_ring_count; i++) {
            fprintf(stream, "  to outgoing %" PRIu16 ": sent: %" PRIu64 ", discarded: %" PRIu64 "\n",
                    i, lcore->outgoing_rings[i].sent_count, lcore->outgoing_rings[i].discarded_count);
        }
    }

    static __rte_always_inline void
    gps_i_forwarder_decapsulate(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt);

    static __rte_always_inline void
    gps_i_forwarder_encapsulate(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt, const struct gps_i_neighbor_info *neighbor_info);

    static __rte_always_inline void
    gps_i_forwarder_handle_publication(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt);

    static __rte_always_inline void
    gps_i_forwarder_handle_packet(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt) {
        // start everything from decapsulation, then, decapsulate will call the other functions
        lcore->received_count++;
        gps_i_forwarder_decapsulate(lcore, pkt);
    }

    static __rte_always_inline void
    gps_i_forwarder_handle_gps_packet(struct gps_i_forwarder_process_lcore *lcore, struct rte_mbuf *pkt) {
        RTE_SET_USED(lcore);
        uint16_t data_len;
        uint8_t pkt_type;

        data_len = rte_pktmbuf_data_len(pkt);
        if (unlikely(data_len < sizeof (struct gps_pkt_common))) {
            DEBUG("pkt %p data_len=%" PRIu16 ", too small for gps_pkt (%zd), free",
                    pkt, data_len, sizeof (struct gps_pkt_common));
            DEBUG("free pkt: %p", pkt);
            rte_pktmbuf_free(pkt);
            return;
        }
        pkt_type = gps_pkt_get_type(rte_pktmbuf_mtod(pkt, void *));
        switch (pkt_type) {
            case GPS_PKT_TYPE_LSA:
                DEBUG("LSA, free pkt: %p", pkt);
                // has to be a control packet
                if (unlikely(!gps_i_forwarder_try_send_to_ring(&lcore->control_ring, pkt))) {
                    DEBUG("control ring full, discard pkt: %p", pkt);
                }
                break;
            case GPS_PKT_TYPE_PUBLICATION:
                gps_i_forwarder_handle_publication(lcore, pkt);
                break;
            case GPS_PKT_TYPE_SUBSCRIPTION:
                // has to be a control packet
                if (unlikely(!gps_i_forwarder_try_send_to_ring(&lcore->control_ring, pkt))) {
                    DEBUG("control ring full, discard pkt: %p", pkt);
                }
                break;
            case GPS_PKT_TYPE_GNRS_REQ:
                DEBUG("GNRS request, free pkt: %p", pkt);
                rte_pktmbuf_free(pkt);
                break;
            case GPS_PKT_TYPE_GNRS_RESP:
                // has to be a control packet
                if (unlikely(!gps_i_forwarder_try_send_to_ring(&lcore->control_ring, pkt))) {
                    DEBUG("control ring full, discard pkt: %p", pkt);
                }
                break;
            case GPS_PKT_TYPE_GNRS_ASSO:
                DEBUG("GNRS assocation, free pkt: %p", pkt);
                rte_pktmbuf_free(pkt);
                break;
            default:
                DEBUG("Unknown packet type 0x%02" PRIX8 ", free pkt: %p", pkt_type, pkt);
                rte_pktmbuf_free(pkt);
                break;
        }
    }

    static __rte_always_inline void
    gps_i_forwarder_control_handle_publication(struct gps_i_forwarder_control_lcore *lcore, struct rte_mbuf *pkt);

    //    static __rte_always_inline void
    //    gps_i_forwarder_control_handle_subscription(struct gps_i_forwarder_control_lcore *lcore, struct rte_mbuf *pkt);
    //
    //    static __rte_always_inline void
    //    gps_i_forwarder_control_handle_gnrs_request(struct gps_i_forwarder_control_lcore *lcore, struct rte_mbuf *pkt);
    //
    //    static __rte_always_inline void
    //    gps_i_forwarder_control_handle_gnrs_response(struct gps_i_forwarder_control_lcore *lcore, struct rte_mbuf *pkt);



#undef _DEBUG
#undef DEBUG

#ifdef __cplusplus
}
#endif

#endif /* GPS_I_FORWARDER_COMMON_H */

