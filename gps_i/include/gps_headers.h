/* 
 * File:   headers.h
 * Author: Jiachen Chen
 *
 * Created on April 11, 2019, 4:43 PM
 */

#ifndef GPS_HEADERS_H
#define GPS_HEADERS_H

#include <gps_guid.h>
#include <gps_na.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETHER_PROTO_TYPE 0x27c0
#define IP_PROTO_TYPE 0x90

#define GPS_PKT_TYPE_MASK_APPLICATION (0x80) // 1000 0000
#define GPS_PKT_TYPE_MASK_GNRS (0xC0)  // 1100 0000

#define GPS_PKT_TYPE_LSA 0x01
#define GPS_PKT_TYPE_PUBLISH 0x81
#define GPS_PKT_TYPE_SUBSCRIBE 0x82
#define GPS_PKT_TYPE_GNRS_REQ 0xc1
#define GPS_PKT_TYPE_GNRS_RESP 0xc2
#define GPS_PKT_TYPE_GNRS_ASSO 0xc3

    struct gps_pkt_common {
        uint8_t type;
    } __rte_aligned(sizeof (uint32_t));

    static __rte_always_inline uint8_t
    gps_pkt_get_type(const void *pkt) {
        return ((const struct gps_pkt_common *) pkt)->type;
    }

    static __rte_always_inline void
    gps_pkt_set_type(void *pkt, uint8_t type) {
        ((struct gps_pkt_common *) pkt)->type = type;
    }

    static __rte_always_inline bool
    gps_pkt_is_application(const void *pkt) {
        return (gps_pkt_get_type(pkt) & GPS_PKT_TYPE_MASK_APPLICATION) == GPS_PKT_TYPE_MASK_APPLICATION;
    }

    static __rte_always_inline bool
    gps_pkt_is_gnrs(const void *pkt) {
        return (gps_pkt_get_type(pkt) & GPS_PKT_TYPE_MASK_GNRS) == GPS_PKT_TYPE_MASK_GNRS;
    }

    struct gps_pkt_lsa {
        struct gps_pkt_common premable;
        struct gps_na src_na;
        struct gps_na intermediate_na;
        uint32_t nonce;
    } __rte_packed;

    static __rte_always_inline const struct gps_na *
    gps_pkt_lsa_get_src_na(const void *pkt) {
        return &((const struct gps_pkt_lsa *) pkt)->src_na;
    }

    static __rte_always_inline const struct gps_na *
    gps_pkt_lsa_get_intermediate_na(const void *pkt) {
        return &((const struct gps_pkt_lsa *) pkt)->intermediate_na;
    }

    static __rte_always_inline uint32_t
    gps_pkt_lsa_get_nonce(const void *pkt) {
        return rte_be_to_cpu_32(((const struct gps_pkt_lsa *) pkt)->nonce);
    }

    static __rte_always_inline void
    gps_pkt_lsa_set_src_na(void *pkt, const struct gps_na *src_na) {
        gps_na_copy(&((struct gps_pkt_lsa *) pkt)->src_na, src_na);
    }

    static __rte_always_inline void
    gps_pkt_lsa_set_intermediate_na(void *pkt, const struct gps_na *intermediate_na) {
        gps_na_copy(&((struct gps_pkt_lsa *) pkt)->intermediate_na, intermediate_na);
    }

    static __rte_always_inline void
    gps_pkt_lsa_set_nonce(void *pkt, uint32_t nonce) {
        ((struct gps_pkt_lsa *) pkt)->nonce = rte_cpu_to_be_32(nonce);
    }

    static inline void
    gps_pkt_lsa_init(void *pkt, const struct gps_na *src_na, const struct gps_na *intermediate_na, uint32_t nonce) {
        gps_pkt_set_type(pkt, GPS_PKT_TYPE_LSA);
        gps_pkt_lsa_set_src_na(pkt, src_na);
        gps_pkt_lsa_set_intermediate_na(pkt, intermediate_na);
        gps_pkt_lsa_set_nonce(pkt, nonce);
    }

    static inline char *
    gps_pkt_lsa_format(char *buf, uint32_t size, const void *pkt) {
        char buf_src_na[GPS_NA_FMT_SIZE], buf_intermediate_na[GPS_NA_FMT_SIZE];
        RTE_ASSERT(gps_pkt_get_type(pkt) == GPS_PKT_TYPE_LSA);
        snprintf(buf, size, "LSA{src_na=%s,intermediate_na=%s,nonce=0x%08x}",
                gps_na_format(buf_src_na, GPS_NA_FMT_SIZE, gps_pkt_lsa_get_src_na(pkt)),
                gps_na_format(buf_intermediate_na, GPS_NA_FMT_SIZE, gps_pkt_lsa_get_intermediate_na(pkt)),
                gps_pkt_lsa_get_nonce(pkt));
        return buf;
    }

    struct gps_pkt_application {
        struct gps_pkt_common premable;
        struct gps_guid src_guid;
        struct gps_guid dst_guid;
        struct gps_na src_na;
        struct gps_na dst_na;
    } __rte_packed;

    struct gps_pkt_publication {
        struct gps_pkt_application premable;
        uint32_t size;
        uint8_t payload[];
    } __rte_packed;

    struct gps_pkt_subscription {
        struct gps_pkt_application premable;
        uint8_t subscribe;
    } __rte_packed;

    struct gps_pkt_gnrs_request {
        // premable.src_guid -> empty
        // premable.dst_guid -> requested GUID
        // premable.src_na -> src NA
        // premable.dst_na -> gnrs NA (dst)
        struct gps_pkt_application premable;
    } __rte_packed;

    struct gps_pkt_gnrs_response {
        // premable.src_guid -> requestedGuid
        // premable.dst_guid -> empty
        // premable.src_na -> gnrs NA
        // premable.dst_na -> requester GUID (dst)
        struct gps_pkt_application premable;
        struct gps_na requested_guid_na;
        uint32_t version;
        uint32_t nonce;
    } __rte_packed;

    struct gps_packet_gnrs_association {
        // premable.src_guid -> requested GUID
        // premable.dst_guid -> empty
        // premable.src_na -> src NA
        // premable.dst_na -> gnrs NA (dst)
        struct gps_pkt_application premable;
        uint8_t fromEndhost;
    } __rte_packed;


#ifdef __cplusplus
}
#endif

#endif /* GPS_HEADERS_H */

