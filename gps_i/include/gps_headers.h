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
#include <rte_common.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETHER_PROTO_TYPE 0x27c0
#define IP_PROTO_TYPE 0x90

#define GPS_TYPE_LSA 0x01
#define GPS_TYPE_PUBLISH 0x81
#define GPS_TYPE_SUBSCRIBE 0x82
#define GPS_TYPE_GNRS_REQ 0xc1
#define GPS_TYPE_GNRS_RESP 0xc2
#define GPS_TYPE_GNRS_ASSO 0xc3

    struct gps_pkt_common {
        uint8_t type;
    } __rte_aligned(sizeof (uint32_t));

    struct gps_pkt_lsa {
        struct gps_pkt_common premable;
        struct gps_na src_na;
        struct gps_na intermediate_na;
        uint32_t nonce;
    } __rte_packed;

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
        uint8_t fromEndhost:1;
    } __rte_packed;


#ifdef __cplusplus
}
#endif

#endif /* GPS_HEADERS_H */

