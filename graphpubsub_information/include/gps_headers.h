/* 
 * File:   headers.h
 * Author: Jiachen Chen
 *
 * Created on April 11, 2019, 4:43 PM
 */

#ifndef GPS_HEADERS_H
#define GPS_HEADERS_H

#include <rte_common.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ETHER_PROTO_TYPE 0x27c0
#define IP_PROTO_TYPE 0x90
    
   

    struct gps_pkt_common {
        uint8_t type;
    } __rte_aligned(sizeof (uint32_t));

    struct gps_pkt_lsa {
        struct gps_pkt_common premable;
        uint32_t srcNa;
        uint32_t intermediateNa;
        uint32_t nonce;
    } __rte_packed;
    
    struct gps_pkt_data {
        struct gps_pkt_common premable;
        
        
    };
    

#ifdef __cplusplus
}
#endif

#endif /* GPS_HEADERS_H */

