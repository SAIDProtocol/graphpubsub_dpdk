/* 
 * File:   gps_anno.h
 * Author: Jiachen Chen
 *
 * Created on April 11, 2019, 6:11 PM
 */
#ifndef GPS_ANNO_H
#define GPS_ANNO_H

#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <gps_na.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct gps_i_anno {
        struct gps_na prev_hop_na;
        struct gps_na next_hop_na;
        uint8_t prio;
        uint8_t is_control:1;
    } __rte_aligned(RTE_MBUF_PRIV_ALIGN);


#ifdef __cplusplus
}
#endif

#endif /* GPS_ANNO_H */

