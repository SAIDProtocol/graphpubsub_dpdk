/* 
 * File:   gps_anno.h
 * Author: Jiachen Chen
 *
 * Created on April 11, 2019, 6:11 PM
 */
#ifndef GPS_ANNO_H
#define GPS_ANNO_H

#include <rte_common.h>
#include <rte_mbuf.h>


#ifdef __cplusplus
extern "C" {
#endif

    struct gps_anno {
        uint32_t size;
    } __rte_aligned(RTE_MBUF_PRIV_ALIGN);


#ifdef __cplusplus
}
#endif

#endif /* GPS_ANNO_H */

