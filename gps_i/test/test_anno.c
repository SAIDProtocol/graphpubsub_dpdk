/* 
 * File:   test_anno.c
 * Author: Jiachen Chen
 *
 * Created on April 13, 2019, 4:55 PM
 */

#include <rte_common.h>
#include "../forwarder/gps_i_anno.h"

extern void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void test_anno(void);

void
test_anno(void) {
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("size of anno: %zd, prev_hop_na@%zd, prev_hop_ip@%zd, "
            "prev_hop_ether@%zd, next_hop_ether@%zd, next_hop_ip@%zd,"
            "next_hop_na@%zd, prev_hop_port@%zd, next_hop_port@%zd, prio@%zd\n",
            sizeof (struct gps_i_anno),
            offsetof(struct gps_i_anno, prev_hop_na),
            offsetof(struct gps_i_anno, prev_hop_ip),
            offsetof(struct gps_i_anno, prev_hop_ether),
            offsetof(struct gps_i_anno, next_hop_ether),
            offsetof(struct gps_i_anno, next_hop_ip),
            offsetof(struct gps_i_anno, next_hop_na),
            offsetof(struct gps_i_anno, prev_hop_port),
            offsetof(struct gps_i_anno, next_hop_port),
            offsetof(struct gps_i_anno, prio));

}