/* 
 * File:   main.c
 * Author: Jiachen Chen
 *
 * Created on April 11, 2019, 4:43 PM
 */

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_mbuf.h>
#include "gps_i_anno.h"

void test_anno(void);
extern void test_neighbor_table(void);
extern void test_routing_table(void);
void print_buf(const void *buf, uint32_t size, uint32_t wrap);

void
test_anno(void) {
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("size of anno: %zd, prev_hop_na@%zd, next_hop_na@%zd, prio@%zd\n",
            sizeof (struct gps_i_anno),
            offsetof(struct gps_i_anno, prev_hop_na),
            offsetof(struct gps_i_anno, next_hop_na),
            offsetof(struct gps_i_anno, prio));

}

int
main(int argc, char **argv) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    //    test_anno();
    //    test_neighbor_table();
    test_routing_table();

    return 0;
}

void
print_buf(const void *buf, uint32_t size, uint32_t wrap) {
    uint32_t i, j;
    for (i = 0; i < size;) {
        printf("%04X:", i);
        for (j = 0; i < size && j < wrap; i++, j++) {
            printf(" %02X", ((const uint8_t *) buf)[i]);
        }
        printf("\n");
    }
}


