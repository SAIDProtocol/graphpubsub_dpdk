/* 
 * File:   main.c
 * Author: Jiachen Chen
 *
 * Created on April 11, 2019, 4:43 PM
 */

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_mbuf.h>

extern void test_neighbor_table(void);
void print_buf(const void *buf, uint32_t size, uint32_t wrap);



int
main(int argc, char **argv) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    test_neighbor_table();
    
    
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


