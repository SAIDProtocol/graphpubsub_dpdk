/* 
 * File:   main.c
 * Author: Jiachen Chen
 */


//#include <inttypes.h>
#include <rte_common.h>
//#include <rte_branch_prediction.h>
//#include <rte_cycles.h>
#include <rte_eal.h>
//#include <rte_mbuf.h>
//#include <rte_lcore.h>
//#include <stdbool.h>
//#include "gps_i_anno.h"
//#include <gps_headers.h>
//#include "gps_i_forwarder_common.h"

int main(int argc, char **argv) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    

    return 0;
}

