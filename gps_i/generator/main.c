/* 
 * File:   main.c
 * Author: Jiachen Chen
 */

#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#define RTE_LOGTYPE_MAIN RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) \
    RTE_LOG(INFO, MAIN, "[%s():%d] " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, __VA_ARGS__)
#define FAIL(...) _FAIL(__VA_ARGS__, "dummy")
#define _FAIL(fmt, ...) \
    rte_exit(EXIT_FAILURE, "[%s():%d] " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_HEAD() \
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__)

static struct rte_mbuf *
generate_packets() {
    return NULL;
}


int main(int argc, char **argv) {
    int ret;
    struct ether_addr src_ether;
    
    ret = rte_eal_init(argc, argv);
    if (ret < 0) FAIL("Invalid EAL parameters.");
    argc -= ret;
    argv += ret;

    RTE_SET_USED(src_ether);
    
    return 0;
}

