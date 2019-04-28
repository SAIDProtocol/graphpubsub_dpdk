/* 
 * File:   test_gps_i_routing_table.c
 * Author: Jiachen Chen
 */
#include <inttypes.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <stdio.h>
#include "gps_i_routing_table.h"

#define RTE_LOGTYPE_TEST_ROUTING_TABLE RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, TEST_ROUTING_TABLE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define FAIL(...) _FAIL(__VA_ARGS__, "dummy")
#define _FAIL(fmt, ...) rte_exit(EXIT_FAILURE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_HEAD() printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__)

void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void dump_mem(const char *file_name);
void test_routing_table(void);

static void
test_routing_table_basic_1(void) {
    DEBUG_HEAD();
    struct gps_i_routing_table *table;
    struct gps_na dst_na, next_hop_na;
    const struct gps_na *ret_na_p;
    uint32_t distance;
    int32_t ret;
    char dst_na_buf[GPS_NA_FMT_SIZE], next_hop_na_buf[GPS_NA_FMT_SIZE];

    table = gps_i_routing_table_create("basic 1", 15, 16, rte_socket_id());
    if (table == NULL) FAIL("Cannot create table!");
    DEBUG("table=%p", table);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x12345678);
    distance = 9876;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");


    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    distance = 6875;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);
    distance = 6874;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x12345678);
    distance = 6873;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);
    distance = 6874;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x32345678);
    distance = 6872;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");


    gps_na_set(&dst_na, 0xdaedbaaf);
    gps_na_set(&next_hop_na, 0xcdef0123);
    distance = 7788;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x42345678);
    ret = gps_i_routing_table_delete(table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbcef);
    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_routing_table_delete(table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> %p",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            ret_na_p);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x22345678);
    ret = gps_i_routing_table_delete(table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x32345678);
    ret = gps_i_routing_table_delete(table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_routing_table_delete(table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> %p",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            ret_na_p);
    printf("\n");



    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x12345678);
    distance = 9977;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");


    gps_na_set(&next_hop_na, 0x22345678);
    distance = 6874;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x32345678);
    distance = 6872;
    ret = gps_i_routing_table_set(table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), ret_na_p),
            distance);
    printf("\n");

    ret = gps_i_routing_table_delete_dst(table, &dst_na);
    DEBUG("delete_dst %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            ret);
    gps_i_routing_table_print(table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete_dst", __FUNCTION__, __LINE__);
    ret_na_p = gps_i_routing_table_get_next_hop(table, &dst_na, &distance);
    DEBUG("lookup %s -> %p",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            ret_na_p);
    printf("\n");

//    gps_i_routing_table_cleanup(table);
    gps_i_routing_table_destroy(table);
}

void
test_routing_table(void) {
    dump_mem("dmp_test_routing_table_0.txt");
    test_routing_table_basic_1();
    dump_mem("dmp_test_routing_table_1.txt");
}