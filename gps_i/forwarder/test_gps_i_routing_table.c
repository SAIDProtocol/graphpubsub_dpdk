/* 
 * File:   test_gps_i_routing_table.c
 * Author: Jiachen Chen
 */
#include <cmdline_parse_etheraddr.h>
#include <inttypes.h>
#include <rte_ip.h>
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
    struct gps_i_routing_table *routing_table;
    struct gps_i_neighbor_table *neighbor_table;
    struct gps_na dst_na, next_hop_na;
    struct gps_i_neighbor_info *neighbor_info, *original_neighbor_info;
    const struct gps_i_neighbor_info *ret_neighbor_info;
    uint32_t distance;
    int32_t ret;
    char dst_na_buf[GPS_NA_FMT_SIZE], next_hop_na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

    neighbor_table = gps_i_neighbor_table_create("basic 1", 15, 32, rte_socket_id());
    if (neighbor_table == NULL) FAIL("Cannot create neighbor table!");
    DEBUG("neighbor_table=%p", neighbor_table);

    routing_table = gps_i_routing_table_create("basic 1", 15, 16, rte_socket_id(), neighbor_table);
    if (routing_table == NULL) FAIL("Cannot create routing_table!");
    DEBUG("routing_table=%p", routing_table);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);

    gps_na_set(&next_hop_na, 0x12345678);
    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    if (neighbor_info == NULL) FAIL("Cannot get entry from neighbor table");
    neighbor_info->port = 1;
    cmdline_parse_etheraddr(NULL, "11:22:33:44:55:66", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->use_ip = 0;
    DEBUG("neighbor info for %s is at %p", gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), neighbor_info);
    original_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    if (original_neighbor_info != NULL) FAIL("Should get NULL for original_neighbor_info, but %p", original_neighbor_info);

    distance = 9876;
    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);

    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");


    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    distance = 6875;
    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);
    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    if (neighbor_info == NULL) FAIL("Cannot get entry from neighbor table");
    neighbor_info->port = 2;
    cmdline_parse_etheraddr(NULL, "ff:ee:dd:cc:bb:aa", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->use_ip = 1;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(192, 168, 1, 2));
    DEBUG("neighbor info for %s is at %p", gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), neighbor_info);
    original_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    if (original_neighbor_info != NULL) FAIL("Should get NULL for original_neighbor_info, but %p", original_neighbor_info);

    distance = 6874;
    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x12345678);
    distance = 6873;
    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    if (neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    neighbor_info->port = 3;
    cmdline_parse_etheraddr(NULL, "78:90:ab:cd:ef:12", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->use_ip = 1;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(123, 234, 3, 4));
    DEBUG("neighbor info for %s is at %p", gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), neighbor_info);
    original_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    if (original_neighbor_info != NULL) FAIL("Should get NULL for original_neighbor_info, but %p", original_neighbor_info);

    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set neighbor table", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");


    gps_na_set(&next_hop_na, 0x22345678);
    distance = 6874;
    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x32345678);
    distance = 6872;
    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    if (neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    neighbor_info->port = 4;
    cmdline_parse_etheraddr(NULL, "de:ad:be:ef:fe:eb", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->use_ip = 1;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(233, 221, 113, 114));
    DEBUG("neighbor info for %s is at %p", gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), neighbor_info);
    original_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    if (original_neighbor_info != NULL) FAIL("Should get NULL for original_neighbor_info, but %p", original_neighbor_info);

    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdaedbaaf);

    gps_na_set(&next_hop_na, 0xcdef0123);
    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    if (neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    neighbor_info->port = 4;
    cmdline_parse_etheraddr(NULL, "ca:cb:cc:cd:ce:cf", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->use_ip = 0;
    DEBUG("neighbor info for %s is at %p", gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), neighbor_info);
    original_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    if (original_neighbor_info != NULL) FAIL("Should get NULL for original_neighbor_info, but %p", original_neighbor_info);

    distance = 7788;

    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x42345678);
    ret = gps_i_routing_table_delete(routing_table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("Cannot get neighbor info!");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbcef);
    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_routing_table_delete(routing_table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info != NULL) FAIL("ret_neighbor_info should be null, but %p", ret_neighbor_info);
    DEBUG("lookup %s -> %p",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            ret_neighbor_info);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x22345678);
    ret = gps_i_routing_table_delete(routing_table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("ret_neighbor_info should not be null");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x32345678);
    ret = gps_i_routing_table_delete(routing_table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("ret_neighbor_info should not be null");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_routing_table_delete(routing_table, &dst_na, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na), ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info != NULL) FAIL("ret_neighbor_info should be null, but %p", ret_neighbor_info);
    DEBUG("lookup %s -> %p",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            ret_neighbor_info);
    printf("\n");

    gps_na_set(&dst_na, 0xdeadbeef);
    gps_na_set(&next_hop_na, 0x12345678);
    //    distance = 9977;
    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("ret_neighbor_info should not be null");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);
    distance = 6874;
    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("ret_neighbor_info should not be null");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    gps_na_set(&next_hop_na, 0x32345678);
    distance = 6872;
    ret = gps_i_routing_table_set(routing_table, &dst_na, &next_hop_na, distance);
    DEBUG("set %s -> (%s,%" PRIu32 "), ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            distance, ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info == NULL) FAIL("ret_neighbor_info should not be null");
    DEBUG("lookup %s -> (%s,%" PRIu32 ")",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), ret_neighbor_info),
            distance);
    printf("\n");

    ret = gps_i_routing_table_delete_dst(routing_table, &dst_na);
    DEBUG("delete_dst %s, ret=%" PRIi32,
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            ret);
    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after delete_dst", __FUNCTION__, __LINE__);
    ret_neighbor_info = gps_i_routing_table_get_next_hop(routing_table, &dst_na, &distance);
    if (ret_neighbor_info != NULL) FAIL("ret_neighbor_info should be null but %p", ret_neighbor_info);
    DEBUG("lookup %s -> %p",
            gps_na_format(dst_na_buf, sizeof (dst_na_buf), &dst_na),
            ret_neighbor_info);
    printf("\n");

    gps_i_routing_table_cleanup(routing_table);
    gps_i_routing_table_destroy(routing_table);
    gps_i_neighbor_table_destroy(neighbor_table);
}

static void
test_routing_table_read(void) {
    DEBUG_HEAD();
    const char *neighbor_file_name = "../test_read_neighbor_table.txt";
    struct gps_i_neighbor_table *neighbor_table;

    neighbor_table = gps_i_neighbor_table_create("read", 2047, 4096, rte_socket_id());
    if (neighbor_table == NULL) FAIL("Cannot create neighbor_table!");
    DEBUG("neighbor_table=%p", neighbor_table);
    printf("\n");

    FILE *f = fopen(neighbor_file_name, "r");
    if (f == NULL) FAIL("Cannot open file: %s", neighbor_file_name);
    DEBUG("f=%p", f);
    gps_i_neighbor_table_read(neighbor_table, f);
    fclose(f);

    const char *routing_file_name = "../test_read_routing_table.txt";
    struct gps_i_routing_table *routing_table;
    routing_table = gps_i_routing_table_create("read", 2047, 2048, rte_socket_id(), neighbor_table);
    if (routing_table == NULL) FAIL("Cannot create table!");
    DEBUG("routing_table=%p", routing_table);
    printf("\n");

    f = fopen(routing_file_name, "r");
    if (f == NULL) FAIL("Cannot open file: %s", routing_file_name);
    DEBUG("f=%p", f);
    gps_i_routing_table_read(routing_table, f, 2048);
    fclose(f);

    gps_i_routing_table_print(routing_table, stdout, "TEST_ROUTING_TABLE: [%s():%d] after read", __FUNCTION__, __LINE__);

    gps_i_neighbor_table_destroy(neighbor_table);
    gps_i_routing_table_destroy(routing_table);
}

void
test_routing_table(void) {
    dump_mem("dmp_test_routing_table_0.txt");
    test_routing_table_basic_1();
    dump_mem("dmp_test_routing_table_1.txt");
    test_routing_table_read();
    dump_mem("dmp_test_routing_table_2.txt");
}