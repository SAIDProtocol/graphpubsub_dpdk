/* 
 * File:   test_gps_i_subscription_table.c
 * Author: Jiachen Chen
 */

#include <cmdline_parse_etheraddr.h>
#include <rte_ip.h>
#include <rte_log.h>
#include "gps_i_subscription_table.h"

#define RTE_LOGTYPE_TEST_SUBSCRIPTION_TABLE RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, TEST_SUBSCRIPTION_TABLE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define FAIL(...) _FAIL(__VA_ARGS__, "dummy")
#define _FAIL(fmt, ...) rte_exit(EXIT_FAILURE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_HEAD() printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__)

void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void dump_mem(const char *file_name);
void test_subscription_table(void);

static void
test_subscription_table_basic_1(void) {
    DEBUG_HEAD();

    struct gps_i_neighbor_table *neighbor_table;
    struct gps_i_subscription_table *subscription_table;
    const struct gps_i_subscription_entry *entry;
    struct gps_guid dst_guid;
    struct gps_na next_hop_na;
    struct gps_i_neighbor_info *neighbor_info, *orig_neighbor_info;
    int32_t ret;
    char dst_guid_buf[GPS_GUID_FMT_SIZE], next_hop_na_buf[GPS_NA_FMT_SIZE];
    uint32_t prefix = rte_cpu_to_be_32(0xfedcba98);

    DEBUG("size=%zd", sizeof (struct gps_i_subscription_entry));
    DEBUG("entry[0] at %p", &((struct gps_i_subscription_entry *) 0)->next_hop_positions_in_neighbor_table[0]);

    neighbor_table = gps_i_neighbor_table_create("basic 1", 15, 32, rte_socket_id());
    if (neighbor_table == NULL) FAIL("Cannot create neighbor_table!");
    DEBUG("table=%p", neighbor_table);
    printf("\n");

    subscription_table = gps_i_subscription_table_create("basic 1", 15, 16, rte_socket_id(), neighbor_table);
    if (subscription_table == NULL) FAIL("Cannot create subscription_table!");
    DEBUG("table=%p", subscription_table);
    printf("\n");

    gps_guid_set(&dst_guid, 0xdeadbeef);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0x12345678);

    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    cmdline_parse_etheraddr(NULL, "01:02:03:04:05:06", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 1;
    neighbor_info->use_ip = 0;
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    assert(orig_neighbor_info == NULL);

    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);

    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    cmdline_parse_etheraddr(NULL, "11:12:13:14:15:16", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 2;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(0xa, 0xb, 0xc, 0xd));
    neighbor_info->use_ip = 1;
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    assert(orig_neighbor_info == NULL);

    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x32345678);

    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    cmdline_parse_etheraddr(NULL, "21:22:23:24:25:26", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 3;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(0x1a, 0x1b, 0x1c, 0x1d));
    neighbor_info->use_ip = 1;
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    assert(orig_neighbor_info == NULL);

    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_guid_set(&dst_guid, 0xdaedbaaf);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0xcdef0123);

    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    cmdline_parse_etheraddr(NULL, "41:42:43:44:45:46", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 5;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(0x3a, 0x3b, 0x3c, 0x3d));
    neighbor_info->use_ip = 1;
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    assert(orig_neighbor_info == NULL);

    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);

    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);

    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    cmdline_parse_etheraddr(NULL, "31:32:33:34:35:36", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 4;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(0x2a, 0x2b, 0x2c, 0x2d));
    neighbor_info->use_ip = 1;
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    assert(orig_neighbor_info == NULL);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);



    gps_guid_set(&dst_guid, 0xdeadbeef);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0x42345678);

    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    cmdline_parse_etheraddr(NULL, "51:52:53:54:55:56", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 6;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(0x4a, 0x4b, 0x4c, 0x4d));
    neighbor_info->use_ip = 1;
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    assert(orig_neighbor_info == NULL);

    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_guid_set(&dst_guid, 0xdeadbcef);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_subscription_table_delete(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        FAIL("");
    }
    printf("\n");

    gps_guid_set(&dst_guid, 0xdeadbeef);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0x22345678);
    ret = gps_i_subscription_table_delete(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x32345678);
    ret = gps_i_subscription_table_delete(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x42345678);
    ret = gps_i_subscription_table_delete(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_subscription_table_delete(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        FAIL("");
    }
    printf("\n");

    ret = gps_i_subscription_table_delete(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        FAIL("");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);
    ret = gps_i_subscription_table_set(subscription_table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        FAIL("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    ret = gps_i_subscription_table_delete_dst(subscription_table, &dst_guid);
    DEBUG("del_dst %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            ret);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after delete_dst", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(subscription_table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(subscription_table, entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        FAIL("");
    }
    printf("\n");

    gps_i_subscription_table_destroy(subscription_table);

}

static void
test_subscription_table_read(void) {
    DEBUG_HEAD();

    const char *neighbor_file_name = "../test_read_neighbor_table.txt";
    const char *file_name_1 = "../test_read_subscription_table_1.txt";
    const char *file_name_2 = "../test_read_subscription_table_2.txt";
    struct gps_i_neighbor_table *neighbor_table;
    FILE *f;

    neighbor_table = gps_i_neighbor_table_create("read", 2047, 4096, rte_socket_id());
    if (neighbor_table == NULL) FAIL("Cannot create neighbor_table!");
    DEBUG("neighbor_table=%p", neighbor_table);
    printf("\n");

    f = fopen(neighbor_file_name, "r");
    if (f == NULL) FAIL("Cannot open file: %s", neighbor_file_name);
    DEBUG("f=%p", f);
    gps_i_neighbor_table_read(neighbor_table, f);
    fclose(f);

    struct gps_i_subscription_table *subscription_table;
    subscription_table = gps_i_subscription_table_create("basic 1", 1023, 1024, rte_socket_id(), neighbor_table);

    f = fopen(file_name_1, "r");
    if (f == NULL) FAIL("Cannot open file: %s", file_name_1);
    DEBUG("f=%p", f);
    gps_i_subscription_table_read(subscription_table, f, 1024);
    fclose(f);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);

    f = fopen(file_name_2, "r");
    if (f == NULL) FAIL("Cannot open file: %s", file_name_2);
    DEBUG("f=%p", f);
    gps_i_subscription_table_read(subscription_table, f, 1024);
    fclose(f);
    gps_i_subscription_table_print(subscription_table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
}

void
test_subscription_table(void) {
    dump_mem("dmp_test_subscription_table_0.txt");
    test_subscription_table_basic_1();
    dump_mem("dmp_test_subscription_table_1.txt");
    test_subscription_table_read();
    dump_mem("dmp_test_subscription_table_2.txt");
}