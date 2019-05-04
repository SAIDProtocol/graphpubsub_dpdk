/* 
 * File:   test_gps_i_subscription_table.c
 * Author: Jiachen Chen
 */

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

    struct gps_i_subscription_table *table;
    const struct gps_i_subscription_entry *entry;
    struct gps_guid dst_guid;
    struct gps_na next_hop_na;
    int32_t ret;
    char dst_guid_buf[GPS_GUID_FMT_SIZE], next_hop_na_buf[GPS_NA_FMT_SIZE];
    uint32_t prefix = rte_cpu_to_be_32(0xfedcba98);

    DEBUG("size=%zd", sizeof (struct gps_i_subscription_entry));
    DEBUG("entry[0] at %p", &((struct gps_i_subscription_entry *) 0)->next_hops[0]);

    table = gps_i_subscription_table_create("basic 1", 15, 16, rte_socket_id());
    if (table == NULL) FAIL("Cannot create table!");
    DEBUG("table=%p", table);
    printf("\n");

    gps_guid_set(&dst_guid, 0xdeadbeef);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0x12345678);

    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);
    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x32345678);
    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_guid_set(&dst_guid, 0xdaedbaaf);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0xcdef0123);
    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_guid_set(&dst_guid, 0xdeadbeef);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0x42345678);
    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_guid_set(&dst_guid, 0xdeadbcef);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_subscription_table_delete(table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_guid_set(&dst_guid, 0xdeadbeef);
    memcpy(&dst_guid, &prefix, sizeof (prefix));
    gps_na_set(&next_hop_na, 0x22345678);
    ret = gps_i_subscription_table_delete(table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x32345678);
    ret = gps_i_subscription_table_delete(table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x42345678);
    ret = gps_i_subscription_table_delete(table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_subscription_table_delete(table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    ret = gps_i_subscription_table_delete(table, &dst_guid, &next_hop_na);
    DEBUG("del %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after del", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x12345678);
    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_na_set(&next_hop_na, 0x22345678);
    ret = gps_i_subscription_table_set(table, &dst_guid, &next_hop_na);
    DEBUG("set %s -> %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after set", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    ret = gps_i_subscription_table_delete_dst(table, &dst_guid);
    DEBUG("del_dst %s, ret=%" PRIi32,
            gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid),
            ret);
    gps_i_subscription_table_print(table, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] after delete_dst", __FUNCTION__, __LINE__);
    entry = gps_i_subscription_table_lookup(table, &dst_guid);
    if (entry == NULL) {
        DEBUG("Lookup %s, got null", gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
    } else {
        gps_i_subscription_entry_print(entry, stdout, "TEST_SUBSCRIPTION_TABLE: [%s():%d] lookup %s -> ", __FUNCTION__, __LINE__,
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), &dst_guid));
        printf("\n");
    }
    printf("\n");

    gps_i_subscription_table_destroy(table);

}

void
test_subscription_table(void) {
    dump_mem("dmp_test_subscription_table_0.txt");
    test_subscription_table_basic_1();
    dump_mem("dmp_test_subscription_table_1.txt");
}