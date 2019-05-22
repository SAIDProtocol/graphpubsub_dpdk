/* 
 * File:   test_gps_i_gnrs_cache.c
 * Author: Jiachen Chen
 */
#include <cmdline_parse_etheraddr.h>
#include "gps_i_gnrs_cache.h"
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_memzone.h>


#define RTE_LOGTYPE_TEST_GNRS_CACHE RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, TEST_GNRS_CACHE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define FAIL(...) _FAIL(__VA_ARGS__, "dummy")
#define _FAIL(fmt, ...) rte_exit(EXIT_FAILURE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_HEAD() printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__)

void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void dump_mem(const char *file_name);
void test_gnrs_cache(void);

static void test_gnrs_cache_basic_1(void) {
    DEBUG_HEAD();

    struct gps_i_neighbor_table *neighbor_table;
    struct gps_i_routing_table *routing_table;
    struct gps_i_gnrs_cache *cache;
    char na_buf[GPS_NA_FMT_SIZE], guid_buf[GPS_GUID_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    struct gps_guid guid;
    struct gps_na na, next_hop_na;
    const struct gps_na *na_p;
    struct gps_i_neighbor_info *neighbor_info;
    const struct gps_i_neighbor_info *orig_neighbor_info;
    uint32_t version = 0;
    int32_t ret;

    neighbor_table = gps_i_neighbor_table_create("basic 1", 15, 32, rte_socket_id());
    if (neighbor_table == NULL) FAIL("Cannot create neighbor table");
    routing_table = gps_i_routing_table_create("basic 1", 15, 16, rte_socket_id(), neighbor_table);
    if (routing_table == NULL) FAIL("Cannot create routing table");
    cache = gps_i_gnrs_cache_create("basic 1", 15, 32, rte_socket_id(), routing_table);
    if (cache == NULL) FAIL("Cannot create cache.");
    DEBUG("neighbor_table=%p, routing_table=%p, cache=%p", neighbor_table, routing_table, cache);
    printf("\n");

    gps_guid_set(&guid, 0xdeadbeef);
    orig_neighbor_info = gps_i_gnrs_cache_lookup(cache, &guid, &version, &na_p);
    DEBUG("Lookup %s, got %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            orig_neighbor_info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), orig_neighbor_info),
            orig_neighbor_info, version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after create", __func__, __LINE__);
    printf("\n");

    gps_na_set(&na, 0x12345678);
    gps_na_set(&next_hop_na, 0xA2345678);
    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    if (neighbor_info == NULL) FAIL("Cannot get entry from neighbor table");
    cmdline_parse_etheraddr(NULL, "a2:34:56:78:87:65", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 1;
    neighbor_info->use_ip = 0;
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    if (orig_neighbor_info != NULL) FAIL("orig_neighbor_info should be NULL, but %p", orig_neighbor_info);

    ret = gps_i_routing_table_set(routing_table, &na, &next_hop_na, 1);
    if (ret < 0) FAIL("fail in adding to routing table, ret=%" PRIi32, ret);

    version = 1;
    ret = gps_i_gnrs_cache_set(cache, &guid, &na, version);
    DEBUG("set %s->(%s,%" PRIu32 "), ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            gps_na_format(na_buf, sizeof (na_buf), &na), version, ret);
    orig_neighbor_info = gps_i_gnrs_cache_lookup(cache, &guid, &version, &na_p);
    DEBUG("Lookup %s, got %s [%p] | %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p), na_p,
            orig_neighbor_info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), orig_neighbor_info), orig_neighbor_info,
            version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after add", __func__, __LINE__);
    printf("\n");

    gps_na_set(&na, 0x22345678);
    gps_na_set(&next_hop_na, 0xB2345678);
    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    if (neighbor_info == NULL) FAIL("Cannot get entry from neighbor table");
    cmdline_parse_etheraddr(NULL, "b3:45:67:89:0a:bc", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 2;
    neighbor_info->use_ip = 0;
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    if (orig_neighbor_info != NULL) FAIL("orig_neighbor_info should be NULL, but %p", orig_neighbor_info);

    ret = gps_i_routing_table_set(routing_table, &na, &next_hop_na, 1);
    if (ret < 0) FAIL("fail in adding to routing table, ret=%" PRIi32, ret);


    version = 2;
    ret = gps_i_gnrs_cache_set(cache, &guid, &na, version);
    DEBUG("set %s->(%s,%" PRIu32 "), ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            gps_na_format(na_buf, sizeof (na_buf), &na), version, ret);
    orig_neighbor_info = gps_i_gnrs_cache_lookup(cache, &guid, &version, &na_p);
    DEBUG("Lookup %s, got %s [%p] | %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p), na_p,
            orig_neighbor_info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), orig_neighbor_info), orig_neighbor_info,
            version);
    printf("\n");


    gps_na_set(&na, 0x32345678);
    gps_na_set(&next_hop_na, 0xC2345678);
    neighbor_info = gps_i_neighbor_table_get_entry(neighbor_table);
    if (neighbor_info == NULL) FAIL("Cannot get entry from neighbor table");
    cmdline_parse_etheraddr(NULL, "77:88:99:aa:bb:cc", &neighbor_info->ether, sizeof (neighbor_info->ether));
    neighbor_info->port = 3;
    neighbor_info->use_ip = 1;
    neighbor_info->ip = rte_cpu_to_be_32(IPv4(123, 222, 111, 66));
    orig_neighbor_info = gps_i_neighbor_table_set(neighbor_table, &next_hop_na, neighbor_info);
    if (orig_neighbor_info != NULL) FAIL("orig_neighbor_info should be NULL, but %p", orig_neighbor_info);

    ret = gps_i_routing_table_set(routing_table, &na, &next_hop_na, 1);
    if (ret < 0) FAIL("fail in adding to routing table, ret=%" PRIi32, ret);

    version = 2;
    ret = gps_i_gnrs_cache_set(cache, &guid, &na, version);
    DEBUG("set %s->(%s,%" PRIu32 "), ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            gps_na_format(na_buf, sizeof (na_buf), &na), version, ret);
    orig_neighbor_info = gps_i_gnrs_cache_lookup(cache, &guid, &version, &na_p);
    DEBUG("Lookup %s, got %s [%p] | %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p), na_p,
            orig_neighbor_info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), orig_neighbor_info), orig_neighbor_info,
            version);
    printf("\n");

    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after add", __func__, __LINE__);
    printf("\n");

    gps_guid_set(&guid, 0xdaedbaaf);
    ret = gps_i_gnrs_cache_set(cache, &guid, &na, version);
    DEBUG("set %s->(%s,%" PRIu32 "), ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            gps_na_format(na_buf, sizeof (na_buf), &na), version, ret);
    orig_neighbor_info = gps_i_gnrs_cache_lookup(cache, &guid, &version, &na_p);
    DEBUG("Lookup %s, got %s [%p] | %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p), na_p,
            orig_neighbor_info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), orig_neighbor_info), orig_neighbor_info,
            version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after add", __func__, __LINE__);
    printf("\n");

    gps_guid_set(&guid, 0xdaedbcaf);
    ret = gps_i_gnrs_cache_delete(cache, &guid);
    DEBUG("del %s, ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid), ret);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after del", __func__, __LINE__);
    printf("\n");

    gps_guid_set(&guid, 0xdaedbaaf);
    ret = gps_i_gnrs_cache_delete(cache, &guid);
    DEBUG("del %s, ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid), ret);
    orig_neighbor_info = gps_i_gnrs_cache_lookup(cache, &guid, &version, &na_p);
    DEBUG("Lookup %s, got %s [%p] | %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p), na_p,
            orig_neighbor_info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), orig_neighbor_info), orig_neighbor_info,
            version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after add", __func__, __LINE__);
    printf("\n");

    gps_i_gnrs_cache_cleanup(cache);
    gps_i_gnrs_cache_destroy(cache);
    gps_i_routing_table_destroy(routing_table);
    gps_i_neighbor_table_destroy(neighbor_table);
}

static void
test_gnrs_cache_read(void) {
    const char *neighbor_file_name = "../test_read_neighbor_table.txt";
    const char *routing_file_name = "../test_read_routing_table.txt";
    const char *cache_file_name = "../test_read_gnrs_cache.txt";
    FILE *f;
    struct gps_i_neighbor_table *neighbor_table;
    struct gps_i_routing_table *routing_table;
    struct gps_i_gnrs_cache *cache;

    DEBUG_HEAD();

    neighbor_table = gps_i_neighbor_table_create("basic 1", 511, 1024, rte_socket_id());
    if (neighbor_table == NULL) FAIL("Cannot create neighbor table");
    routing_table = gps_i_routing_table_create("basic 1", 2047, 1024, rte_socket_id(), neighbor_table);
    if (routing_table == NULL) FAIL("Cannot create routing table");
    cache = gps_i_gnrs_cache_create("basic 1", 511, 1024, rte_socket_id(), routing_table);
    if (cache == NULL) FAIL("Cannot create cache.");
    DEBUG("neighbor_table=%p, routing_table=%p, cache=%p", neighbor_table, routing_table, cache);
    printf("\n");

    f = fopen(neighbor_file_name, "r");
    if (f == NULL) FAIL("Cannot open file: %s", neighbor_file_name);
    DEBUG("f=%p", f);
    gps_i_neighbor_table_read(neighbor_table, f);
    fclose(f);

    f = fopen(routing_file_name, "r");
    if (f == NULL) FAIL("Cannot open file: %s", routing_file_name);
    DEBUG("f=%p", f);
    gps_i_routing_table_read(routing_table, f, 1024);
    fclose(f);

    struct gps_na dst_na;
    gps_na_set(&dst_na, 0x3D5DD2DA);
    char na_buf[GPS_NA_FMT_SIZE];
    const struct gps_i_routing_entry * entry = gps_i_routing_table_lookup(routing_table, &dst_na);
    DEBUG("routing_table=%p, na=%s, entry=%p", routing_table, gps_na_format(na_buf, sizeof (na_buf), &dst_na), entry);
    gps_i_routing_entry_print(routing_table, entry, stdout, "");
    printf("\n");
    DEBUG("Get position=%" PRIi32, gps_i_routing_table_get_position(routing_table, &dst_na));

    f = fopen(cache_file_name, "r");
    if (f == NULL) FAIL("Cannot open file: %s", cache_file_name);
    DEBUG("f=%p", f);
    gps_i_gnrs_cache_read(cache, f, 1024);
    fclose(f);

    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after read", __func__, __LINE__);

    gps_i_gnrs_cache_destroy(cache);
    gps_i_routing_table_destroy(routing_table);
    gps_i_neighbor_table_destroy(neighbor_table);
}

void
test_gnrs_cache(void) {
    dump_mem("dmp_test_gnrs_cache_0.txt");
    test_gnrs_cache_basic_1();
    dump_mem("dmp_test_gnrs_cache_1.txt");
    test_gnrs_cache_read();
    dump_mem("dmp_test_gnrs_cache_2.txt");
}
