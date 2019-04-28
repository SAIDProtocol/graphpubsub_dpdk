/* 
 * File:   test_gps_i_gnrs_cache.c
 * Author: Jiachen Chen
 */
#include "gps_i_gnrs_cache.h"
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



static void test_gnrs_entry(void) {
    DEBUG_HEAD();
    struct gps_i_gnrs_cache_entry entry;
    char entry_buf[GPS_I_GNRS_CACHE_ENTRY_FMT_SIZE];

    gps_na_set(&entry.na, 0x123456);
    entry.version = UINT32_MAX;
    DEBUG("Entry=%s",
            gps_i_gnrs_cache_entry_format(entry_buf, sizeof (entry_buf), &entry));
    print_buf(&entry, sizeof (entry), 16);

}

static void test_gnrs_cache_basic_1(void) {
    DEBUG_HEAD();

    struct gps_i_gnrs_cache *cache;
    char na_buf[GPS_NA_FMT_SIZE], guid_buf[GPS_GUID_FMT_SIZE];
    struct gps_guid guid;
    struct gps_na na;
    const struct gps_na *na_p, *na_p_keep_1, *na_p_keep_2;
    uint32_t version = 0;
    int32_t ret;

    cache = gps_i_gnrs_cache_create("basic 1", 15, 32, rte_socket_id());
    if (cache == NULL) FAIL("Cannot create cache.");
    DEBUG("cache=%p", cache);
    printf("\n");

    gps_guid_set(&guid, 0xdeadbeef);
    na_p = gps_i_gnrs_cache_lookup(cache, &guid, &version);
    DEBUG("Lookup %s, got %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p),
            na_p, version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after create", __func__, __LINE__);
    printf("\n");

    gps_na_set(&na, 0x12345678);
    version = 1;
    ret = gps_i_gnrs_cache_set(cache, &guid, &na, version);
    DEBUG("set %s->(%s,%" PRIu32 "), ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            gps_na_format(na_buf, sizeof (na_buf), &na), version, ret);
    na_p_keep_1 = na_p = gps_i_gnrs_cache_lookup(cache, &guid, &version);
    DEBUG("Lookup %s, got %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p),
            na_p, version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after add", __func__, __LINE__);
    printf("\n");

    gps_na_set(&na, 0x22345678);
    version = 2;
    ret = gps_i_gnrs_cache_set(cache, &guid, &na, version);
    DEBUG("set %s->(%s,%" PRIu32 "), ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            gps_na_format(na_buf, sizeof (na_buf), &na), version, ret);
    na_p = gps_i_gnrs_cache_lookup(cache, &guid, &version);
    DEBUG("Lookup %s, got %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p),
            na_p, version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after add", __func__, __LINE__);
    printf("\n");

    gps_na_set(&na, 0x32345678);
    version = 2;
    ret = gps_i_gnrs_cache_set(cache, &guid, &na, version);
    DEBUG("set %s->(%s,%" PRIu32 "), ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            gps_na_format(na_buf, sizeof (na_buf), &na), version, ret);
    na_p = gps_i_gnrs_cache_lookup(cache, &guid, &version);
    DEBUG("Lookup %s, got %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p),
            na_p, version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after add", __func__, __LINE__);
    printf("\n");

    gps_guid_set(&guid, 0xdaedbaaf);
    ret = gps_i_gnrs_cache_set(cache, &guid, &na, version);
    DEBUG("set %s->(%s,%" PRIu32 "), ret=%" PRIi32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            gps_na_format(na_buf, sizeof (na_buf), &na), version, ret);
    na_p_keep_2 = na_p = gps_i_gnrs_cache_lookup(cache, &guid, &version);
    DEBUG("Lookup %s, got %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p),
            na_p, version);
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
    na_p = gps_i_gnrs_cache_lookup(cache, &guid, &version);
    DEBUG("Lookup %s, got %s [%p], ver=%" PRIu32,
            gps_guid_format(guid_buf, sizeof (guid_buf), &guid),
            na_p == NULL ? "" : gps_na_format(na_buf, sizeof (na_buf), na_p),
            na_p, version);
    gps_i_gnrs_cache_print(cache, stdout, "TEST_GNRS_CACHE [%s():%d] after del", __func__, __LINE__);
    printf("\n");


    DEBUG("na_p_keep1=%s [%p]", gps_na_format(na_buf, sizeof (na_buf), na_p_keep_1), na_p_keep_1);
    DEBUG("na_p_keep2=%s [%p]", gps_na_format(na_buf, sizeof (na_buf), na_p_keep_2), na_p_keep_2);
    gps_i_gnrs_cache_cleanup(cache);
    DEBUG("na_p_keep1=%s [%p]", gps_na_format(na_buf, sizeof (na_buf), na_p_keep_1), na_p_keep_1);
    DEBUG("na_p_keep2=%s [%p]", gps_na_format(na_buf, sizeof (na_buf), na_p_keep_2), na_p_keep_2);
    
    gps_i_gnrs_cache_destroy(cache);
}

void
test_gnrs_cache(void) {

    test_gnrs_entry();

    dump_mem("dmp_test_gnrs_cache_0.txt");
    test_gnrs_cache_basic_1();

    dump_mem("dmp_test_gnrs_cache_1.txt");
}
