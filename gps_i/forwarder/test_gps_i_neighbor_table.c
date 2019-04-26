///* 
// * File:   test_neighbor_table.c
// * Author: Jiachen Chen
// *
// * Created on April 14, 2019, 2:56 AM
// */
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_mempool.h>
#include <stdio.h>
#include <urcu-qsbr.h>
#include "gps_i_neighbor_table.h"

#define RTE_LOGTYPE_TEST_NEIGHBOR_TABLE RTE_LOGTYPE_USER1


#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, TEST_NEIGHBOR_TABLE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_TIME(start, ...) _DEBUG_TIME(start, __VA_ARGS__, "dummy")
#define _DEBUG_TIME(start, fmt, ...) \
    RTE_LOG(INFO, TEST_NEIGHBOR_TABLE, "[%s():%d] %.6f " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, \
        (rte_get_timer_cycles()- start) / ((float)rte_get_timer_hz()),  \
        __VA_ARGS__)
#define FAIL(...) _FAIL(__VA_ARGS__, "dummy")
#define _FAIL(fmt, ...) rte_exit(EXIT_FAILURE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_HEAD() printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__)


extern void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void test_neighbor_table(void);

static __rte_always_inline void dump_mem(const char *file_name) {
    FILE *fp = fopen(file_name, "w");
    if (fp == NULL) FAIL("Cannot open file for dump: %s", file_name);
    rte_malloc_dump_heaps(fp);
    rte_memzone_dump(fp);
    rte_mempool_list_dump(fp);
    fflush(fp);
    fclose(fp);
}

static void
test_neighbor_table_basic_1(void) {
    DEBUG_HEAD();

    int32_t ret;

    struct gps_i_neighbor_table *table;
    uint32_t i;
    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

    struct gps_i_neighbor_info *info, *ret_info;
    const struct gps_i_neighbor_info *const_info;
    struct gps_na nas[15], *na_p, na;

    gps_na_set(nas + 0, 0xdeadbeef);
    gps_na_set(nas + 1, 0xabcdef01);
    gps_na_set(nas + 2, 0xbcdef012);
    gps_na_set(nas + 3, 0xcdef0123);
    for (i = 4; i < RTE_DIM(nas); i++) {
        gps_na_set(nas + i, i);
    }

    table = gps_i_neighbor_table_create("basic 1", RTE_DIM(nas), 32, rte_socket_id());
    if (table == NULL) FAIL("Cannot create table.");
    DEBUG("table=%p\n", table);

    rte_mempool_dump(stdout, table->values);

    // add until all the keys are used
    for (i = 0;; i++) {
        info = gps_i_neighbor_table_get_entry(table);
        DEBUG("Get entry, info=%p", info);
        if (info == NULL) break;
        info->port = (uint16_t) i;

        na_p = nas + (i % RTE_DIM(nas));
        ret_info = gps_i_neighbor_table_set(table, na_p, info);
        DEBUG("set %s->%s, ret=%p",
                gps_na_format(na_buf, sizeof (na_buf), na_p),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info),
                ret_info);
        if (unlikely(ret_info != NULL)) {
            gps_i_neighbor_table_return_entry(table, ret_info);
            printf("\n");
            break;
        }
        printf("\n");
    }

    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after populate", __func__, __LINE__);
    printf("\n");


    for (i = 0; i < RTE_DIM(nas); i++) {
        gps_na_copy(&na, nas + i);
        const_info = gps_i_neighbor_table_lookup(table, &na);
        DEBUG("Lookup %s, ret=%s [%p]",
                gps_na_format(na_buf, sizeof (na_buf), &na),
                const_info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), const_info),
                const_info);
    }
    printf("\n");

    gps_i_neighbor_table_cleanup(table);
    printf("\n");

    // add when no keys available
    gps_na_set(&na, RTE_DIM(nas));
    info = gps_i_neighbor_table_get_entry(table);
    DEBUG("Get entry, info=%p", info);
    if (info == NULL) FAIL("Cannot get info!");
    memset(info, 24, sizeof (*info));
    ret_info = gps_i_neighbor_table_set(table, &na, info);
    DEBUG("set %s->%s, ret=%p",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info),
            ret_info);
    if (ret_info == NULL) FAIL("Expect ret_info != NULL");
    if (ret_info != info) FAIL("ret_info should == info, ret=%p, info=%p", ret_info, info);
    gps_i_neighbor_table_return_entry(table, ret_info);
    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after add", __func__, __LINE__);
    printf("\n");

    for (i = 0; i < RTE_DIM(nas); i++) {
        na_p = nas + i;
        ret = gps_i_neighbor_table_delete(table, na_p);
        DEBUG("delete %s, ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), na_p),
                ret);
    }
    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after delete", __func__, __LINE__);
    printf("\n");

    gps_i_neighbor_table_cleanup(table);
    printf("\n");

    // Add a last entry to see if destroy can free all the elements
    info = gps_i_neighbor_table_get_entry(table);
    DEBUG("Get entry, info=%p", info);
    if (info == NULL) FAIL("Cannot get info!");
    memset(info, 23, sizeof (*info));
    na_p = &na;
    ret_info = gps_i_neighbor_table_set(table, na_p, info);
    DEBUG("set %s->%s, ret=%p",
            gps_na_format(na_buf, sizeof (na_buf), na_p),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info),
            ret_info);
    if (ret_info != NULL) FAIL("Expect ret_info==NULL, but get %p", ret_info);
    DEBUG("Print table");
    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after add", __func__, __LINE__);
    printf("\n");


    gps_i_neighbor_table_destroy(table);

}

static void
test_neighbor_table_basic_2(void) {
    DEBUG_HEAD();

    struct gps_i_neighbor_info info = {
        .ether =
        {.addr_bytes =
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
        .ip = IPv4(192, 168, 123, 234),
        .port = 54321,
        .use_ip = true
    };
    struct gps_i_neighbor_info *result, *result2;
    const struct gps_i_neighbor_info *const_result;
    struct gps_na na;
    gps_na_set(&na, 0x12345678);

    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    struct ether_addr addr2 = {.addr_bytes =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    int32_t ret;
    struct gps_i_neighbor_table *table;

    DEBUG("buf=%s\n", gps_i_neighbor_info_format(info_buf, sizeof (info_buf), &info));
    print_buf(&info, sizeof (info), 16);

    table = gps_i_neighbor_table_create("basic 2", 15, 32, rte_socket_id());
    if (table == NULL) FAIL("Cannot create table.");
    DEBUG("table=%p", table);

    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after create", __func__, __LINE__);
    printf("\n");

    result = gps_i_neighbor_table_get_entry(table);
    if (result == NULL) FAIL("Cannot get entry");

    rte_memcpy(result, &info, sizeof (struct gps_i_neighbor_info));
    DEBUG("result=%s [%p]", gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result), result);

    result2 = gps_i_neighbor_table_set(table, &na, result);
    DEBUG("set %s->%s: %p",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result),
            result2);
    if (result2 != NULL) FAIL("Add entry got result not null result2=%p", result2);

    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after add", __func__, __LINE__);
    printf("\n");
    gps_i_neighbor_table_cleanup(table);
    printf("\n");

    info.ip = IPv4(192, 168, 1, 2);
    info.port = 1234;
    rte_memcpy(&info.ether, &addr2, sizeof (struct ether_addr));

    result = gps_i_neighbor_table_get_entry(table);
    if (result == NULL) FAIL("Cannot get entry");
    rte_memcpy(result, &info, sizeof (struct gps_i_neighbor_info));
    DEBUG("result=%s [%p]", gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result), result);

    result2 = gps_i_neighbor_table_set(table, &na, result);
    DEBUG("set %s->%s: %p\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result),
            result2);
    if (result2 != NULL) FAIL("Add entry got result not null result2=%p", result2);

    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after add", __func__, __LINE__);
    printf("\n");
    gps_i_neighbor_table_cleanup(table);
    printf("\n");


    memset(&info.ether, 0x39, sizeof (info.ether));
    info.port = 7890;
    gps_na_set(&na, 0x87654321);
    info.use_ip = false;

    result = gps_i_neighbor_table_get_entry(table);
    if (result == NULL) FAIL("Cannot get entry");
    rte_memcpy(result, &info, sizeof (struct gps_i_neighbor_info));
    DEBUG("result=%s [%p]", gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result), result);

    result2 = gps_i_neighbor_table_set(table, &na, result);
    DEBUG("set %s->%s: %p",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result),
            result2);
    if (result2 != NULL) FAIL("Add entry got result not null result2=%p", result2);

    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after add", __func__, __LINE__);
    printf("\n");
    gps_i_neighbor_table_cleanup(table);
    printf("\n");

    gps_na_set(&na, 0x12345678);
    const_result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> %s [%p]",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            const_result == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), const_result),
            const_result);

    gps_na_set(&na, 0x87654321);
    const_result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> %s [%p]",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            const_result == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), const_result),
            const_result);

    gps_na_set(&na, 0x77654321);
    const_result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> %s [%p]",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            const_result == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), const_result),
            const_result);
    printf("\n");


    ret = gps_i_neighbor_table_delete(table, &na);
    DEBUG("delete %s: %" PRIi32, gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after delete", __func__, __LINE__);
    printf("\n");
    gps_i_neighbor_table_cleanup(table);
    printf("\n");

    gps_na_set(&na, 0x12345678);
    ret = gps_i_neighbor_table_delete(table, &na);
    DEBUG("delete %s: %" PRIi32, gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after delete", __func__, __LINE__);
    printf("\n");
    gps_i_neighbor_table_cleanup(table);
    printf("\n");


    const_result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> [%p]",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            const_result);
    printf("\n");

    gps_na_set(&na, 0x87654321);
    ret = gps_i_neighbor_table_delete(table, &na);
    DEBUG("delete %s: %" PRIi32, gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    gps_i_neighbor_table_print(table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after delete", __func__, __LINE__);
    printf("\n");
    gps_i_neighbor_table_cleanup(table);
    printf("\n");

    const_result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> [%p]",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            const_result);
    printf("\n");

    gps_i_neighbor_table_destroy(table);

}

struct rcu_param {
    struct gps_i_neighbor_table *table;
    struct gps_na nas[2];
    uint64_t start_time;

    volatile enum {
        STATE_WAIT,
        STATE_LOOKUP_1,
    } state;
};

static int
test_neighbor_table_rcu_slave_1(void *param) {
    DEBUG_HEAD();
    urcu_qsbr_register_thread();

    struct rcu_param *param_p = (struct rcu_param *) param;
    const struct gps_i_neighbor_info * results[RTE_DIM(param_p->nas)];
    uint32_t i;

    while (param_p->state != STATE_LOOKUP_1);
    DEBUG_TIME(param_p->start_time, "Entering lookup 1"); // time: 0s

    for (i = 0; i < RTE_DIM(param_p->nas); i++) {
        results[i] = gps_i_neighbor_table_lookup(param_p->table, param_p->nas + i);
        if (results[i] == NULL) FAIL("results[%d] == NULL", i);
        DEBUG_TIME(param_p->start_time, "USING %p port=%" PRIu16, results[i], results[i]->port);
    }
    rte_delay_ms(1000); // time 1s
    for (i = 0; i < RTE_DIM(param_p->nas); i++) {
        DEBUG_TIME(param_p->start_time, "Finish USING %p port=%" PRIu16, results[i], results[i]->port);
    }
    urcu_qsbr_quiescent_state();

    rte_delay_ms(100); // time 1.1s
    for (i = 0; i < RTE_DIM(param_p->nas); i++) {
        DEBUG_TIME(param_p->start_time, "Recheck %p port=%" PRIu16, results[i], results[i]->port);
    }

    for (i = 0; i < RTE_DIM(param_p->nas); i++) {
        results[i] = gps_i_neighbor_table_lookup(param_p->table, param_p->nas + i);
        if (results[i] == NULL) FAIL("results[%d] == NULL", i);
        DEBUG_TIME(param_p->start_time, "USING %p port=%" PRIu16, results[i], results[i]->port);
    }

    rte_delay_ms(1000); // time 2.1s

    for (i = 0; i < RTE_DIM(param_p->nas); i++) {
        DEBUG_TIME(param_p->start_time, "Finish USING %p port=%" PRIu16, results[i], results[i]->port);
    }

    urcu_qsbr_quiescent_state();

    rte_delay_ms(100); // time 2.2s

    for (i = 0; i < RTE_DIM(param_p->nas); i++) {
        DEBUG_TIME(param_p->start_time, "Recheck %p port=%" PRIu16, results[i], results[i]->port);
    }

    DEBUG_TIME(param_p->start_time, "EXIT!");
    return 0;
}

static void
test_neighbor_table_rcu_master(void) {
    DEBUG_HEAD();
    unsigned core_id = -1;
    struct gps_i_neighbor_info *data, *ret_data;
    struct gps_na na;
    struct rcu_param param = {.state = STATE_WAIT};
    gps_na_set(&param.nas[0], 0x12345678);
    gps_na_set(&param.nas[1], 0xdeadbeef);
    int32_t ret;
    uint32_t i;
    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

    if (rte_lcore_count() < 2) FAIL("Must have at least 2 cores.");

    param.table = gps_i_neighbor_table_create("rcu", 15, 32, rte_socket_id());
    if (param.table == NULL) FAIL("Cannot create table!");
    param.start_time = rte_get_timer_cycles();

    core_id = rte_get_next_lcore(core_id, 1, 0);
    rte_eal_remote_launch(test_neighbor_table_rcu_slave_1, &param, core_id);

    for (i = 0; i < RTE_DIM(param.nas); i++) {
        data = gps_i_neighbor_table_get_entry(param.table);
        if (data == NULL) FAIL("Cannot get data");
        data->port = i + 128;
        ret_data = gps_i_neighbor_table_set(param.table, &param.nas[i], data);
        DEBUG_TIME(param.start_time, "set %s->%s, ret=%p",
                gps_na_format(na_buf, sizeof (na_buf), &param.nas[i]),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                ret_data);
        if (ret_data != NULL) FAIL("ret_data should be NULL, but %p", ret_data);
    }
    gps_i_neighbor_table_print(param.table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after populate", __func__, __LINE__);

    param.state = STATE_LOOKUP_1;

    rte_delay_ms(500); // Time: 0.5s

    for (i = 0; i < RTE_DIM(param.nas); i++) {
        data = gps_i_neighbor_table_get_entry(param.table);
        if (data == NULL) FAIL("Cannot get data");
        data->port = i + 228;
        ret_data = gps_i_neighbor_table_set(param.table, &param.nas[i], data);
        DEBUG_TIME(param.start_time, "set %s->%s, ret=%p",
                gps_na_format(na_buf, sizeof (na_buf), &param.nas[i]),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                ret_data);
        if (ret_data != NULL) FAIL("ret_data should be NULL, but %p", ret_data);
    }
    gps_i_neighbor_table_print(param.table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after update", __func__, __LINE__);

    urcu_qsbr_synchronize_rcu(); // Time: 1s

    DEBUG_TIME(param.start_time, "Cleanup");
    gps_i_neighbor_table_cleanup(param.table);


    for (i = 0; i < RTE_DIM(param.nas); i++) {
        data = gps_i_neighbor_table_get_entry(param.table);
        if (data == NULL) FAIL("Cannot get data");
        data->port = i + 328;
        gps_na_set(&na, i);
        ret_data = gps_i_neighbor_table_set(param.table, &na, data);
        DEBUG_TIME(param.start_time, "set %s->%s, ret=%p",
                gps_na_format(na_buf, sizeof (na_buf), &param.nas[i]),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                ret_data);
        if (ret_data != NULL) FAIL("ret_data should be NULL, but %p", ret_data);
    }
    gps_i_neighbor_table_print(param.table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after add", __func__, __LINE__);


    rte_delay_ms(200); // Time 1.2s
    ret = gps_i_neighbor_table_delete(param.table, param.nas + 0);
    DEBUG_TIME(param.start_time, "delete %s, ret=%" PRIi32,
            gps_na_format(na_buf, sizeof (na_buf), param.nas + 0),
            ret);
    gps_i_neighbor_table_print(param.table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after delete", __func__, __LINE__);

    urcu_qsbr_synchronize_rcu(); // Time: 2.1s
    gps_i_neighbor_table_cleanup(param.table);
    gps_i_neighbor_table_print(param.table, stdout, "TEST_NEIGHBOR_TABLE [%s():%d] after cleanup", __func__, __LINE__);

    RTE_LCORE_FOREACH_SLAVE(core_id) {
        rte_eal_wait_lcore(core_id);
    }

    gps_i_neighbor_table_destroy(param.table);
}

void
test_neighbor_table(void) {
    dump_mem("dmp_test_neighbor_table_0.txt");
    test_neighbor_table_basic_1();
    dump_mem("dmp_test_neighbor_table_1.txt");
    test_neighbor_table_basic_2();
    dump_mem("dmp_test_neighbor_table_2.txt");
    test_neighbor_table_rcu_master();
    dump_mem("dmp_test_neighbor_table_3.txt");
}

