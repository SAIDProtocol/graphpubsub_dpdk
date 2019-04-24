/* 
 * File:   test_neighbor_table.c
 * Author: Jiachen Chen
 *
 * Created on April 14, 2019, 2:56 AM
 */
#include <assert.h>
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <urcu-qsbr.h>
#include "gps_i_neighbor_table.h"

#define DEFAULT_NEIGHBOR_TABLE_SIZE 1023
#define DEFAULT_WRAP_SIZE 16
#define RTE_LOGTYPE_TEST_NEIGHBOR_TABLE RTE_LOGTYPE_USER1


#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, TEST_NEIGHBOR_TABLE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#define DEBUG_TIME(start, ...) _DEBUG_TIME(start, __VA_ARGS__, "dummy")
#define _DEBUG_TIME(start, fmt, ...) \
    RTE_LOG(INFO, TEST_NEIGHBOR_TABLE, "[%s():%d] %.6f " fmt "%.0s\n", \
        __FUNCTION__, __LINE__, \
        (rte_get_timer_cycles()- start) / ((float)rte_get_timer_hz()),  \
        __VA_ARGS__)
#define DEBUG_HEAD() printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__)

extern void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void test_neighbor_table(void);

static void
test_neighbor_table_basic(void) {
    DEBUG_HEAD();
    int32_t ret;

    struct gps_i_neighbor_table *table = gps_i_neighbor_table_create("test", 15, rte_socket_id());
    uint32_t i;
    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

    struct gps_i_neighbor_info *info;
    struct gps_na nas[4], *na_p, na;
    gps_na_set(nas + 0, 0xdeadbeef);
    gps_na_set(nas + 1, 0xabcdef01);
    gps_na_set(nas + 2, 0xbcdef012);
    gps_na_set(nas + 3, 0xcdef0123);

    for (i = 0;; i++) {
        info = gps_i_neighbor_table_get_entry(table);
        DEBUG("Get entry, info=%p, diff=%zd", info, info - table->values);
        if (info == NULL) break;
        info->port = (uint16_t) i;

        na_p = nas + (i % RTE_DIM(nas));
        ret = gps_i_neighbor_table_set(table, na_p, info);
        gps_i_neighbor_table_print_available(table, stdout);
        DEBUG("set %s->%s, ret=%" PRIi32 ", to_free=%" PRIu32,
                gps_na_format(na_buf, sizeof (na_buf), na_p),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info),
                ret, table->num_values_to_free);
        printf("\n");
    }
    printf("\n");

    DEBUG("Print table");
    gps_i_neighbor_table_print(table, stdout);
    printf("\n");

    for (i = 0; i < RTE_DIM(nas); i++) {
        gps_na_copy(&na, nas + i);
        info = gps_i_neighbor_table_lookup(table, &na);
        DEBUG("Lookup %s, ret=%s (%p)",
                gps_na_format(na_buf, sizeof (na_buf), &na),
                info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info),
                info);
    }


    for (i = 0; i < RTE_DIM(nas); i++) {
        na_p = nas + i;
        ret = gps_i_neighbor_table_delete(table, na_p);
        DEBUG("delete %s, ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), na_p),
                ret);
    }

    DEBUG("Print table");
    gps_i_neighbor_table_print(table, stdout);
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_print_keys_to_free(table, stdout);
    printf("\n");

    gps_i_neighbor_table_cleanup(table);
    DEBUG("After cleanup:");
    gps_i_neighbor_table_print_available(table, stdout);



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
    struct gps_i_neighbor_info *result;
    struct gps_na na;
    gps_na_set(&na, 0x12345678);

    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    struct ether_addr addr2 = {.addr_bytes =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    int32_t ret;
    struct gps_i_neighbor_table *table;

    DEBUG("buf=%s\n", gps_i_neighbor_info_format(info_buf, sizeof (info_buf), &info));
    print_buf(&info, sizeof (info), 16);

    table = gps_i_neighbor_table_create("test 2", 15, rte_socket_id());
    assert(table != NULL);
    DEBUG("table=%p\n", table);
    gps_i_neighbor_table_print(table, stdout);

    result = gps_i_neighbor_table_get_entry(table);
    assert(result != NULL);
    rte_memcpy(result, &info, sizeof (struct gps_i_neighbor_info));
    DEBUG("result=%zd, %s\n", result - table->values, gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result));

    ret = gps_i_neighbor_table_set(table, &na, result);
    DEBUG("set %s->%s: %" PRIi32 "\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result),
            ret);
    gps_i_neighbor_table_print(table, stdout);
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_cleanup(table);
    DEBUG("After cleanup");
    gps_i_neighbor_table_print_available(table, stdout);

    info.ip = IPv4(192, 168, 1, 2);
    info.port = 1234;
    rte_memcpy(&info.ether, &addr2, sizeof (struct ether_addr));


    result = gps_i_neighbor_table_get_entry(table);
    assert(result != NULL);
    rte_memcpy(result, &info, sizeof (struct gps_i_neighbor_info));
    DEBUG("result=%zd, %s\n", result - table->values, gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result));

    ret = gps_i_neighbor_table_set(table, &na, result);
    DEBUG("set %s->%s: %" PRIi32 "\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result),
            ret);
    gps_i_neighbor_table_print(table, stdout);
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_cleanup(table);
    DEBUG("After cleanup");
    gps_i_neighbor_table_print_available(table, stdout);

    memset(&info.ether, 0x39, sizeof (info.ether));
    info.port = 7890;
    gps_na_set(&na, 0x87654321);

    info.use_ip = false;
    result = gps_i_neighbor_table_get_entry(table);
    assert(result != NULL);
    rte_memcpy(result, &info, sizeof (struct gps_i_neighbor_info));
    DEBUG("result=%zd, %s\n", result - table->values, gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result));


    ret = gps_i_neighbor_table_set(table, &na, result);
    DEBUG("set %s->%s: %" PRIi32 "\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result),
            ret);
    gps_i_neighbor_table_print(table, stdout);
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_cleanup(table);
    DEBUG("After cleanup");
    gps_i_neighbor_table_print_available(table, stdout);

    gps_na_set(&na, 0x12345678);
    result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> [%p,%zd] %s\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result, result - table->values,
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result));

    gps_na_set(&na, 0x87654321);
    result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> [%p,%zd] %s\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result, result - table->values,
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result));

    gps_na_set(&na, 0x77654321);
    result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> [%p]\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result);

    ret = gps_i_neighbor_table_delete(table, &na);
    DEBUG("delete %s: %" PRIi32 "\n", gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    gps_i_neighbor_table_print(table, stdout);
    gps_i_neighbor_table_print_available(table, stdout);

    gps_na_set(&na, 0x12345678);
    ret = gps_i_neighbor_table_delete(table, &na);
    DEBUG("delete %s: %" PRIi32 "\n", gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    gps_i_neighbor_table_print(table, stdout);
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_print_keys_to_free(table, stdout);
    gps_i_neighbor_table_cleanup(table);
    DEBUG("After cleanup");
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_print_keys_to_free(table, stdout);


    result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> [%p] \n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result);

    gps_na_set(&na, 0x87654321);
    ret = gps_i_neighbor_table_delete(table, &na);
    DEBUG("delete %s: %" PRIi32 "\n", gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    gps_i_neighbor_table_print(table, stdout);
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_print_keys_to_free(table, stdout);
    gps_i_neighbor_table_cleanup(table);
    DEBUG("After cleanup");
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_print_keys_to_free(table, stdout);

    result = gps_i_neighbor_table_lookup(table, &na);
    DEBUG("lookup %s -> [%p] \n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result);

    gps_i_neighbor_table_cleanup(table);
    gps_i_neighbor_table_print(table, stdout);
    gps_i_neighbor_table_print_available(table, stdout);
    gps_i_neighbor_table_print_keys_to_free(table, stdout);

    //    gps_i_neighbor_table_destroy(table);

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
    struct gps_i_neighbor_info * results[RTE_DIM(param_p->nas)];
    uint32_t i;

    while (param_p->state != STATE_LOOKUP_1);
    DEBUG_TIME(param_p->start_time, "Entering lookup 1"); // time: 0s

    for (i = 0; i < RTE_DIM(param_p->nas); i++) {
        results[i] = gps_i_neighbor_table_lookup(param_p->table, param_p->nas + i);
        assert(results[i] != NULL);
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
        assert(results[i] != NULL);
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
    struct gps_i_neighbor_info *data;
    struct gps_na na;
    struct rcu_param param = {.state = STATE_WAIT};
    gps_na_set(&param.nas[0], 0x12345678);
    gps_na_set(&param.nas[1], 0xdeadbeef);
    int32_t ret;
    uint32_t i;
    param.table = gps_i_neighbor_table_create("test rcu", 15, rte_socket_id());
    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

    if (rte_lcore_count() < 2)
        rte_exit(EXIT_FAILURE, "Must have 2 cores.\n");

    param.start_time = rte_get_timer_cycles();
    core_id = rte_get_next_lcore(core_id, 1, 0);
    rte_eal_remote_launch(test_neighbor_table_rcu_slave_1, &param, core_id);

    for (i = 0; i < RTE_DIM(param.nas); i++) {
        data = gps_i_neighbor_table_get_entry(param.table);
        assert(data != NULL);
        data->port = i + 128;
        ret = gps_i_neighbor_table_set(param.table, &param.nas[i], data);
        DEBUG_TIME(param.start_time, "set %s->%s, ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), &param.nas[i]),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                ret);
        assert(ret >= 0);
    }
    gps_i_neighbor_table_print(param.table, stdout);
    gps_i_neighbor_table_print_available(param.table, stdout);
    gps_i_neighbor_table_print_keys_to_free(param.table, stdout);

    param.state = STATE_LOOKUP_1;

    rte_delay_ms(500); // Time: 0.5s

    for (i = 0; i < RTE_DIM(param.nas); i++) {
        data = gps_i_neighbor_table_get_entry(param.table);
        assert(data != NULL);
        data->port = i + 228;
        ret = gps_i_neighbor_table_set(param.table, &param.nas[i], data);
        DEBUG_TIME(param.start_time, "set %s->%s, ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), &param.nas[i]),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                ret);
        assert(ret >= 0);
    }
    gps_i_neighbor_table_print(param.table, stdout);
    gps_i_neighbor_table_print_available(param.table, stdout);
    gps_i_neighbor_table_print_keys_to_free(param.table, stdout);

    urcu_qsbr_synchronize_rcu(); // Time: 1s

    gps_i_neighbor_table_cleanup(param.table);
    DEBUG_TIME(param.start_time, "After cleanup:");
    gps_i_neighbor_table_print(param.table, stdout);
    gps_i_neighbor_table_print_available(param.table, stdout);
    gps_i_neighbor_table_print_keys_to_free(param.table, stdout);

    for (i = 0; i < RTE_DIM(param.nas); i++) {
        data = gps_i_neighbor_table_get_entry(param.table);
        assert(data != NULL);
        data->port = i + 328;
        gps_na_set(&na, i);
        ret = gps_i_neighbor_table_set(param.table, &na, data);
        DEBUG_TIME(param.start_time, "set %s->%s, ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), &param.nas[i]),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                ret);
        assert(ret >= 0);
    }
    gps_i_neighbor_table_print(param.table, stdout);
    gps_i_neighbor_table_print_available(param.table, stdout);
    gps_i_neighbor_table_print_keys_to_free(param.table, stdout);

    rte_delay_ms(200); // Time 1.2s
    ret = gps_i_neighbor_table_delete(param.table, param.nas + 0);
    DEBUG_TIME(param.start_time, "delete %s, ret=%" PRIi32,
            gps_na_format(na_buf, sizeof (na_buf), param.nas + 0),
            ret);

    urcu_qsbr_synchronize_rcu(); // Time: 2.1s
    gps_i_neighbor_table_cleanup(param.table);
    DEBUG_TIME(param.start_time, "After cleanup:");
    gps_i_neighbor_table_print(param.table, stdout);
    gps_i_neighbor_table_print_available(param.table, stdout);
    gps_i_neighbor_table_print_keys_to_free(param.table, stdout);

    data = gps_i_neighbor_table_get_entry(param.table);
    data->port = 428;

    RTE_LCORE_FOREACH_SLAVE(core_id) {
        rte_eal_wait_lcore(core_id);
    }

    gps_i_neighbor_table_destroy(param.table);
}

void
test_neighbor_table(void) {
    test_neighbor_table_basic();
    test_neighbor_table_basic_2();
    test_neighbor_table_rcu_master();
}