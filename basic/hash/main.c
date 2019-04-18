//#define URCU_INLINE_SMALL_FUNCTIONS
//#define _LGPL_SOURCE

#include <inttypes.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_cpuflags.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include "rte_hash.h"
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <stdbool.h>

#define HASH_ENTRIES (16)
#define TEST_HASH_START (15)
#define TEST_HASH_END (16)

static int positions[HASH_ENTRIES + 1];

static uint32_t my_hash_int(const void *key, __rte_unused uint32_t key_len, uint32_t init_val) {
    const uint32_t i_key = *((const uint32_t *) key);
    return (i_key + (i_key << 17)) +init_val;
}

static void
test_hash(void) {
    struct rte_hash_x *table;

    struct rte_hash_parameters params = {
        .entries = HASH_ENTRIES,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
        //        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD,
        //        .extra_flag = RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD | RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL,
        //        .extra_flag = RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL,
        .hash_func = my_hash_int,
        .hash_func_init_val = 100,
        .key_len = sizeof (uint32_t),
        .name = "test_hash",
        .socket_id = rte_socket_id()
    };
    uint32_t i;
    uint32_t *key;
    uintptr_t val, *orig_val = NULL; 
    int32_t ret;

    printf("socket id=%u\n", rte_socket_id());
    table = rte_hash_create_x(&params);
    if (table == NULL) {
        rte_exit(EXIT_FAILURE, "%s:%d %s(): Cannot create hash table!", __FILE__, __LINE__, __FUNCTION__);
    }

    for (i = 0, val = i + HASH_ENTRIES; i <= HASH_ENTRIES; i++, val--) {
        positions[i] = rte_hash_add_key_data_x(table, &i, (void *)val, (void **)&orig_val);
        printf("Added %" PRIu32 "->0x%" PRIxPTR " to table, ret=%" PRIi32 ", orig=%p\n", i, val, positions[i], orig_val);
        positions[i] = rte_hash_add_key_data_x(table, &i, (void *)(val + 1), (void **)&orig_val);
        printf("Added %" PRIu32 "->0x%" PRIxPTR " to table, ret=%" PRIi32 ", orig=%p\n", i, val + 1, positions[i], orig_val);
        positions[i] = rte_hash_add_key_data_x(table, &i, (void *)(val + 2), (void **)&orig_val);
        printf("Added %" PRIu32 "->0x%" PRIxPTR " to table, ret=%" PRIi32 ", orig=%p\n", i, val + 2, positions[i], orig_val);
    }
    printf("\n Current Count=%" PRIu32 "\n\n", rte_hash_count_x(table));
    
    ret = rte_hash_get_key_with_position_x(table, positions[HASH_ENTRIES - 1], (void **) &key);
    printf("get key with position %d=%d, tmp=%p (%" PRIu32 ")\n", positions[HASH_ENTRIES - 1], ret, key, *key);
    ret = rte_hash_get_key_with_position_x(table, positions[0], (void **) &key);
    printf("get key with position %d=%d, tmp=%p (%" PRIu32 ")\n", positions[0], ret, key, *key);
    ret = rte_hash_get_key_with_position_x(table, HASH_ENTRIES, (void **) &key);
    printf("get key with position %d=%d, tmp=%p\n", HASH_ENTRIES, ret, key);

    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup_data_x(table, &i, (void **)&orig_val);
        printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 ", pos=%d, val=%p\n", i, ret, positions[i], orig_val);
    }
    printf("\n**********TEST RTE_HASH_DEL_KEY************\n");

    for (i = TEST_HASH_START; i < TEST_HASH_END; i++) {
        ret = rte_hash_del_key_x(table, &i);
        printf("Deleted %" PRIu32 " from table, ret=%" PRIi32 "\n", i, ret);
        ret = rte_hash_get_key_with_position_x(table, ret, (void **) &key);
        printf("get key with position=%d, tmp=%p %" PRIu32 "\n", ret, key, *key);
    }
    printf("\n Current Count=%" PRIu32 "\n\n", rte_hash_count_x(table));

    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup_data_x(table, &i, (void **)&orig_val);
        printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 ", pos=%d, val=%p\n", i, ret, positions[i], orig_val);
    }

    return;
    printf(" New Hash Count(After del)=%d\n", rte_hash_count_x(table));
    printf("**********************\n");
#if 0
    i = 3;
    ret = rte_hash_lookup_x(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);

    i = 7;
    ret = rte_hash_lookup_x(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
#endif

    for (i = TEST_HASH_START; i < TEST_HASH_END; i++) {
        ret = rte_hash_add_key_x(table, &i);
        printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    }

    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup_x(table, &i);
        printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
    }
    printf(" New Hash Count(After add)=%d\n", rte_hash_count_x(table));
    printf("**********************\n");
#if 0
    ret = rte_hash_add_key_x(table, &i);
    printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    printf("Current Count=%d\n", rte_hash_count_x(table));
#endif
    printf("\n**********TEST_FREE_KEY_WITH_POS************\n");

    for (i = TEST_HASH_START; i < TEST_HASH_END; i++) {
        ret = rte_hash_free_key_with_position_x(table, positions[i]);
        printf("Freed  key at position %" PRIu32 " from table, ret=%" PRIi32 "\n", positions[i], ret);
    }
    printf("Hash Count (After free)=%d\n", rte_hash_count_x(table));

    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup_x(table, &i);
        printf("Lookup for %" PRIu32 " in table, ret=%" PRIi32 "\n", i, ret);
    }
#if 0
    i = 4;
    ret = rte_hash_lookup_x(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);

    i = 3;
    ret = rte_hash_lookup_x(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
#if 0
    i = 2;
    ret = rte_hash_lookup_x(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
#endif

#endif

    printf("\n**********TEST RTE_HASH_ADD_KEY DUPLICATE KEYS************\n");
    for (i = TEST_HASH_START; i < TEST_HASH_END; i++) {
        ret = rte_hash_add_key_x(table, &i);
        printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    }
    printf(" New Hash Count(After add)=%d\n", rte_hash_count_x(table));
    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup_x(table, &i);
        printf("Lookup for %" PRIu32 " in table, ret=%" PRIi32 "\n", i, ret);
    }

    printf("\n**********TEST RTE_HASH_ADD_KEY ONE MORE ENTRY************\n");
    i = HASH_ENTRIES;
    ret = rte_hash_add_key_x(table, &i);
    printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    printf(" New Hash Count(After add)=%d\n", rte_hash_count_x(table));
    for (i = 0; i < HASH_ENTRIES + 1; i++) {
        ret = rte_hash_lookup_x(table, &i);
        printf("Lookup for %" PRIu32 " in table, ret=%" PRIi32 "\n", i, ret);
    }

    printf("**********************\n\n");
#if 0
    i = 3;
    ret = rte_hash_add_key_x(table, &i);
    printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    printf(" New Hash Count=%d\n", rte_hash_count_x(table));

    i = 2;
    ret = rte_hash_add_key_x(table, &i);
    printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    printf(" New Hash Count=%d\n", rte_hash_count_x(table));
#endif
}

//static struct rte_hash *table;
//static uint64_t start_time;
//
//static __rte_always_inline double
//time_since_start(void) {
//    return (rte_get_timer_cycles() - start_time) / ((double) rte_get_timer_hz());
//}
//#define DEBUG(...) DEBUG_(__VA_ARGS__, "dummy")
//#define DEBUG_(str, ...) printf("[%.6f] %d: " str "%.0s", time_since_start(), __LINE__, __VA_ARGS__)
//#define FAIL(...) FAIL_(__VA_ARGS__, "dummy")
//#define FAIL_(str, ...) rte_exit(EXIT_FAILURE, "[%.6f] %d: " str "%.0s", time_since_start(), __LINE__, __VA_ARGS__)
//
//struct my_struct {
//    int val;
//    struct rcu_head head;
//};
//
//static volatile enum state {
//    STATE_WAIT,
//    STATE_ADD,
//    STATE_UPDATE,
//    STATE_UPDATE_MID,
//    STATE_UPDATE_MID2,
//    STATE_UPDATE_FINISH,
//    STATE_DELETE,
//} curr_state = STATE_WAIT;
//static volatile bool finish = false;
//
//static struct my_struct *add1, *add2;
//
//static int
//test_hash_rcu_slave1(__rte_unused void *params) {
//    printf("\n==== %s:%d %s ====\n", __FILE__, __LINE__, __FUNCTION__);
//    DEBUG("S1 lcore=%u, socket id=%u\n", rte_lcore_id(), rte_socket_id());
//    urcu_qsbr_register_thread();
//    struct my_struct *ms;
//    uint32_t key;
//    int ret;
//    bool add_print = false;
//
//    while (!finish) {
//        switch (curr_state) {
//            default:
//                break;
//            case STATE_ADD:
//                key = 3;
//                ret = rte_hash_lookup_data(table, &key, (void **) &ms);
//                if (ret == -ENOENT)
//                    break;
//                if (ms != add1) {
//                    FAIL("S1 ADD ms=%p, add1=%p\n", ms, add1);
//                } else if (!add_print) {
//                    DEBUG("S1 ADD ms(%p)=add1(%p)\n", ms, add1);
//                    add_print = true;
//                }
//                break;
//            case STATE_UPDATE:
//                key = 3;
//                DEBUG("S1 UPDATE enter lock!\n");
//                urcu_qsbr_read_lock();
//                ret = rte_hash_lookup_data(table, &key, (void **) &ms);
//                if (ret == -ENOENT)
//                    FAIL("S1 UPDATE Lookup failure!\n");
//                if (ms != add1)
//                    FAIL("S1 UPDATE Wrong lookup value! ms=%p, add1=%p, add2=%p\n", ms, add1, add2);
//
//                DEBUG("S1 UPDATE ms=%p, add1=%p, add2=%p, wait 3s\n", ms, add1, add2);
//                rte_delay_ms(3000);
//                DEBUG("S1 UPDATE ms=%p, add1=%p, add2=%p\n", ms, add1, add2);
//                urcu_qsbr_read_unlock();
//                DEBUG("S1 UPDATE exit lock!.\n");
//                curr_state = STATE_UPDATE_MID;
//                break;
//            case STATE_UPDATE_MID:
//                key = 3;
//                DEBUG("S1 UPDATE2 enter lock!\n");
//                urcu_qsbr_read_lock();
//                ret = rte_hash_lookup_data(table, &key, (void **) &ms);
//                if (ret == -ENOENT)
//                    FAIL("S1 UPDATE2 Lookup failure! \n");
//                if (ms != add2)
//                    FAIL("S1 UPDATE Wrong lookup value! ms=%p, add1=%p, add2=%p\n", ms, add1, add2);
//                DEBUG("S1 UPDATE2 ms=%p, add1=%p, add2=%p, wait 3s\n", ms, add1, add2);
//                rte_delay_ms(3000);
//                DEBUG("S1 UPDATE2 ms=%p, add1=%p, add2=%p\n", ms, add1, add2);
//
//                urcu_qsbr_read_unlock();
//                DEBUG("S1 UPDATE2 exit lock!.\n");
//                break;
//            case STATE_UPDATE_MID2:
//                curr_state = STATE_UPDATE_FINISH;
//                break;
//        }
//
//        urcu_qsbr_quiescent_state();
//    }
//
//    DEBUG("S1 urcu_qsbr_barrier...\n");
//    urcu_qsbr_unregister_thread();
//    DEBUG("S1 exit...\n");
//}
//
//static int
//test_hash_rcu_slave2(__rte_unused void *params) {
//    printf("\n==== %s:%d %s ====\n", __FILE__, __LINE__, __FUNCTION__);
//    DEBUG("S2 lcore=%u, socket id=%u\n", rte_lcore_id(), rte_socket_id());
//    urcu_qsbr_register_thread();
//    struct my_struct *ms;
//    uint32_t key;
//    int ret;
//    
////    cds_lfht_new_flavor(1, 1, 0, CDS_LFHT_AUTO_RESIZE, &urcu_qsbr_flavor,  NULL);
//
//    while (!finish) {
//        switch (curr_state) {
//            default:
//                break;
//            case STATE_UPDATE:
//                key = 3;
//                DEBUG("S2 UPDATE enter lock!\n");
//                urcu_qsbr_read_lock();
//                ret = rte_hash_lookup_data(table, &key, (void **) &ms);
//                if (ret == -ENOENT)
//                    FAIL("S2 UPDATE Lookup failure!\n");
//                if (ms != add1)
//                    FAIL("S2 UPDATE Wrong lookup value! ms=%p, add1=%p, add2=%p\n", ms, add1, add2);
//
//                DEBUG("S2 UPDATE ms=%p, add1=%p, add2=%p, wait 5s\n", ms, add1, add2);
//                rte_delay_ms(5000);
//                DEBUG("S2 UPDATE ms=%p, add1=%p, add2=%p\n", ms, add1, add2);
//
//                urcu_qsbr_read_unlock();
//                DEBUG("S2 UPDATE exit lock!.\n");
//                break;
//            case STATE_UPDATE_MID:
//                key = 3;
//                DEBUG("S2 UPDATE2 enter lock!\n");
//                urcu_qsbr_read_lock();
//                ret = rte_hash_lookup_data(table, &key, (void **) &ms);
//                if (ret == -ENOENT)
//                    FAIL("S2 UPDATE2 Lookup failure! \n");
//                if (ms != add2)
//                    FAIL("S2 UPDATE Wrong lookup value! ms=%p, add1=%p, add2=%p\n", ms, add1, add2);
//                DEBUG("S2 UPDATE2 ms=%p, add1=%p, add2=%p, wait 8s\n", ms, add1, add2);
//                rte_delay_ms(8000);
//                DEBUG("S2 UPDATE2 ms=%p, add1=%p, add2=%p\n", ms, add1, add2);
//
//                urcu_qsbr_read_unlock();
//                DEBUG("S2 UPDATE2 exit lock!.\n");
//                curr_state = STATE_UPDATE_MID2;
//                break;
//        }
//        urcu_qsbr_quiescent_state();
//    }
//
//    DEBUG("S2 urcu_qsbr_barrier...\n");
//    urcu_qsbr_unregister_thread();
//    DEBUG("S2 exit...\n");
//}
//
//static void free_entry(struct rcu_head *head) {
//    struct my_struct *to_free = container_of(head, struct my_struct, head);
//    DEBUG("Run free entry %p, lcore=%u.\n", to_free, rte_lcore_id());
//    rte_free(to_free);
//}
//
//static int
//test_hash_rcu_master(__rte_unused void *dummy) {
//    printf("\n==== %s:%d %s ====\n", __FILE__, __LINE__, __FUNCTION__);
//    DEBUG("M lcore=%u, socket id=%u\n", rte_lcore_id(), rte_socket_id());
//    int ret = 0;
//    uint32_t key;
//
//    struct rte_hash_parameters params = {
//        .entries = HASH_ENTRIES,
//        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
//        .hash_func = my_hash_int,
//        .hash_func_init_val = 100,
//        .key_len = sizeof (uint32_t),
//        .name = "test_hash",
//        .socket_id = rte_socket_id()
//    };
//
//    //    urcu_qsbr_register_thread();
//
//    table = rte_hash_create(&params);
//    if (table == NULL) {
//        DEBUG("M Failed to create table.\n");
//        ret = -1;
//        goto cleanup;
//    }
//
//    // Add an entry to the table
//    key = 3;
//    DEBUG("M Add data.\n");
//    rcu_set_pointer(&add1, (struct my_struct *) rte_malloc_socket("add1", sizeof (struct my_struct), 0, rte_socket_id()));
//    if (add1 == NULL) {
//        DEBUG("M Failed to malloc add1.\n");
//        ret = -2;
//        goto cleanup;
//    }
//    DEBUG("M add1=%p\n", add1);
//    curr_state = STATE_ADD;
//    rte_hash_add_key_data(table, &key, add1);
//    rte_delay_ms(1000);
//
//
//    curr_state = STATE_UPDATE;
//    DEBUG("M wait for .5s to update!\n");
//    rte_delay_ms(500);
//    add2 = (struct my_struct *) rte_malloc_socket("add2", sizeof (struct my_struct), 0, rte_socket_id());
//    if (add2 == NULL) {
//        DEBUG("M Failed to malloc add2.\n");
//        ret = -3;
//        goto cleanup;
//    }
//    DEBUG("M add2=%p\n", add2);
//    struct my_struct *tmp;
//
//
//    DEBUG("M perform update!\n");
//
//    ret = rte_hash_lookup_data(table, &key, (void **) &tmp);
//    if (tmp != add1) {
//        DEBUG("M Lookup failure! tmp=%p, add1=%p, add2=%p\n", tmp, add1, add2);
//        ret = -4;
//        goto cleanup;
//    }
//    DEBUG("M Add key data %" PRIu32 " %p\n", key, add2);
//    rte_hash_add_key_data(table, &key, add2);
//    DEBUG("M schedule free entry%p.\n", tmp);
//    synchronize_rcu_qsbr();
//    free_entry(&tmp->head);
////        urcu_qsbr_call_rcu(&tmp->head, free_entry);
//
//    DEBUG("M waiting for UPDATE_FINISH\n");
//    while (curr_state != STATE_UPDATE_FINISH);
//    DEBUG("M NOW STATE_UPDATE_FINISH\n");
//    //        printf("%d: Sleep 1s.\n", __LINE__);
//    //        rte_delay_ms(1000);
//    //    }
//
//
//cleanup:
//
//
//    finish = true;
//    DEBUG("M urcu_qsbr_barrier...\n");
//    //    urcu_qsbr_unregister_thread();
//    DEBUG("M exit...\n");
//    return ret;
//}

int main(int argc, char **argv) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "%d: Invalid EAL parameters\n", __LINE__);
    argc -= ret;
    argv += ret;
    rte_log_set_global_level(RTE_LOG_DEBUG);

    //    unsigned lcore;
    //    if (rte_lcore_count() < 3) {
    //        rte_exit(EXIT_FAILURE, "%d: Need at least 2 cores!\n", __LINE__);
    //    }
    //    
    //    int enabled = rte_cpu_get_flag_enabled(RTE_CPUFLAG_RTM);
    //    printf("Transactional memory enabled: %d\n", enabled);
    //
    //    start_time = rte_get_timer_cycles();
    //
    //    lcore = -1;
    //    lcore = rte_get_next_lcore(lcore, 1, 0);
    //    rte_eal_remote_launch(test_hash_rcu_slave1, NULL, lcore);
    //
    //    lcore = rte_get_next_lcore(lcore, 1, 0);
    //    rte_eal_remote_launch(test_hash_rcu_slave2, NULL, lcore);
    //
    //
    //    test_hash_rcu_master(NULL);
    //
    //    RTE_LCORE_FOREACH_SLAVE(lcore) {
    //        rte_eal_wait_lcore(lcore);
    //    }


    test_hash();
    return 0;
}

