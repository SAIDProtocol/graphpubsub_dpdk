#include <inttypes.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <stdbool.h>

#define HASH_ENTRIES (16)
#define TEST_HASH_ENTRIES (10)

static uint32_t my_hash_int(const void *key, __rte_unused uint32_t key_len, uint32_t init_val) {
    return *((const uint32_t *) key) + init_val;
}

static void test_hash(void) {
    struct rte_hash *table;
    struct rte_hash_parameters params = {
        .entries = HASH_ENTRIES,
        //                .extra_flag = 0,
//        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
//        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL,
        .hash_func = my_hash_int,
        .hash_func_init_val = 100,
        .key_len = sizeof (uint32_t),
        .name = "test_hash",
        .socket_id = rte_socket_id()
    };
    uint32_t i;
    int32_t ret;

    printf("socket id=%u\n", rte_socket_id());
    table = rte_hash_create(&params);
    if (table == NULL) {
        rte_exit(EXIT_FAILURE, "%s:%d %s(): Cannot create hash table!", __FILE__, __LINE__, __FUNCTION__);
    }

    for (i = 0; i < HASH_ENTRIES + 1; i++) {
        ret = rte_hash_add_key(table, &i);
        printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    }

    printf("\n Current Count=%d\n", rte_hash_count(table));
    printf("\n**********TEST RTE_HASH_DEL_KEY************\n");
#if 0
    i = 3;
    ret = rte_hash_lookup(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);

    i = 2;
    ret = rte_hash_lookup(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);

#endif
    for (i = 3; i < TEST_HASH_ENTRIES; i++) {
        ret = rte_hash_del_key(table, &i);
        printf("Deleted %" PRIu32 " from table, ret=%" PRIi32 "\n", i, ret);
    }

    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup(table, &i);
        printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
    }
    printf(" New Hash Count(After del)=%d\n", rte_hash_count(table));
    printf("**********************\n");
#if 0
    i = 3;
    ret = rte_hash_lookup(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);

    i = 7;
    ret = rte_hash_lookup(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
#endif

    for (i = 3; i < TEST_HASH_ENTRIES; i++) {
        ret = rte_hash_add_key(table, &i);
        printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    }

    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup(table, &i);
        printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
    }
    printf(" New Hash Count(After add)=%d\n", rte_hash_count(table));
    printf("**********************\n");
#if 0
    ret = rte_hash_add_key(table, &i);
    printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    printf("Current Count=%d\n", rte_hash_count(table));
#endif
    printf("\n**********TEST_FREE_KEY_WITH_POS************\n");

    for (i = 3; i < TEST_HASH_ENTRIES; i++) {
        ret = rte_hash_free_key_with_position(table, i);
        printf("Freed  key at position %" PRIu32 " from table, ret=%" PRIi32 "\n", i, ret);
    }
    printf("Hash Count (After free)=%d\n", rte_hash_count(table));

    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup(table, &i);
        printf("Lookup for %" PRIu32 " in table, ret=%" PRIi32 "\n", i, ret);
    }
#if 0
    i = 4;
    ret = rte_hash_lookup(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);

    i = 3;
    ret = rte_hash_lookup(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
#if 0
    i = 2;
    ret = rte_hash_lookup(table, &i);
    printf("Lookup %" PRIu32 " on table, ret=%" PRIi32 "\n", i, ret);
#endif

#endif

    for (i = 3; i < TEST_HASH_ENTRIES; i++) {
        ret = rte_hash_add_key(table, &i);
        printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    }
    printf(" New Hash Count(After add)=%d\n", rte_hash_count(table));
    for (i = 0; i < HASH_ENTRIES; i++) {
        ret = rte_hash_lookup(table, &i);
        printf("Lookup for %" PRIu32 " in table, ret=%" PRIi32 "\n", i, ret);
    }
    printf("**********************\n\n");
#if 0
    i = 3;
    ret = rte_hash_add_key(table, &i);
    printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    printf(" New Hash Count=%d\n", rte_hash_count(table));

    i = 2;
    ret = rte_hash_add_key(table, &i);
    printf("Added %" PRIu32 " to table, ret=%" PRIi32 "\n", i, ret);
    printf(" New Hash Count=%d\n", rte_hash_count(table));
#endif
}

int main(int argc, char **argv) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    test_hash();

    return 0;
}

