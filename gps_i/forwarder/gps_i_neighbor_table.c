/* 
 * File:   gps_i_neighbor_table.c
 * Author: Jiachen Chen
 *
 * Created on April 14, 2019, 2:53 AM
 */

#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include "gps_i_neighbor_table.h"

#define NEIGHBOR_TABLE_ENTRIES_EXTRA 8

struct gps_i_neighbor_table *
gps_i_neighbor_table_create(const char *type, uint32_t entries, unsigned socket_id) {
    struct gps_i_neighbor_table *ret = NULL;
    struct rte_hash_parameters_x params = {
        .entries = entries,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .key_len = sizeof (struct gps_na),
        .name = NULL,
        .reserved = 0,
        .socket_id = socket_id
    };
    uint32_t value_entries = entries + NEIGHBOR_TABLE_ENTRIES_EXTRA;
    uint32_t i;


    ret = rte_zmalloc_socket(type, sizeof (struct gps_i_neighbor_table), RTE_CACHE_LINE_SIZE, socket_id);
    if (ret == NULL) goto fail;
    ret->entries = entries;
    //    No need, zeroed the whole structure.
    //    ret->num_keys_to_free = 0;

    ret->keys = rte_hash_create_x(&params);
    if (ret->keys == NULL) goto fail;

    ret->values = (struct gps_i_neighbor_table_value *) rte_malloc_socket(
            NULL, sizeof (struct gps_i_neighbor_table_value) * value_entries, RTE_CACHE_LINE_SIZE, socket_id);
    if (ret->values == NULL) goto fail;

    ret->keys_to_free = (int32_t *) rte_malloc_socket(NULL, sizeof (int32_t) * entries, RTE_CACHE_LINE_SIZE, socket_id);
    if (ret->keys_to_free == NULL) goto fail;

    LINUX_INIT_LIST_HEAD(&ret->values_available);

    for (i = 0; i < value_entries; i++) {
        linux_list_add_tail(&ret->values[i].available_list, &ret->values_available);
    }

    return ret;

fail:
    gps_i_neighbor_table_destroy(ret);
    return NULL;
}

void
gps_i_neighbor_table_destroy(struct gps_i_neighbor_table * table) {
    if (table != NULL) {
        if (table->keys != NULL)
            rte_hash_free_x(table->keys);
        table->keys = NULL;

        if (table->values != NULL)
            rte_free(table->values);
        table->values = NULL;

        if (table->keys_to_free != NULL)
            rte_free(table->keys_to_free);
        table->keys_to_free = NULL;

        rte_free(table);
    }
}

struct gps_i_neighbor_info *
gps_i_neighbor_table_get_entry(struct gps_i_neighbor_table *table) {
    struct linux_list_head *pos;

    pos = table->values_available.next;
    // empty list
    if (pos == &table->values_available) return NULL;
    linux_list_del(pos);

    return &container_of(pos, struct gps_i_neighbor_table_value, available_list)->value;
}

void
gps_i_neighbor_table_return_entry(struct gps_i_neighbor_table *table,
        struct gps_i_neighbor_info *entry) {
    struct linux_list_head *pos;

    pos = &container_of(entry, struct gps_i_neighbor_table_value, value)->available_list;

    linux_list_add_tail(pos, &table->values_available);
}

int32_t
gps_i_neighbor_table_set(struct gps_i_neighbor_table * table,
        const struct gps_na *na, struct gps_i_neighbor_info *info) {
    struct gps_i_neighbor_table_value *val_add, *val_orig;
    int32_t ret;

    val_add = container_of(info, struct gps_i_neighbor_table_value, value);

    ret = rte_hash_add_key_data_x(table->keys, na, val_add, (void **) &val_orig);
    if (ret < 0) return ret;

    // place the original entries to be freed
    if (val_orig != NULL)
        linux_list_add_tail(&val_orig->available_list, &table->values_to_free);

    return ret;
}

int32_t
gps_i_neighbor_table_delete(struct gps_i_neighbor_table * table,
        const struct gps_na *na) {
    int32_t ret;
    ret = rte_hash_del_key_x(table->keys, na, NULL);
    if (ret < 0) return ret;

    // Mark ret for to free
    table->keys_to_free[table->num_keys_to_free++] = ret;
    return ret;
}

void
gps_i_neighbor_table_cleanup(struct gps_i_neighbor_table * table) {
    uint32_t i;
    struct gps_i_neighbor_table_value *value;
    struct linux_list_head *pos, *n;

    // free keys and corresponding values
    for (i = 0; i < table->num_keys_to_free; i++) {
        rte_hash_free_key_with_position_x(table->keys, table->keys_to_free[i], (void **)&value);
        linux_list_add_tail(&table->values_available, &value->available_list);
    }

    // free values
    linux_list_splice_tail_init(&table->values_to_free, &table->values_available);
}
