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

//#define GPS_I_NEIGHBOR_TABLE_DEBUG

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
#include <rte_log.h>

#define RTE_LOGTYPE_NEIGHBOR_TABLE RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy");
#define _DEBUG(fmt, ...) RTE_LOG(INFO, NEIGHBOR_TABLE, "[%s():%d] " fmt "%.0s\n", __FUNCTION__, __LINE__, __VA_ARGS__)
#endif

struct gps_i_neighbor_table *
gps_i_neighbor_table_create(const char *type, uint32_t entries, unsigned socket_id) {
    struct gps_i_neighbor_table *ret = NULL;
    struct rte_hash_parameters_x params = {
        .entries = entries,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .key_len = sizeof (struct gps_na),
        .name = type,
        .reserved = 0,
        .socket_id = socket_id
    };
    uint32_t value_entries = entries + NEIGHBOR_TABLE_ENTRIES_EXTRA;
    uint32_t available_entries = value_entries + NEIGHBOR_TABLE_ENTRIES_PADDING;
    uint32_t i;

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    DEBUG("entries=%" PRIu32 ", value_entries=%" PRIu32 ", available_entries=%" PRIu32,
            entries, value_entries, available_entries);
#endif

    ret = rte_zmalloc_socket(type, sizeof (struct gps_i_neighbor_table), RTE_CACHE_LINE_SIZE, socket_id);
    if (ret == NULL) goto fail;
    ret->entries = entries;
    ret->num_values_available = value_entries;


    ret->keys = rte_hash_create_x(&params);
    if (ret->keys == NULL) goto fail;

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    DEBUG("table->keys=%p", ret->keys);
#endif

    ret->values = (struct gps_i_neighbor_info *) rte_malloc_socket(
            type, sizeof (struct gps_i_neighbor_info) * value_entries, RTE_CACHE_LINE_SIZE, socket_id);
    if (ret->values == NULL) goto fail;

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    DEBUG("table->values=%p", ret->values);
#endif

    ret->keys_to_free = (int32_t *) rte_malloc_socket(type, sizeof (int32_t) * entries, RTE_CACHE_LINE_SIZE, socket_id);
    if (ret->keys_to_free == NULL) goto fail;

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    DEBUG("table->keys_to_free=%p", ret->keys_to_free);
#endif

    ret->values_available = (int32_t *) rte_malloc_socket(type, sizeof (int32_t) * available_entries, RTE_CACHE_LINE_SIZE, socket_id);
    if (ret->values_available == NULL) goto fail;

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    DEBUG("table->values_available=%p", ret->values_available);
#endif

    for (i = 0; i < value_entries; i++)
        ret->values_available[i] = (int32_t) i;

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    gps_i_neighbor_table_print_available(ret, stdout);
#endif

    return ret;

fail:
    gps_i_neighbor_table_destroy(ret);
    return NULL;
}

void
gps_i_neighbor_table_destroy(struct gps_i_neighbor_table * table) {
    if (table != NULL) {
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
        DEBUG("freeing keys=%p, values=%p, keys_to_free=%p, values_available=%p",
                table->keys, table->values, table->keys_to_free, table->values_available);
#endif
        if (table->keys != NULL)
            rte_hash_free_x(table->keys);

        if (table->values != NULL)
            rte_free(table->values);

        if (table->keys_to_free != NULL)
            rte_free(table->keys_to_free);

        if (table->values_available != NULL)
            rte_free(table->values_available);

        memset(table, 0, sizeof (*table));

        rte_free(table);
    }
}

struct gps_i_neighbor_info *
gps_i_neighbor_table_get_entry(struct gps_i_neighbor_table *table) {
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    if (table->num_values_available == 0) {
        DEBUG("No available slots in table.");
    } else {
        DEBUG("return %" PRIi32 ".", table->values_available[table->num_values_available - 1]);
    }
#endif
    return (table->num_values_available == 0) ?
            NULL :
            (table->values + table->values_available[--table->num_values_available]);
}

static __rte_always_inline void
__gps_i_neighbor_table_return_entry(struct gps_i_neighbor_table *table,
        struct gps_i_neighbor_info *entry) {
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    DEBUG("Return entry: %zd", entry - table->values);
#endif
    table->values_available[table->num_values_available++] = (int32_t) (entry - table->values);
}

void
gps_i_neighbor_table_return_entry(struct gps_i_neighbor_table *table,
        struct gps_i_neighbor_info *entry) {
    __gps_i_neighbor_table_return_entry(table, entry);
}

static __rte_always_inline void
__gps_i_neighbor_table_add_to_free(struct gps_i_neighbor_table *table,
        struct gps_i_neighbor_info *entry) {
    if (entry == NULL) return;
    uint32_t end = table->entries + NEIGHBOR_TABLE_ENTRIES_EXTRA + NEIGHBOR_TABLE_ENTRIES_PADDING;
    uint32_t to_add = end - (++table->num_values_to_free);
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    DEBUG("Add to free: %zd, at position: %" PRIu32, entry - table->values, to_add);
#endif
    table->values_available[to_add] = (int32_t) (entry - table->values);
}

int32_t
gps_i_neighbor_table_set(struct gps_i_neighbor_table * table,
        const struct gps_na *na, struct gps_i_neighbor_info *info) {
    struct gps_i_neighbor_info *val_orig;
    int32_t ret;

    ret = rte_hash_add_key_data_x(table->keys, na, info, (void **) &val_orig);
    if (ret < 0) return ret;

    // place the original entries to be freed
    __gps_i_neighbor_table_add_to_free(table, val_orig);

    return ret;
}

int32_t
gps_i_neighbor_table_delete(struct gps_i_neighbor_table * table,
        const struct gps_na *na) {
    int32_t ret;
    struct gps_i_neighbor_info *data;
    ret = rte_hash_del_key_x(table->keys, na, (void **) &data);
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    if (ret < 0) {
        DEBUG("delete key na=%s, ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), na),
                ret);
    } else {
        DEBUG("delete key na=%s, data=%s (%zd), ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), na),
                data == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                data - table->values,
                ret);
    }
#endif
    if (ret < 0) return ret;


    // Mark ret for to free
    table->keys_to_free[table->num_keys_to_free++] = ret;
    return ret;
}

void
gps_i_neighbor_table_cleanup(struct gps_i_neighbor_table * table) {
    uint32_t end = table->entries + NEIGHBOR_TABLE_ENTRIES_EXTRA + NEIGHBOR_TABLE_ENTRIES_PADDING;
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    char info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    struct gps_i_neighbor_info *data;
#endif

    // free values
    while (table->num_values_to_free > 0) {
        uint32_t id_to_free = end - (table->num_values_to_free--);
        uint32_t id_to_add = table->num_values_available++;
        table->values_available[id_to_add] = table->values_available[id_to_free];
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
        data = &table->values[table->values_available[id_to_free]];
        DEBUG("move value from %" PRIu32 " to %" PRIu32 ", slot at %" PRIi32 " %s (%zd)",
                id_to_free,
                id_to_add,
                table->values_available[id_to_free],
                data == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                data - table->values);
#endif
    }

    struct gps_i_neighbor_info *value;
    // free keys and corresponding values
    while (table->num_keys_to_free > 0) {
        int32_t key_to_free = table->keys_to_free[--table->num_keys_to_free];
        rte_hash_free_key_with_position_x(table->keys, key_to_free, (void **) &value);
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
        DEBUG("Free key at %" PRIi32 ", data=%s (%zd)",
                key_to_free,
                value == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), value),
                value - table->values);
#endif

        if (value != NULL) __gps_i_neighbor_table_return_entry(table, value);
    }
}
