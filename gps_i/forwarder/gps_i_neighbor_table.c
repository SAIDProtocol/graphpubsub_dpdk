/* 
 * File:   gps_i_neighbor_table.c
 * Author: Jiachen Chen
 *
 * Created on April 14, 2019, 2:53 AM
 */

#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include "gps_i_neighbor_table.h"

//#define GPS_I_NEIGHBOR_TABLE_DEBUG

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
#include <rte_log.h>

#define RTE_LOGTYPE_NEIGHBOR_TABLE RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, NEIGHBOR_TABLE, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

struct gps_i_neighbor_table *
gps_i_neighbor_table_create(const char *type, uint32_t entries,
        unsigned value_slots, unsigned socket_id) {
    struct gps_i_neighbor_table *table = NULL;
    char tmp_name[RTE_MEMZONE_NAMESIZE];
    DEBUG("entries=%" PRIu32 ", values_to_free=%" PRIu32, entries, value_slots);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBTK_%s", type);
    DEBUG("name for key: %s", tmp_name);
    struct rte_hash_parameters_x params = {
        .entries = entries,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .key_len = sizeof (struct gps_na),
        .name = tmp_name,
        .reserved = 0,
        .socket_id = socket_id
    };

    table = rte_zmalloc_socket(type, sizeof (struct gps_i_neighbor_table),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (table == NULL) goto fail;

    table->keys = rte_hash_create_x(&params);
    if (unlikely(table->keys == NULL)) {
        DEBUG("fail to create keys, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->keys=%p", table->keys);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBTV_%s", type);
    DEBUG("name for values: %s", tmp_name);
    table->values = rte_mempool_create(tmp_name, value_slots, sizeof (struct gps_i_neighbor_info), 0, 0, NULL, NULL, NULL, NULL, rte_socket_id(), MEMPOOL_F_NO_CACHE_ALIGN | MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (unlikely(table->values == NULL)) {
        DEBUG("fail to create values, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->values=%p", table->values);


    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBTKF_%s", type);
    DEBUG("name for key_positions_to_free: %s", tmp_name);
    table->key_positions_to_free = rte_ring_create(tmp_name, entries + 1, socket_id, 0);
    if (unlikely(table->key_positions_to_free == NULL)) {
        DEBUG("fail to create key_positions_to_free, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->key_positions_to_free=%p", table->key_positions_to_free);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBTVF_%s", type);
    DEBUG("name for values_to_free: %s", tmp_name);
    table->values_to_free = rte_ring_create(tmp_name, value_slots, socket_id, 0);
    if (unlikely(table->values_to_free == NULL)) {
        DEBUG("fail to create values_to_free, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->values_to_free=%p", table->values_to_free);

    return table;

fail:
    if (table->keys != NULL) rte_hash_free_x(table->keys);
    if (table->values != NULL) rte_mempool_free(table->values);
    if (table->key_positions_to_free != NULL) rte_ring_free(table->key_positions_to_free);
    if (table->values_to_free != NULL) rte_ring_free(table->values_to_free);
    if (table != NULL) rte_free(table);
    return NULL;
}

void
gps_i_neighbor_table_destroy(struct gps_i_neighbor_table * table) {
    DEBUG("free table=%p, keys=%p, key_positions_to_free=%p, values_to_free=%p",
            table, table->keys, table->key_positions_to_free, table->values_to_free);
    rte_hash_free_x(table->keys);
    rte_mempool_free(table->values);
    rte_ring_free(table->key_positions_to_free);
    rte_ring_free(table->values_to_free);
    memset(table, 0, sizeof(*table));
    rte_free(table);
}

struct gps_i_neighbor_info *
gps_i_neighbor_table_get_entry(struct gps_i_neighbor_table *table) {
    struct gps_i_neighbor_info *ret;
    if (likely(rte_mempool_get(table->values, (void **) &ret) == 0)) {
        DEBUG("get entry: %p", ret);
        return ret;
    } else {
        DEBUG("Cannot get entry!");
        return NULL;
    }
}

static __rte_always_inline void
__gps_i_neighbor_table_return_entry(struct rte_mempool *mempool,
        struct gps_i_neighbor_info *entry) {
    DEBUG("return entry: %p", entry);
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    memset(entry, 0xBF, sizeof(*entry));
#endif
    rte_mempool_put(mempool, entry);

}

void
gps_i_neighbor_table_return_entry(struct gps_i_neighbor_table *table,
        struct gps_i_neighbor_info *entry) {
    __gps_i_neighbor_table_return_entry(table->values, entry);
}

struct gps_i_neighbor_info *
gps_i_neighbor_table_set(struct gps_i_neighbor_table * table,
        const struct gps_na *na, struct gps_i_neighbor_info *info) {
    struct gps_i_neighbor_info *val_orig;
    int32_t ret;
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE],
            orig_info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
#endif
    ret = rte_hash_add_key_data_x(table->keys, na, info, (void **) &val_orig);
    if (ret < 0) {
        DEBUG("add key na=%s, val=%s [%p], ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), na),
                info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info),
                info, ret);
        return info;
    } else {
        DEBUG("add key na=%s, val=%s [%p], ret=%" PRIi32 ", orig_val=%s [%p]",
                gps_na_format(na_buf, sizeof (na_buf), na),
                info == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info),
                info, ret,
                val_orig == NULL ? "" : gps_i_neighbor_info_format(orig_info_buf, sizeof (orig_info_buf), val_orig),
                val_orig);
        // place the original entries to be freed
        if (likely(val_orig != NULL)) {
            if (likely(rte_ring_enqueue(table->values_to_free, val_orig) == 0)) {
                DEBUG("add %p to values_to_free", val_orig);
                return NULL;
            } else {
                return val_orig;
            }
        } else {
            return NULL;
        }
    }
}

int32_t
gps_i_neighbor_table_delete(struct gps_i_neighbor_table * table,
        const struct gps_na *na) {
    int32_t ret;
    struct gps_i_neighbor_info *data;
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
#endif

    ret = rte_hash_del_key_x(table->keys, na, (void **) &data);
    if (ret < 0) {
        DEBUG("delete key na=%s, ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), na),
                ret);
    } else {
        DEBUG("delete key na=%s, data=%s [%p], ret=%" PRIi32,
                gps_na_format(na_buf, sizeof (na_buf), na),
                data == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                data,
                ret);
        // Mark ret for to free
        rte_ring_enqueue(table->key_positions_to_free, (void *) ((uintptr_t) ret));
    }

    return ret;
}

void
gps_i_neighbor_table_cleanup(struct gps_i_neighbor_table * table) {
    struct gps_i_neighbor_info *value_to_free;
    uintptr_t position_to_free;
    while (rte_ring_dequeue(table->values_to_free, (void **) &value_to_free) == 0) {
        if (likely(value_to_free != NULL)) {
            __gps_i_neighbor_table_return_entry(table->values, value_to_free);
        }
    }
    while (rte_ring_dequeue(table->key_positions_to_free, (void **) &position_to_free) == 0) {
        rte_hash_free_key_with_position_x(table->keys, position_to_free, (void **) &value_to_free);
        DEBUG("free key position: %u", (unsigned) position_to_free);
        if (likely(value_to_free != NULL)) __gps_i_neighbor_table_return_entry(table->values, value_to_free);
    }
}
