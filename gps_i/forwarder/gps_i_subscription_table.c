/* 
 * File:   gps_i_subscription_table.c
 * Author: Jiachen Chen
 */

#include <assert.h>
#include "gps_i_subscription_table.h"
#include <rte_errno.h>
#include <rte_malloc.h>


#define RTE_LOGTYPE_SUBSCRIPTION_TABLE RTE_LOGTYPE_USER1
#include <rte_log.h>

//#define GPS_I_SUBSCRIPTION_TABLE_DEBUG

#ifdef GPS_I_SUBSCRIPTION_TABLE_DEBUG
#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, SUBSCRIPTION_TABLE, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#define INFO(...) _INFO(__VA_ARGS__, "dummy")
#define _INFO(fmt, ...) RTE_LOG(INFO, SUBSCRIPTION_TABLE, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)

void
gps_i_subscription_entry_print(const struct gps_i_subscription_entry *entry,
        FILE *stream, const char *fmt, ...) {
    va_list valist;
    char na_buf[GPS_NA_FMT_SIZE];
    uint32_t i;
    va_start(valist, fmt);
    vfprintf(stream, fmt, valist);
    va_end(valist);

    fprintf(stream, "c=%" PRIu32, entry->count);
    for (i = 0; i < entry->count; i++) {
        fprintf(stream, " (%s)", gps_na_format(na_buf, sizeof (na_buf), &entry->next_hops[i]));
    }
}

struct gps_i_subscription_table *
gps_i_subscription_table_create(const char *type, uint32_t entries,
        unsigned values_to_free, unsigned socket_id) {
    char tmp_name[RTE_MEMZONE_NAMESIZE];
    struct gps_i_subscription_table *table;
    DEBUG("entries=%" PRIu32 ", values_to_free=%" PRIu32, entries, values_to_free);
    struct rte_hash_parameters_x params = {
        .entries = entries,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
        .hash_func = gps_guid_hash,
        .hash_func_init_val = 0,
        .key_len = sizeof (struct gps_guid),
        .name = tmp_name,
        .reserved = 0,
        .socket_id = socket_id
    };

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "ST_%s", type);
    DEBUG("name for table: %s", tmp_name);
    table = rte_zmalloc_socket(tmp_name, sizeof (struct gps_i_subscription_table),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (unlikely(table == NULL)) {
        DEBUG("fail to malloc table, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table=%p", table);
    table->socket_id = socket_id;

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "STK_%s", type);
    DEBUG("name for key: %s", params.name);
    table->keys = rte_hash_create_x(&params);
    if (unlikely(table->keys == NULL)) {
        DEBUG("fail to create keys, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->keys=%p", table->keys);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "STKF_%s", type);
    DEBUG("name for key_positions_to_free: %s", tmp_name);
    table->key_positions_to_free = rte_ring_create(tmp_name, entries + 1, socket_id,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (unlikely(table->key_positions_to_free == NULL)) {
        DEBUG("fail to create key_positions_to_free, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->key_positions_to_free=%p", table->key_positions_to_free);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "STVF_%s", type);
    DEBUG("name for values_to_free: %s", tmp_name);
    table->values_to_free = rte_ring_create(tmp_name, values_to_free, socket_id,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (unlikely(table->values_to_free == NULL)) {
        DEBUG("fail to create values_to_free, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->values_to_free=%p", table->values_to_free);

    return table;

fail:
    if (table != NULL) {
        if (table->keys != NULL) {
            DEBUG("free keys=%p", table->keys);
            rte_hash_free_x(table->keys);
        }
        if (table->key_positions_to_free != NULL) {
            DEBUG("free key_positions_to_free=%p", table->key_positions_to_free);
            rte_ring_free(table->key_positions_to_free);
        }
        if (table->values_to_free != NULL) {
            DEBUG("free values_to_free=%p", table->values_to_free);
            rte_ring_free(table->values_to_free);
        }
        memset(table, 0, sizeof (*table));
        DEBUG("free table=%p", table);
        rte_free(table);
    }
    return NULL;
}

static __rte_always_inline uint32_t
__gps_i_subscription_table_get_entry_size(uint32_t elements) {
    return sizeof (struct gps_i_subscription_entry) + sizeof (struct gps_na) * elements;
}

static __rte_always_inline struct gps_i_subscription_entry *
__gps_i_subscription_table_malloc_entry(unsigned socket_id, uint32_t elements) {
    uint32_t size = __gps_i_subscription_table_get_entry_size(elements);
    struct gps_i_subscription_entry *ret;
    ret = rte_malloc_socket(NULL, size, 0, socket_id);
    DEBUG("elements=%" PRIu32 ", size=%" PRIu32 ", ret=%p", elements, size, ret);
    return ret;
}

static __rte_always_inline void
__gps_i_subscription_table_free_entry(struct gps_i_subscription_entry *entry) {
    DEBUG("Free entry: %p", entry);
#ifdef GPS_I_SUBSCRIPTION_TABLE_DEBUG
    memset(entry, 0xef, __gps_i_subscription_table_get_entry_size(entry->count));
#endif
    rte_free(entry);
}

int32_t
gps_i_subscription_table_set(struct gps_i_subscription_table * table,
        const struct gps_guid *dst_guid, const struct gps_na *next_hop_na) {
#ifdef GPS_I_SUBSCRIPTION_TABLE_DEBUG
    char guid_buf[GPS_GUID_FMT_SIZE];
#endif

    struct gps_i_subscription_entry *entry, *orig_entry, *new_entry;
    int ret, position;
    uint32_t i;

    position = rte_hash_lookup_data_x(table->keys, dst_guid, (void **) &entry);
    DEBUG("lookup %s, got: %" PRIi32 ", entry=%p",
            gps_guid_format(guid_buf, sizeof (guid_buf), dst_guid), position, entry);
    if (position >= 0) { // found entry, update
        for (i = 0; i < entry->count; i++) {
            if (gps_na_cmp(&entry->next_hops[i], next_hop_na) == 0) { // found next_hop_na
                DEBUG("Found same next_hop, i=%" PRIu32, i);
                break;
            }
        }
        if (i == entry->count) {
            DEBUG("Cannot find next_hop_na, need add an element");
            new_entry = __gps_i_subscription_table_malloc_entry(table->socket_id, entry->count + 1);
            rte_memcpy(new_entry->next_hops, entry->next_hops, sizeof (struct gps_na) * entry->count);
            new_entry->count = entry->count + 1;
            gps_na_copy(&new_entry->next_hops[i], next_hop_na);

            ret = rte_hash_add_key_data_x(table->keys, dst_guid, new_entry, (void **) &orig_entry);
            DEBUG("add %s, got: %" PRIi32 ", orig_entry=%p",
                    gps_guid_format(guid_buf, sizeof (guid_buf), dst_guid), ret, orig_entry);
            assert(ret >= 0);
            // Should replace the entry out, unless there are multiple threads adding to it.
            assert(orig_entry == entry);
            ret = rte_ring_enqueue(table->values_to_free, entry);
            DEBUG("add %p to values_to_free, ret=%" PRIi32, entry, ret);
            // Report fail if we cannot add it to values to free. Should increase the size of ring.
            assert(ret == 0);
        }
    } else { // not found, create new
        DEBUG("Adding dst_guid for the first time, create new");
        entry = __gps_i_subscription_table_malloc_entry(table->socket_id, 1);
        entry->count = 1;
        gps_na_copy(&entry->next_hops[0], next_hop_na);
        position = rte_hash_add_key_data_x(table->keys, dst_guid, entry, (void **) &orig_entry);
        DEBUG("add %s, got: %" PRIi32 ", orig_entry=%p",
                gps_guid_format(guid_buf, sizeof (guid_buf), dst_guid), position, orig_entry);
        if (position < 0) return -1;
        // should not have entry, unless there are multiple threads adding to it.
        assert(orig_entry == NULL);
    }
    return position;
}

int32_t
gps_i_subscription_table_delete(struct gps_i_subscription_table * table,
        const struct gps_guid *dst_guid, const struct gps_na *next_hop_na) {
#ifdef GPS_I_SUBSCRIPTION_TABLE_DEBUG
    char guid_buf[GPS_GUID_FMT_SIZE];
#endif

    struct gps_i_subscription_entry *entry, *orig_entry, *new_entry;
    int ret, position;
    uint32_t i;

    // lookup
    position = rte_hash_lookup_data_x(table->keys, dst_guid, (void **) &entry);
    DEBUG("lookup %s, got: %" PRIi32 ", entry=%p",
            gps_guid_format(guid_buf, sizeof (guid_buf), dst_guid), position, entry);
    if (position >= 0) { // found entry, update
        for (i = 0; i < entry->count; i++) {
            if (gps_na_cmp(&entry->next_hops[i], next_hop_na) == 0) { // found next_hop_na
                if (entry->count == 1) { // last element in entry, delete the whole entry.
                    DEBUG("Last element in the entry, delete the whole entry.");
                    ret = rte_hash_del_key_x(table->keys, dst_guid, (void **) &orig_entry);
                    assert(ret >= 0);
                    // Should replace the entry out, unless there are multiple threads adding to it.
                    assert(orig_entry == entry);
                    DEBUG("Add %" PRIi32 " to key_positions_to_free.", ret);
                    ret = rte_ring_enqueue(table->key_positions_to_free, (void *) ((intptr_t) ret));
                } else {
                    DEBUG("Remove element %d in the entry.", i);
                    new_entry = __gps_i_subscription_table_malloc_entry(table->socket_id, entry->count - 1);
                    new_entry->count = entry->count - 1;

                    rte_memcpy(new_entry->next_hops, entry->next_hops, sizeof (struct gps_guid) * i);
                    rte_memcpy(new_entry->next_hops + i, entry->next_hops + i + 1, sizeof (struct gps_guid) * (new_entry->count - i));

                    ret = rte_hash_add_key_data_x(table->keys, dst_guid, new_entry, (void **) &orig_entry);
                    DEBUG("add %s, got: %" PRIi32 ", orig_entry=%p",
                            gps_guid_format(guid_buf, sizeof (guid_buf), dst_guid), ret, orig_entry);
                    assert(ret >= 0);
                    // Should replace the entry out, unless there are multiple threads adding to it.
                    assert(orig_entry == entry);
                    ret = rte_ring_enqueue(table->values_to_free, entry);
                    DEBUG("add %p to values_to_free, ret=%" PRIi32, entry, ret);
                    // Report fail if we cannot add it to values to free. Should increase the size of ring.
                    assert(ret == 0);
                }
                return position;
            }
        }
        // Cannot find next_hop_na, do nothing
        DEBUG("Cannot find next_hop_na, do nothing");
        return -ENOENT;
    } else {
        DEBUG("Cannot find dst_guid, do nothing");
        return -ENOENT;
    }
}

int32_t
gps_i_subscription_table_delete_dst(struct gps_i_subscription_table * table,
        const struct gps_guid *dst_guid) {
#ifdef GPS_I_SUBSCRIPTION_TABLE_DEBUG
    char guid_buf[GPS_GUID_FMT_SIZE];
#endif
    struct gps_i_subscription_entry *orig_entry;
    int position, ret;

    position = rte_hash_del_key_x(table->keys, dst_guid, (void **) &orig_entry);
    DEBUG("delete key %s, got: %" PRIi32 ", orig_entry=%p",
            gps_guid_format(guid_buf, sizeof (guid_buf), dst_guid), position, orig_entry);
    if (position >= 0) {
        ret = rte_ring_enqueue(table->key_positions_to_free, (void *) ((intptr_t) position));
        DEBUG("Add %" PRIi32 " to key_positions_to_free, ret=%" PRIi32 ".", position, ret);
        assert(ret == 0);
    }
    return position;
}

void
gps_i_subscription_table_cleanup(struct gps_i_subscription_table * table) {
    DEBUG("Start cleanup");
    struct gps_i_subscription_entry *value_to_free;
    uintptr_t position_to_free;
    while (rte_ring_dequeue(table->values_to_free, (void **) &value_to_free) == 0) {
        __gps_i_subscription_table_free_entry(value_to_free);
    }
    while (rte_ring_dequeue(table->key_positions_to_free, (void **) &position_to_free) == 0) {
        rte_hash_free_key_with_position_x(table->keys, position_to_free, (void **) &value_to_free);
        DEBUG("free key position: %u", (unsigned) position_to_free);
        __gps_i_subscription_table_free_entry(value_to_free);
    }
    DEBUG("End cleanup");
}

void
gps_i_subscription_table_destroy(struct gps_i_subscription_table * table) {
    DEBUG("Start destroy");
    gps_i_subscription_table_cleanup(table);

    const struct gps_na *dst_guid;
    struct gps_i_subscription_entry *value_to_free;
    int position;
    uint32_t next = 0;

    DEBUG("Free all the values in the table.");
    for (;;) {
        position = rte_hash_iterate_x(table->keys, (const void **) &dst_guid, (void **) &value_to_free, &next);
        if (position == -ENOENT)
            break;
        assert(position >= 0);
        __gps_i_subscription_table_free_entry(value_to_free);
    }


    DEBUG("free table=%p, keys=%p, key_positions_to_free=%p, values_to_free=%p",
            table, table->keys, table->key_positions_to_free, table->values_to_free);
    rte_hash_free_x(table->keys);
    rte_ring_free(table->key_positions_to_free);
    rte_ring_free(table->values_to_free);
    memset(table, 0, sizeof (*table));
    rte_free(table);
    DEBUG("End destroy");
}

void
gps_i_subscription_table_print(struct gps_i_subscription_table *table,
        FILE *stream, const char *fmt, ...) {
    const struct gps_guid *dst_guid;
    struct gps_i_subscription_entry *entry;
    int position;
    uint32_t next = 0;
    char dst_guid_buf[GPS_GUID_FMT_SIZE];
    va_list valist;

    va_start(valist, fmt);
    vfprintf(stream, fmt, valist);
    va_end(valist);
    fprintf(stream, "\n");

    for (;;) {
        position = rte_hash_iterate_x(table->keys, (const void **) &dst_guid, (void **) &entry, &next);
        if (position == -ENOENT)
            break;
        assert(position >= 0);
        gps_i_subscription_entry_print(entry, stream, "  %s (%" PRIi32 ") -> [%p] ",
                gps_guid_format(dst_guid_buf, sizeof (dst_guid_buf), dst_guid), position, entry);
        fprintf(stream, "\n");
    }
    fprintf(stream, ">>>>>>>>>>\n");
}

void
gps_i_subscription_table_read(struct gps_i_subscription_table *table,
        FILE *input, unsigned values_to_free) {
    const char *delim = "\t ";

    char *line = NULL, *token, *end;
    size_t len = 0;
    ssize_t read;
    unsigned line_id = 0, count = 0;
    long int value;
    struct gps_guid group_guid;
    struct gps_na next_hop_na;
    int32_t ret;
    uint32_t prefix = rte_cpu_to_be_32(0xbeefdead);

#ifdef GPS_I_SUBSCRIPTION_TABLE_DEBUG
    char group_guid_buf[GPS_GUID_FMT_SIZE], next_hop_na_buf[GPS_NA_FMT_SIZE];
#endif

    DEBUG("table=%p, input=%p", table, input);

    while ((read = getline(&line, &len, input)) != -1) {
        line_id++;
        if (line[read - 1] == '\n') line[--read] = '\0';
        if (line[read - 1] == '\r') line[--read] = '\0';
        DEBUG("getline %u read=%zu, len=%zu", line_id, read, len);
        DEBUG("line=\"%s\"", line);

        token = strtok(line, delim);
        if (token == NULL) {
            INFO("Cannot read line %u, cannot find group guid, skip.", line_id);
            continue;
        }
        value = strtol(token, &end, 0);
        if (*end != '\0') {
            INFO("Cannot read line %u, group guid not pure number, skip.", line_id);
            continue;
        }
        gps_guid_set(&group_guid, (uint32_t) value);
        rte_memcpy(&group_guid, &prefix, sizeof (uint32_t));
        DEBUG("guid=%s", gps_guid_format(group_guid_buf, sizeof (group_guid_buf), &group_guid));

        token = strtok(NULL, delim);
        if (token == NULL) {
            INFO("Cannot read line %u, cannot find next_hop_na, skip.", line_id);
            continue;
        }
        value = strtol(token, &end, 0);
        if (*end != '\0') {
            INFO("Cannot read line %u, next_hop_na not pure number, skip.", line_id);
            continue;
        }
        gps_na_set(&next_hop_na, (uint32_t) value);
        DEBUG("na=%s", gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na));

        ret = gps_i_subscription_table_set(table, &group_guid, &next_hop_na);
        if (ret < 0) {
            INFO("Cannot add to table, ret=%" PRIi32, ret);
        }
        count++;
        if (count == values_to_free)
            gps_i_subscription_table_cleanup(table);

    }
    free(line);
    gps_i_subscription_table_cleanup(table);
}
