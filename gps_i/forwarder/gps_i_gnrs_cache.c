/* 
 * File:   gps_i_gnrs_cache.c
 * Author: Jiachen Chen
 */
#include <assert.h>
#include "gps_i_gnrs_cache.h"
#include <rte_errno.h>
#include <rte_malloc.h>

#define GPS_I_GNRS_CACHE_DEBUG

#ifdef GPS_I_GNRS_CACHE_DEBUG
#include <rte_log.h>

#define RTE_LOGTYPE_GNRS_CACHE RTE_LOGTYPE_USER1

#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, GNRS_CACHE, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

struct gps_i_gnrs_cache *
gps_i_gnrs_cache_create(const char *type, uint32_t entries,
        unsigned value_slots, unsigned socket_id) {

    struct gps_i_gnrs_cache *cache = NULL;
    char tmp_name[RTE_MEMZONE_NAMESIZE];
    DEBUG("entries=%" PRIu32 ", value_slots=%" PRIu32, entries, value_slots);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "GNRSK_%s", type);
    DEBUG("name for key: %s", tmp_name);
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

    cache = rte_zmalloc_socket(type, sizeof (struct gps_i_gnrs_cache),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (cache == NULL) goto fail;

    cache->keys = rte_hash_create_x(&params);
    if (unlikely(cache->keys == NULL)) {
        DEBUG("fail to create keys, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("cache->keys=%p", cache->keys);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "GNRSV_%s", type);
    DEBUG("name for values: %s", tmp_name);
    cache->values = rte_mempool_create(tmp_name,
            value_slots, sizeof (struct gps_i_gnrs_cache_entry),
            0, 0,
            NULL, NULL, NULL, NULL,
            rte_socket_id(),
            MEMPOOL_F_NO_CACHE_ALIGN | MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (unlikely(cache->values == NULL)) {
        DEBUG("fail to create values, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("cache->values=%p", cache->values);


    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "GNRSKF_%s", type);
    DEBUG("name for key_positions_to_free: %s", tmp_name);
    cache->key_positions_to_free = rte_ring_create(tmp_name, entries + 1, socket_id,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (unlikely(cache->key_positions_to_free == NULL)) {
        DEBUG("fail to create key_positions_to_free, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("cache->key_positions_to_free=%p", cache->key_positions_to_free);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "GNRSVF_%s", type);
    DEBUG("name for values_to_free: %s", tmp_name);
    cache->values_to_free = rte_ring_create(tmp_name, value_slots, socket_id,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (unlikely(cache->values_to_free == NULL)) {
        DEBUG("fail to create values_to_free, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("cache->values_to_free=%p", cache->values_to_free);

    return cache;

fail:
    if (cache != NULL) {
        if (cache->keys != NULL) rte_hash_free_x(cache->keys);
        if (cache->values != NULL) rte_mempool_free(cache->values);
        if (cache->key_positions_to_free != NULL) rte_ring_free(cache->key_positions_to_free);
        if (cache->values_to_free != NULL) rte_ring_free(cache->values_to_free);
        memset(cache, 0, sizeof (*cache));
        rte_free(cache);
    }
    return NULL;
}

int32_t
gps_i_gnrs_cache_set(struct gps_i_gnrs_cache * cache,
        const struct gps_guid *guid, const struct gps_na *na, uint32_t version) {
    RTE_SET_USED(na);
    RTE_SET_USED(version);


    struct gps_i_gnrs_cache_entry *entry = NULL, *new_entry, *orig_entry;
    int position, ret;
#ifdef GPS_I_GNRS_CACHE_DEBUG
    char guid_buf[GPS_GUID_FMT_SIZE], entry_buf[GPS_I_GNRS_CACHE_ENTRY_FMT_SIZE],
            orig_entry_buf[GPS_I_GNRS_CACHE_ENTRY_FMT_SIZE];
#endif

    position = rte_hash_lookup_data_x(cache->keys, guid, (void **) &entry);
    DEBUG("lookup %s, got: %" PRIi32 ", entry=%s [%p]",
            gps_guid_format(guid_buf, sizeof (guid_buf), guid), position,
            entry == NULL ? "" : gps_i_gnrs_cache_entry_format(entry_buf, sizeof (entry_buf), entry),
            entry);

    if (position < 0) { // an earlier version
        if (likely(rte_mempool_get(cache->values, (void **) &new_entry) == 0)) {
            DEBUG("get entry: %p", new_entry);
        } else {
            DEBUG("Cannot get entry!");
            return -1;
        }
        gps_na_copy(&new_entry->na, na);
        new_entry->version = version;
        position = rte_hash_add_key_data_x(cache->keys, guid, new_entry, (void **) &orig_entry);
        DEBUG("add %s->%s [%p], orig=%s [%p] ret=%" PRIi32,
                gps_guid_format(guid_buf, sizeof (guid_buf), guid),
                gps_i_gnrs_cache_entry_format(entry_buf, sizeof (entry_buf), new_entry),
                new_entry,
                orig_entry == NULL ? "" : gps_i_gnrs_cache_entry_format(orig_entry_buf, sizeof (orig_entry_buf), orig_entry),
                orig_entry, position);
        assert(orig_entry == NULL);

    } else if (entry->version < version) {
        if (likely(rte_mempool_get(cache->values, (void **) &new_entry) == 0)) {
            DEBUG("get entry: %p", new_entry);
        } else {
            DEBUG("Cannot get entry!");
            return -1;
        }
        gps_na_copy(& new_entry->na, na);
        new_entry->version = version;
        ret = rte_hash_add_key_data_x(cache->keys, guid, new_entry, (void **) &orig_entry);
        DEBUG("add %s->%s [%p], orig=%s [%p] ret=%" PRIi32,
                gps_guid_format(guid_buf, sizeof (guid_buf), guid),
                gps_i_gnrs_cache_entry_format(entry_buf, sizeof (entry_buf), new_entry),
                new_entry,
                orig_entry == NULL ? "" : gps_i_gnrs_cache_entry_format(orig_entry_buf, sizeof (orig_entry_buf), orig_entry),
                orig_entry, position);
        assert(ret == position && orig_entry == entry);
        // add orig_entry to free
        ret = rte_ring_enqueue(cache->values_to_free, entry);
        DEBUG("Add entry %p to values_to_free, ret=%" PRIi32, entry, ret);
        assert(ret == 0);
    } else {
        DEBUG("curr version=%" PRIu32 ", set version=%" PRIu32 ", do nothing.", entry->version, version);
    }
    return position;
}

int32_t
gps_i_gnrs_cache_delete(struct gps_i_gnrs_cache * cache,
        const struct gps_guid *guid) {
    int32_t position, ret;
    struct gps_i_gnrs_cache_entry *entry;

#ifdef GPS_I_GNRS_CACHE_DEBUG
    char guid_buf[GPS_GUID_FMT_SIZE], entry_buf[GPS_I_GNRS_CACHE_ENTRY_FMT_SIZE];
#endif

    position = rte_hash_del_key_x(cache->keys, guid, (void **) &entry);
    if (position >= 0) {
        DEBUG("delete %s->%s [%p], ret=%" PRIi32,
                gps_guid_format(guid_buf, sizeof (guid_buf), guid),
                gps_i_gnrs_cache_entry_format(entry_buf, sizeof (entry_buf), entry),
                entry, position);
        ret = rte_ring_enqueue(cache->key_positions_to_free, (void *) ((intptr_t) position));
        DEBUG("Add %" PRIi32 " to key_positions_to_free, ret=%" PRIi32 ".", position, ret);
        assert(ret == 0);
    } else {
        DEBUG("delete %s, ret=%" PRIi32,
                gps_guid_format(guid_buf, sizeof (guid_buf), guid),
                position);
    }
    return position;
}

static __rte_always_inline void
__gps_i_gnrs_cache_free_entry(struct rte_mempool *mempool,
        struct gps_i_gnrs_cache_entry *entry) {
    DEBUG("return entry: %p", entry);
#ifdef GPS_I_GNRS_CACHE_DEBUG
    memset(entry, 0xBF, sizeof (*entry));
#endif
    rte_mempool_put(mempool, entry);
}

void
gps_i_gnrs_cache_cleanup(struct gps_i_gnrs_cache * cache) {
    struct gps_i_gnrs_cache_entry *entry_to_free;
    uintptr_t position_to_free;

    while (rte_ring_dequeue(cache->values_to_free, (void **) &entry_to_free) == 0) {
        __gps_i_gnrs_cache_free_entry(cache->values, entry_to_free);
    }
    while (rte_ring_dequeue(cache->key_positions_to_free, (void **) &position_to_free) == 0) {
        rte_hash_free_key_with_position_x(cache->keys, position_to_free, (void **) &entry_to_free);
        DEBUG("free key position: %u", (unsigned) position_to_free);
        __gps_i_gnrs_cache_free_entry(cache->values, entry_to_free);
    }

}

void
gps_i_gnrs_cache_destroy(struct gps_i_gnrs_cache * cache) {
    DEBUG("free cache=%p, keys=%p, values=%p, key_positions_to_free=%p, values_to_free=%p",
            cache, cache->keys, cache->values, cache->key_positions_to_free, cache->values_to_free);
    rte_hash_free_x(cache->keys);
    rte_mempool_free(cache->values);
    rte_ring_free(cache->key_positions_to_free);
    rte_ring_free(cache->values_to_free);
    memset(cache, 0, sizeof (*cache));
    rte_free(cache);
}

void
gps_i_gnrs_cache_print(struct gps_i_gnrs_cache *cache,
        FILE *stream, const char *fmt, ...) {
    int32_t position;
    struct gps_guid *guid;
    struct gps_i_gnrs_cache_entry *entry;
    uint32_t next = 0;
    va_list valist;
    char guid_buf[GPS_GUID_FMT_SIZE], entry_buf[GPS_I_GNRS_CACHE_ENTRY_FMT_SIZE];

    va_start(valist, fmt);
    vfprintf(stream, fmt, valist);
    va_end(valist);
    fprintf(stream, "\n");

    for (;;) {
        position = rte_hash_iterate_x(cache->keys, (const void **) &guid, (void **) &entry, &next);
        if (position == -ENOENT)
            break;
        assert(position >= 0);
        fprintf(stream, "  %s -> %s\n",
                gps_guid_format(guid_buf, sizeof (guid_buf), guid),
                gps_i_gnrs_cache_entry_format(entry_buf, sizeof (entry_buf), entry));
    }
    fprintf(stream, ">>>>>>>>>>\n");
}
