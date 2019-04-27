/* 
 * File:   gps_i_gnrs_cache.h
 * Author: Jiachen Chen
 */

#ifndef GPS_I_GNRS_CACHE_H
#define GPS_I_GNRS_CACHE_H

#include <gps_na.h>
#include <gps_guid.h>
#include <rte_common.h>
#include "rte_hash.h"
#include <rte_mempool.h>
#include <rte_ring.h>
#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif

    struct gps_i_gnrs_cache_entry {
        struct gps_na na;
        uint32_t version;
    };

#define GPS_I_GNRS_CACHE_ENTRY_FMT_SIZE (GPS_NA_FMT_SIZE + 22)

    static __rte_always_inline char *
    gps_i_gnrs_cache_entry_format(char *buf, uint16_t size, const struct gps_i_gnrs_cache_entry *entry) {
        char na_buf[GPS_NA_FMT_SIZE];
        snprintf(buf, size, "GNRS{na=%s,v=%" PRIu32 "}",
                gps_na_format(na_buf, sizeof (na_buf), &entry->na), entry->version);
        return buf;
    }

    struct gps_i_gnrs_cache {
        struct rte_hash_x *keys;
        struct rte_mempool *values;
        struct rte_ring *key_positions_to_free;
        struct rte_ring *values_to_free;
    };

    /**
     * Initiate a gnrs cache with specified number of entries on a socket id.
     * 
     * The assumption is that there will be only 1 writer (including add and remove),
     * but there can be multiple readers (lookups).
     * 
     * @param type
     *   A string identifying the type of allocated objects. Has to be unique in the system.
     * @param entries 
     *   The number of entries to create. Should be 2^n-1.
     * @param value_slots
     *   The element count of mempool values. Should be 2^n.
     * @param socket_id 
     *   The socket id.
     * @return 
     *   - The gnrs cache created
     *   - NULL on error.
     */
    struct gps_i_gnrs_cache *
    gps_i_gnrs_cache_create(const char *type, uint32_t entries,
            unsigned value_slots, unsigned socket_id);

    /**
     * Add an entry into the gnrs cache.
     * 
     * Using RCU flavor.
     * Need to call cleanup when other threads have claimed quiescent.
     * The original value will be freed on cleanup.
     * 
     * @param cache 
     *   The gnrs cache to be added to.
     * @param guid 
     *   The guid of the gnrs cache entry.
     * @param na 
     *   The na corresponding to the guid.
     * @param version
     *   The version of the mapping
     * @return 
     *   >= 0 when successfully added.
     *   Less than 0 on failure.
     */
    int32_t
    gps_i_gnrs_cache_set(struct gps_i_gnrs_cache * cache,
            const struct gps_guid *guid, const struct gps_na *na, uint32_t version);

    /**
     * Remove an entry from the gnrs cache.
     * 
     * Value will be freed at cleanup stage. Can perform RCU
     * 
     * @param cache 
     *   The gnrs cache to be deleted from.
     * @param guid
     *   The guid of the entry.
     * @return 
     *   - The position deleted. 
     *   - Less than 0 on failure.
     */
    int32_t
    gps_i_gnrs_cache_delete(struct gps_i_gnrs_cache * cache,
            const struct gps_guid *guid);

    /**
     * Lookup an entry in the gnrs cache.
     *
     * Should be put in rcu read lock block.
     * 
     * @param cache
     *   The gnrs to be looked up.
     * @param guid
     *   The guid of the entry.
     * @param version
     *   Output. The version of the entry. Can be NULL.
     * @return 
     *   - The na mapped with the guid.
     *   - NULL if entry not exist.
     */
    static __rte_always_inline const struct gps_na *
    gps_i_gnrs_cache_lookup(const struct gps_i_gnrs_cache * cache,
            const struct gps_guid *guid, uint32_t *version) {
        struct gps_i_gnrs_cache_entry *value;
        int ret;

        ret = rte_hash_lookup_data_x(cache->keys, guid, (void **) &value);
        if (ret < 0) return NULL;
        if (unlikely(version != NULL)) *version = value->version;
        return &value->na;
    }

    /**
     * Cleanup the entries deleted during grace period.
     * 
     * Shall be called when all the referring threads claim quiescent state.
     * 
     * @param cache 
     *   The gnrs cache to be cleaned.
     */
    void
    gps_i_gnrs_cache_cleanup(struct gps_i_gnrs_cache * cache);

    /**
     * Clear all the resources the gnrs cache uses.
     * 
     * @param cache 
     *   The gnrs cache to be cleaned.
     */
    void
    gps_i_gnrs_cache_destroy(struct gps_i_gnrs_cache * cache);


    /**
     * Dumps the information of the gnrs cache.
     * 
     * @param cache
     *   The gnrs cache to be printed.
     * @param stream
     *   The stream the gnrs cache to be printed on.
     * @param fmt
     *   The format of the leading string.
     * @param ...
     *   The variables of the leading string.
     */
    void
    gps_i_gnrs_cache_print(struct gps_i_gnrs_cache *cache,
            FILE *stream, const char *fmt, ...);


#ifdef __cplusplus
}
#endif

#endif /* GPS_I_GNRS_CACHE_H */

