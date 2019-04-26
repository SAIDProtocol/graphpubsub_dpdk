/* 
 * File:   gps_i_neighbor_table.h
 * Author: Jiachen Chen
 *
 * Created on April 14, 2019, 2:53 AM
 */

#ifndef GPS_I_NEIGHBOR_TABLE_H
#define GPS_I_NEIGHBOR_TABLE_H

#include <assert.h>
#include <gps_na.h>
#include <rte_ether.h>
#include "rte_hash.h"
#include <rte_mempool.h>
#include <rte_ring.h>
#include <stdarg.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct gps_i_neighbor_info {
        struct ether_addr ether;
        uint16_t port;
        uint32_t ip;
        bool use_ip;
    };

#define GPS_I_NEIGHBOR_INFO_FMT_SIZE 64

    static __rte_always_inline char *
    gps_i_neighbor_info_format(char *buf, uint16_t size, const struct gps_i_neighbor_info *info) {
        char ether_buf[ETHER_ADDR_FMT_SIZE];
        ether_format_addr(ether_buf, ETHER_ADDR_FMT_SIZE, &info->ether);
        const uint8_t *tmp_ip = (const uint8_t *) &info->ip;
        if (info->use_ip) {
            snprintf(buf, size, "Neighbor{ether=%s,ip=%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 ",port=%" PRIu16 "}",
                    ether_buf, tmp_ip[3], tmp_ip[2], tmp_ip[1], tmp_ip[0], info->port);
        } else {
            snprintf(buf, size, "Neighbor{ether=%s,port=%" PRIu16 "}",
                    ether_buf, info->port);
        }
        return buf;
    }

    struct gps_i_neighbor_table {
        struct rte_hash_x *keys;
        struct rte_mempool *values;
        struct rte_ring *key_positions_to_free;
        struct rte_ring *values_to_free;
    };

    /**
     * Initiate a neighbor table with specified number of entries on a socket id.
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
     *   - The neighbor table created
     *   - NULL on error.
     */
    struct gps_i_neighbor_table *
    gps_i_neighbor_table_create(const char *type, uint32_t entries,
            unsigned value_slots, unsigned socket_id);

    /**
     * Gets an empty slot to store the neighbor info.
     * 
     * @param table 
     *   The table that contains the entries.
     * @return 
     *   - The empty slot, but might not be zeroed. 
     *   - NULL if no slot available.
     */
    struct gps_i_neighbor_info *
    gps_i_neighbor_table_get_entry(struct gps_i_neighbor_table *table);

    /**
     * Returns an unused slot.
     * 
     * @param table 
     *   The table that contains the entries.
     * @return 
     *   - The empty slot. 
     *   - NULL if no slot available.
     */
    void
    gps_i_neighbor_table_return_entry(struct gps_i_neighbor_table *table,
            struct gps_i_neighbor_info *entry);

    /**
     * Add an entry into the neighbor table.
     * 
     * Using RCU flavor.
     * Need to call cleanup when other threads have claimed quiescent.
     * The original value will be freed on cleanup.
     * 
     * @param table 
     *   The neighbor table to be added to.
     * @param na 
     *   The na of the neighbor table entry.
     * @param info 
     *   The info to be stored.
     * @return 
     *   - NULL when successfully added.
     *   - == info when add failed.
     *   - == orig_val when values_to_free is full.
     */
    struct gps_i_neighbor_info *
    gps_i_neighbor_table_set(struct gps_i_neighbor_table * table,
            const struct gps_na *na, struct gps_i_neighbor_info *info);

    /**
     * Remove an entry from the neighbor table.
     * 
     * Value will be freed at cleanup stage. Can perform RCU
     * 
     * @param table 
     *   The table to be deleted from.
     * @param na 
     *   The na of the entry.
     * @return 
     *   - The position deleted. 
     *   - Less than 0 on failure.
     */
    int32_t
    gps_i_neighbor_table_delete(struct gps_i_neighbor_table * table,
            const struct gps_na *na);

    /**
     * Lookup an entry in the neighbor table.
     *
     * Should be put in rcu read lock block.
     * 
     * @param table 
     *   The table to be looked up.
     * @param na 
     *   The na of the entry.
     * @return 
     *   - The neighbor entry.
     *   - NULL if entry not exist.
     */
    static __rte_always_inline const struct gps_i_neighbor_info *
    gps_i_neighbor_table_lookup(const struct gps_i_neighbor_table * table,
            const struct gps_na *na) {
        struct gps_i_neighbor_info *value;
        int ret;

        ret = rte_hash_lookup_data_x(table->keys, na, (void **) &value);
        if (ret < 0) return NULL;
        return value;
    }

    /**
     * Cleanup the entries deleted during grace period.
     * 
     * Shall be called when all the referring threads claim quiescent state.
     * 
     * @param table 
     *   The table to be cleaned.
     */
    void
    gps_i_neighbor_table_cleanup(struct gps_i_neighbor_table * table);

    /**
     * Clear all the resources the table uses.
     * 
     * @param table 
     *   The table to be cleaned.
     */
    void
    gps_i_neighbor_table_destroy(struct gps_i_neighbor_table * table);


    /**
     * Dumps the information of the neighbor table.
     * 
     * @param table
     *   The table to be printed.
     * @param stream
     *   The stream the table to be printed on.
     * @param fmt
     *   The format of the leading string.
     * @param ...
     *   The variables of the leading string.
     */
    void
    gps_i_neighbor_table_print(struct gps_i_neighbor_table *table,
            FILE *stream, const char *fmt, ...);


#ifdef __cplusplus
}
#endif

#endif /* GPS_I_NEIGHBOR_TABLE_H */

