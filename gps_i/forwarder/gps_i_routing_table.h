/* 
 * File:   gps_i_routing_table.h
 * Author: Jiachen Chen
 */

#ifndef GPS_I_ROUTING_TABLE_H
#define GPS_I_ROUTING_TABLE_H

#include <gps_na.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include "rte_hash.h"
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct gps_i_routing_element {
        struct gps_na next_hop;
        uint32_t distance;
    };

    struct gps_i_routing_entry {
        uint16_t count;
        uint16_t min_idx;
        struct gps_i_routing_element elements[];
    };

    void
    gps_i_routing_entry_print(struct gps_i_routing_entry *entry,
            FILE *stream, const char *fmt, ...);

    struct gps_i_routing_table {
        struct rte_hash_x *keys;
        struct rte_ring *key_positions_to_free;
        struct rte_ring *values_to_free;
        unsigned socket_id;
    };

    /**
     * Initiate a routing table with specified number of entries on a socket id.
     * 
     * The assumption is that there will be only 1 writer (including add and remove),
     * but there can be multiple readers (lookups).
     * 
     * @param type
     *   A string identifying the type of allocated objects. Has to be unique in the system.
     * @param entries 
     *   The number of entries to create. Should be 2^n-1.
     * @param values_to_free
     *   The size of ring values_to_free. Should be 2^n.
     * @param socket_id 
     *   The socket id.
     * @return 
     *   - The neighbor table created
     *   - NULL on error.
     */
    struct gps_i_routing_table *
    gps_i_routing_table_create(const char *type, uint32_t entries,
            unsigned values_to_free, unsigned socket_id);

    /**
     * Add an entry into the routing table.
     * 
     * Using RCU flavor.
     * Need to call cleanup when other threads have claimed quiescent.
     * The original value will be freed on cleanup.
     * 
     * @param table 
     *   The routing table to be added to.
     * @param dst_na 
     *   The destination na.
     * @param next_hop_na
     *   The next hop na.
     * @param distance
     *   The distance to destination via next hop.
     * @return 
     *   - >=0 when successfully added.
     *   - Less than 0 on failure.
     */
    int32_t
    gps_i_routing_table_set(struct gps_i_routing_table * table,
            const struct gps_na *dst_na, const struct gps_na *next_hop_na,
            uint32_t distance);

    /**
     * Remove an entry from the routing table.
     * 
     * Value will be freed at cleanup stage. Can perform RCU
     * 
     * @param table 
     *   The table to be deleted from.
     * @param dst_na 
     *   The destination na.
     * @param next_hop_na
     *   The next hop na.
     * @return 
     *   - >=0 when successfully deleted.
     *   - Less than 0 on failure.
     */
    int32_t
    gps_i_routing_table_delete(struct gps_i_routing_table * table,
            const struct gps_na *dst_na, const struct gps_na *next_hop_na);

    /**
     * Remove all the entries corresponding to dst_na from the routing table.
     * 
     * Value will be freed at cleanup stage. Can perform RCU
     * 
     * @param table 
     *   The table to be deleted from.
     * @param dst_na 
     *   The destination na.
     * @return 
     *   - >=0 when successfully deleted.
     *   - Less than 0 on failure.
     */
    int32_t
    gps_i_routing_table_delete_dst(struct gps_i_routing_table * table,
            const struct gps_na *dst_na);

    /**
     * Lookup an entry in the routing table.
     *
     * Should be put in rcu read lock block.
     * 
     * @param table 
     *   The table to be looked up.
     * @param dst_na 
     *   The destination na of the entry.
     * @return 
     *   - The routing entry.
     *   - NULL if entry not exist.
     */
    static __rte_always_inline const struct gps_i_routing_entry *
    gps_i_routing_table_lookup(const struct gps_i_routing_table * table,
            const struct gps_na *dst_na) {
        struct gps_i_routing_entry *value;
        int ret;

        ret = rte_hash_lookup_data_x(table->keys, dst_na, (void **) &value);
        if (ret < 0) return NULL;
        return value;
    }

    /**
     * Get the next hop na for a destination na.
     *
     * Should be put in rcu read lock block.
     * 
     * @param table 
     *   The table to be looked up.
     * @param dst_na 
     *   The dst_na of the entry.
     * @param distance
     *   Output. The distance associated witht he next hop na. Can be NULL
     * @return 
     *   - The next hop na with lowest distance.
     *   - NULL if entry not exist.
     */
    static __rte_always_inline const struct gps_na *
    gps_i_routing_table_get_next_hop(const struct gps_i_routing_table * table,
            const struct gps_na *dst_na, uint32_t *distance) {
        const struct gps_i_routing_entry *value;
        const struct gps_i_routing_element *elem;

        value = gps_i_routing_table_lookup(table, dst_na);
        if (unlikely(value == NULL)) return NULL;

        elem = value->elements + value->min_idx;

        if (unlikely(distance != NULL)) *distance = elem->distance;
        return &elem->next_hop;
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
    gps_i_routing_table_cleanup(struct gps_i_routing_table * table);

    /**
     * Clear all the resources the table uses.
     * 
     * @param table 
     *   The table to be cleaned.
     */
    void
    gps_i_routing_table_destroy(struct gps_i_routing_table * table);


    /**
     * Dumps the information of the routing table.
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
    gps_i_routing_table_print(struct gps_i_routing_table *table,
            FILE *stream, const char *fmt, ...);




#ifdef __cplusplus
}
#endif

#endif /* GPS_I_ROUTING_TABLE_H */

