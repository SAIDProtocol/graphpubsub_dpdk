/* 
 * File:   gps_i_subscription_table.h
 * Author: Jiachen Chen
 */

#ifndef GPS_I_SUBSCRIPTION_TABLE_H
#define GPS_I_SUBSCRIPTION_TABLE_H

#include <gps_guid.h>
#include <gps_na.h>
#include <rte_common.h>
#include "rte_hash.h"
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

    struct gps_i_subscription_entry {
        uint32_t count;
        struct gps_na next_hops[];
    };

    void
    gps_i_subscription_entry_print(const struct gps_i_subscription_entry *entry,
            FILE *stream, const char *fmt, ...);

    struct gps_i_subscription_table {
        struct rte_hash_x *keys;
        struct rte_ring *key_positions_to_free;
        struct rte_ring *values_to_free;
        unsigned socket_id;
    };

    /**
     * Initiate a subscription table with specified number of entries on a socket id.
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
     *   - The subscription table created
     *   - NULL on error.
     */
    struct gps_i_subscription_table *
    gps_i_subscription_table_create(const char *type, uint32_t entries,
            unsigned values_to_free, unsigned socket_id);

    /**
     * Add an entry into the subscription table.
     * 
     * Using RCU flavor.
     * Need to call cleanup when other threads have claimed quiescent.
     * The original value will be freed on cleanup.
     * 
     * @param table 
     *   The routing table to be added to.
     * @param dst_guid 
     *   The destination guid.
     * @param next_hop_na
     *   The next hop na.
     * @return 
     *   - >=0 when successfully added.
     *   - Less than 0 on failure.
     */
    int32_t
    gps_i_subscription_table_set(struct gps_i_subscription_table * table,
            const struct gps_guid *dst_guid, const struct gps_na *next_hop_na);

    /**
     * Remove an entry from the subscription table.
     * 
     * Value will be freed at cleanup stage. Can perform RCU
     * 
     * @param table 
     *   The table to be deleted from.
     * @param dst_guid 
     *   The destination guid.
     * @param next_hop_na
     *   The next hop na.
     * @return 
     *   - >=0 when successfully deleted.
     *   - Less than 0 on failure.
     */
    int32_t
    gps_i_subscription_table_delete(struct gps_i_subscription_table * table,
            const struct gps_guid *dst_guid, const struct gps_na *next_hop_na);

    /**
     * Remove all the entries corresponding to dst_guid from the subscription table.
     * 
     * Value will be freed at cleanup stage. Can perform RCU
     * 
     * @param table 
     *   The table to be deleted from.
     * @param dst_guid 
     *   The destination guid.
     * @return 
     *   - >=0 when successfully deleted.
     *   - Less than 0 on failure.
     */
    int32_t
    gps_i_subscription_table_delete_dst(struct gps_i_subscription_table * table,
            const struct gps_guid *dst_guid);

    /**
     * Lookup an entry in the subscription table.
     *
     * Should be put in rcu read lock block.
     * 
     * @param table 
     *   The table to be looked up.
     * @param dst_guid
     *   The destination guid of the entry.
     * @return 
     *   - The subscription entry.
     *   - NULL if entry not exist.
     */
    static __rte_always_inline const struct gps_i_subscription_entry *
    gps_i_subscription_table_lookup(const struct gps_i_subscription_table * table,
            const struct gps_guid *dst_guid) {
        struct gps_i_subscription_entry *value;
        int ret;

        ret = rte_hash_lookup_data_x(table->keys, dst_guid, (void **) &value);
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
    gps_i_subscription_table_cleanup(struct gps_i_subscription_table * table);

    /**
     * Clear all the resources the table uses.
     * 
     * @param table 
     *   The table to be cleaned.
     */
    void
    gps_i_subscription_table_destroy(struct gps_i_subscription_table * table);


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
    gps_i_subscription_table_print(struct gps_i_subscription_table *table,
            FILE *stream, const char *fmt, ...);

    /**
     * Reads a file into subscription table.
     * 
     * @param table The target subscription table.
     * @param input The input file.
     */
    void
    gps_i_subscription_table_read(struct gps_i_subscription_table *table, 
            FILE *input, unsigned values_to_free);


#ifdef __cplusplus
}
#endif

#endif /* GPS_I_SUBSCRIPTION_TABLE_H */

