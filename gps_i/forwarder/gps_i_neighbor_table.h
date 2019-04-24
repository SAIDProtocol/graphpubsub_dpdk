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
#include <stdbool.h>
#include <linux_list.h>

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

#define NEIGHBOR_TABLE_ENTRIES_EXTRA 8
#define NEIGHBOR_TABLE_ENTRIES_PADDING 8

    struct gps_i_neighbor_table {
        uint32_t entries;
        struct rte_hash_x *keys;
        struct gps_i_neighbor_info *values;
        int32_t *keys_to_free;
        uint32_t num_keys_to_free;
        // 0 to num_values_available - 1: value slots available
        // value_entries = entries + NEIGHBOR_TABLE_ENTRIES_EXTRA
        // total_entries = entries + padding
        // total_entries - 1 - num_values_to_free to total_entries - 1: values slots to free
        int32_t *values_available;
        uint32_t num_values_available, num_values_to_free;
    };

    /**
     * Initiate a neighbor table with specified number of entries on a socket id.
     * 
     * The assumption is that there will be only 1 writer (including add and remove),
     * but there can be multiple readers (lookups).
     * 
     * @param type
     *   A string identifying the type of allocated objects (useful for debug
     *   purposes, such as identifying the cause of a memory leak). Can be NULL.
     * @param entries 
     *   The number of entries to create. Better use 2^n-1 for optimal memory utilization.
     * @param socket_id 
     *   The socket id.
     * @return 
     *   - The neighbor table created
     *   - NULL on error.
     */
    struct gps_i_neighbor_table *
    gps_i_neighbor_table_create(const char *type, uint32_t entries, unsigned socket_id);

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
     * Using lock-free algorithms. Can do add/remove/lookup at the same time.
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
     *   - The position added/set. 
     *   - Less than 0 on failure.
     */
    int32_t
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
    static __rte_always_inline struct gps_i_neighbor_info *
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

    static __rte_always_inline void
    gps_i_neighbor_table_print_available(struct gps_i_neighbor_table *table, FILE *stream) {
        uint32_t i;
        uint32_t end = table->entries + NEIGHBOR_TABLE_ENTRIES_EXTRA + NEIGHBOR_TABLE_ENTRIES_PADDING;

        for (i = 0; i < end; i++) {
            fprintf(stream, "[%" PRIu32, i);
            if (i < table->num_values_available) {
                fprintf(stream, ",A");
            }
            if (i >= end - table->num_values_to_free) {
                fprintf(stream, ",F");
            }
            fprintf(stream, "]%" PRIi32 " ", table->values_available[i]);
        }
        fprintf(stream, "\n");
    }

    static __rte_always_inline void
    gps_i_neighbor_table_print_keys_to_free(struct gps_i_neighbor_table *table, FILE *stream) {
        uint32_t i;
        int32_t position;
        const struct gps_na *na;
        struct gps_i_neighbor_info *data;
        char na_buf[GPS_NA_FMT_SIZE];

        fprintf(stream, ">>> To frees: \n");
        for (i = 0; i < table->num_keys_to_free; i++) {
            position = table->keys_to_free[i];
            rte_hash_get_key_data_with_position_x(table->keys, position, (const void **) &na, (void **) &data);

            fprintf(stream, "  %s (%d)\n",
                    gps_na_format(na_buf, sizeof (na_buf), na),
                    position);
        }
        fprintf(stream, ">>>>>>>>>>\n");
    }

    static __rte_always_inline void
    gps_i_neighbor_table_print(struct gps_i_neighbor_table *table, FILE *stream) {
        uint32_t next = 0;
        int32_t position;
        const struct gps_na *na;
        struct gps_i_neighbor_info *data;
        char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

        fprintf(stream, ">>> Table: \n");
        for (;;) {
            position = rte_hash_iterate_x(table->keys, (const void **) &na, (void **) &data, &next);
            if (position == -ENOENT)
                break;

            assert(position >= 0);
            fprintf(stream, "  %s (%d) -> %s (%zd) \n",
                    gps_na_format(na_buf, sizeof (na_buf), na),
                    position,
                    data == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                    data - table->values);
        }
        fprintf(stream, ">>>>>>>>>>\n");

    }


#ifdef __cplusplus
}
#endif

#endif /* GPS_I_NEIGHBOR_TABLE_H */

