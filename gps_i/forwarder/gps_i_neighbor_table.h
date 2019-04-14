/* 
 * File:   gps_i_neighbor_table.h
 * Author: Jiachen Chen
 *
 * Created on April 14, 2019, 2:53 AM
 */

#ifndef GPS_I_NEIGHBOR_TABLE_H
#define GPS_I_NEIGHBOR_TABLE_H

#include <gps_na.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
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

    static inline char *
    gps_i_neighbor_info_format(char *buf, uint16_t size, const struct gps_i_neighbor_info *info) {
        char ether_buf[ETHER_ADDR_FMT_SIZE];
        ether_format_addr(ether_buf, ETHER_ADDR_FMT_SIZE, &info->ether);
        const uint8_t *tmp_ip = (const uint8_t *)&info->ip;
        if (info->use_ip) {
            snprintf(buf, size, "Neighbor{ether=%s,ip=%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8 ",port=%" PRIu16 "}",
                    ether_buf, tmp_ip[3], tmp_ip[2], tmp_ip[1], tmp_ip[0], info->port);
        } else {
            snprintf(buf, size, "Neighbor{ether=%s,port=%" PRIu16 "}",
                    ether_buf, info->port);
        }
        return buf;
    }

    extern struct rte_hash *gps_i_neighbor_keys;
    extern struct gps_i_neighbor_info *gps_i_neighbor_values;

    /**
     * Initiate neighbor table with specified number of entries on a socket id.
     * 
     * @param entries The number of entries to create.
     * @param socket_id The socket id.
     */
    static inline void
    gps_i_neighbor_table_init(uint32_t entries, unsigned socket_id) {
        struct rte_hash_parameters params = {
            .entries = entries,
            .extra_flag = RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT | RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY,
            .hash_func = rte_jhash,
            .hash_func_init_val = 0,
            .key_len = sizeof (struct gps_na),
            .name = "gps_i_neighbor_keys",
            .socket_id = socket_id
        };
        gps_i_neighbor_keys = rte_hash_create(&params);
        if (gps_i_neighbor_keys == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot initiate neighbor keys!\n");
        }

        gps_i_neighbor_values = rte_malloc_socket("gps_i_neighbor_values",
                sizeof (struct gps_i_neighbor_info) * entries, RTE_CACHE_LINE_SIZE,
                socket_id);
        if (gps_i_neighbor_values == NULL) {
            rte_exit(EXIT_FAILURE, "Cannot initiate neighbor values!\n");
        }
    }

    static inline void
    gps_i_neighbor_table_destroy(void) {
        rte_hash_free(gps_i_neighbor_keys);
        rte_free(gps_i_neighbor_values);
    }

    /**
     * Add an entry into the neighbor table.
     * 
     * No lock is added here. Caller has the responsibility to add locks when needed.
     * Yet, the hash table has RW_CONCURRENCY set, no need to add lock.
     * 
     * @param na The na of the neighbor table entry.
     * @param info The info to be stored.
     * @return The position added/set. &lt;0 on failure.
     */
    static inline int32_t
    gps_i_neighbor_table_set(const struct gps_na *na, const struct gps_i_neighbor_info *info) {
        int32_t ret;

        ret = rte_hash_add_key(gps_i_neighbor_keys, na);
        if (ret >= 0) {
            rte_memcpy(gps_i_neighbor_values + ret, info, sizeof (struct gps_i_neighbor_info));
        }

        return ret;
    }

    /**
     * Lookup an entry in the neighbor table.
     * 
     * No lock is added here. Caller has the responsibility to add locks when needed.
     * Yet, the hash table has RW_CONCURRENCY set, no need to add lock.
     * 
     * @param na The na of the entry.
     * @return The neighbor entry, NULL if entry not exist.
     */
    static inline const struct gps_i_neighbor_info *
    gps_i_neighbor_table_lookup(const struct gps_na *na) {
        int32_t ret;

        ret = rte_hash_lookup(gps_i_neighbor_keys, na);

        return ret < 0 ? NULL : (gps_i_neighbor_values + ret);
    }

    /**
     * Remove an entry in the neighbor table.
     * 
     * Value is not cleared, just invalidated.
     * 
     * No lock is added here. Caller has the responsibility to add locks when needed.
     * Yet, the hash table has RW_CONCURRENCY set, no need to add lock.
     * 
     * @param na The na of the entry.
     * @return The position deleted. &lt;0 on failure.
     */
    static inline int
    gps_i_neighbor_table_delete(const struct gps_na *na) {
        int32_t ret;

        ret = rte_hash_del_key(gps_i_neighbor_keys, na);

        // No need to remove the entry in value. 

        return ret;
    }



#ifdef __cplusplus
}
#endif

#endif /* GPS_I_NEIGHBOR_TABLE_H */

