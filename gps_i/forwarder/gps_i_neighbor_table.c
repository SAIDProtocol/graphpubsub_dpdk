/* 
 * File:   gps_i_neighbor_table.c
 * Author: Jiachen Chen
 */

#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_ipaddr.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include "gps_i_neighbor_table.h"

//#define GPS_I_NEIGHBOR_TABLE_DEBUG

#define RTE_LOGTYPE_NEIGHBOR_TABLE RTE_LOGTYPE_USER1
#include <rte_log.h>

#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
#define DEBUG(...) _DEBUG(__VA_ARGS__, "dummy")
#define _DEBUG(fmt, ...) RTE_LOG(INFO, NEIGHBOR_TABLE, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)
#else
#define DEBUG(...)
#endif

#define INFO(...) _INFO(__VA_ARGS__, "dummy")
#define _INFO(fmt, ...) RTE_LOG(INFO, NEIGHBOR_TABLE, "[%s():%d] " fmt "%.0s\n", __func__, __LINE__, __VA_ARGS__)

struct gps_i_neighbor_table *
gps_i_neighbor_table_create(const char *type, uint32_t entries,
        unsigned value_slots, unsigned socket_id) {
    struct gps_i_neighbor_table *table = NULL;
    char tmp_name[RTE_MEMZONE_NAMESIZE];
    DEBUG("entries=%" PRIu32 ", value_slots=%" PRIu32, entries, value_slots);

    struct rte_hash_parameters_x params = {
        .entries = entries,
        .extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF,
        .hash_func = gps_na_hash,
        .hash_func_init_val = 0,
        .key_len = sizeof (struct gps_na),
        .name = tmp_name,
        .reserved = 0,
        .socket_id = socket_id
    };

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBT_%s", type);
    DEBUG("name for table: %s", tmp_name);
    table = rte_zmalloc_socket(tmp_name, sizeof (struct gps_i_neighbor_table),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (unlikely(table == NULL)) {
        DEBUG("fail to malloc table, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table=%p", table);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBTK_%s", type);
    DEBUG("name for keys: %s", params.name);
    table->keys = rte_hash_create_x(&params);
    if (unlikely(table->keys == NULL)) {
        DEBUG("fail to create keys, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->keys=%p", table->keys);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBTV_%s", type);
    DEBUG("name for values: %s", tmp_name);
    table->values = rte_mempool_create(tmp_name,
            value_slots, sizeof (struct gps_i_neighbor_info),
            0, 0,
            NULL, NULL, NULL, NULL,
            rte_socket_id(),
            MEMPOOL_F_NO_CACHE_ALIGN | MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (unlikely(table->values == NULL)) {
        DEBUG("fail to create values, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->values=%p", table->values);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBTKF_%s", type);
    DEBUG("name for key_positions_to_free: %s", tmp_name);
    table->key_positions_to_free = rte_ring_create(tmp_name, entries + 1, socket_id,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (unlikely(table->key_positions_to_free == NULL)) {
        DEBUG("fail to create key_positions_to_free, reason: %s", rte_strerror(rte_errno));
        goto fail;
    }
    DEBUG("table->key_positions_to_free=%p", table->key_positions_to_free);

    snprintf(tmp_name, RTE_MEMZONE_NAMESIZE, "NBTVF_%s", type);
    DEBUG("name for values_to_free: %s", tmp_name);
    table->values_to_free = rte_ring_create(tmp_name, value_slots, socket_id,
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
        if (table->values != NULL) {
            DEBUG("free values=%p", table->values);
            rte_mempool_free(table->values);
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

void
gps_i_neighbor_table_destroy(struct gps_i_neighbor_table * table) {
    DEBUG("free table=%p, keys=%p, values=%p, key_positions_to_free=%p, values_to_free=%p",
            table, table->keys, table->values, table->key_positions_to_free, table->values_to_free);
    rte_hash_free_x(table->keys);
    rte_mempool_free(table->values);
    rte_ring_free(table->key_positions_to_free);
    rte_ring_free(table->values_to_free);
    memset(table, 0, sizeof (*table));
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
    memset(entry, 0xBF, sizeof (*entry));
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

void
gps_i_neighbor_table_print(struct gps_i_neighbor_table *table,
        FILE *stream, const char *fmt, ...) {
    uint32_t next = 0;
    int32_t position;
    const struct gps_na *na;
    struct gps_i_neighbor_info *data;
    va_list valist;

    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

    va_start(valist, fmt);
    vfprintf(stream, fmt, valist);
    va_end(valist);
    fprintf(stream, "\n");
    for (;;) {
        position = rte_hash_iterate_x(table->keys, (const void **) &na, (void **) &data, &next);
        if (position == -ENOENT)
            break;

        assert(position >= 0);
        fprintf(stream, "  %s (%d) -> %s [%p] \n",
                gps_na_format(na_buf, sizeof (na_buf), na),
                position,
                data == NULL ? "" : gps_i_neighbor_info_format(info_buf, sizeof (info_buf), data),
                data);
    }
    fprintf(stream, ">>>>>>>>>>\n");

}

void
gps_i_neighbor_table_read(struct gps_i_neighbor_table *table, FILE *input) {
    const char *delim = "\t ";
    char *line = NULL, *token, *end;
    size_t len = 0;
    ssize_t read;
    unsigned line_id = 0;
    long int value;
    struct gps_na next_hop_na;
    uint16_t port;
    struct ether_addr ether_addr;
    struct gps_i_neighbor_info *info, *ret;

    //    union {
    //        uint32_t ip;
    //        uint8_t bytes[sizeof (uint32_t)];
    //    } ip;
    char next_hop_na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
    char ether_buf[ETHER_ADDR_FMT_SIZE];
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
            INFO("Cannot read line %u, cannot find next_hop_na, skip.", line_id);
            continue;
        }
        value = strtol(token, &end, 0);
        if (*end != '\0') {
            INFO("Cannot read line %u, next_hop_na not pure number, skip.", line_id);
            continue;
        }
        gps_na_set(&next_hop_na, (uint32_t) value);
        DEBUG("NEXT_HOP_NA=%s", gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na));

        token = strtok(NULL, delim);
        if (token == NULL) {
            INFO("Cannot read line %u, cannot find port, skip.", line_id);
            continue;
        }
        value = strtol(token, &end, 0);
        if (*end != '\0') {
            INFO("Cannot read line %u, port not pure number, skip.", line_id);
            continue;
        }
        if (value < 0 || value > UINT16_MAX) {
            INFO("Cannot read line %u, port (%ld) not in range [0,%d].", line_id, value, UINT16_MAX);
            continue;
        }
        port = (uint16_t) value;
        DEBUG("port=%" PRIu16, port);

        token = strtok(NULL, delim);
        if (token == NULL) {
            INFO("Cannot read line %u, cannot find ether.", line_id);
            continue;
        }
        value = cmdline_parse_etheraddr(NULL, token, &ether_addr, sizeof (ether_addr));
        if (value < 0) {
            INFO("Cannot read line %u, cannot parse ether %s.", line_id, token);
            continue;
        }
#ifdef GPS_I_NEIGHBOR_TABLE_DEBUG
        ether_format_addr(ether_buf, sizeof (ether_buf), &ether_addr);
#endif
        DEBUG("ether=%s", ether_buf);

        //        ip.ip = 0;
        token = strtok(NULL, delim);
        if (token != NULL) {
            INFO("Skip ip lines for now...");
            continue;
            //            value = cmdline_parse_ipaddr(NULL, token, &ip.ip, sizeof (uint32_t));
            //            if (value < 0) {
            //                INFO("Cannot read line %u, cannot parse ip %s.", line_id, token);
            //                continue;
            //            }
            //            ip.ip = rte_cpu_to_be_32(ip.ip);
            //            DEBUG("ip=%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8, ip.bytes[0], ip.bytes[1], ip.bytes[2], ip.bytes[3]);
        }
        info = gps_i_neighbor_table_get_entry(table);
        if (info == NULL) {
            gps_i_neighbor_table_cleanup(table);
            info = gps_i_neighbor_table_get_entry(table);
            if (info == NULL) {
                INFO("No entries in neighbor table! line: %u", line_id);
                continue;
            }
        }
        ether_addr_copy(&ether_addr, &info->ether);
        info->port = port;
        info->use_ip = false;
        ret = gps_i_neighbor_table_set(table, &next_hop_na, info);
        if (ret != NULL) {
            if (ret != info) {
                gps_i_neighbor_table_return_entry(table, ret);
                gps_i_neighbor_table_cleanup(table);
            } else {
                INFO("Cannot add line %u: next_hop_na=%s info %s to table, ret=%p",
                        line_id, gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
                        gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info), ret);
            }
            gps_i_neighbor_table_return_entry(table, info);
            gps_i_neighbor_table_cleanup(table);
            continue;
        }
        DEBUG("Added line %u: next_hop_na=%s info %s to table, ret=%p",
                line_id, gps_na_format(next_hop_na_buf, sizeof (next_hop_na_buf), &next_hop_na),
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), info), ret);
    }

    free(line);
    gps_i_neighbor_table_cleanup(table);
}
