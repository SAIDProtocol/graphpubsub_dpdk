/* 
 * File:   guid.h
 * Author: Jiachen Chen
 *
 * Created on April 12, 2019, 9:35 AM
 */

#ifndef GPS_GUID_H
#define GPS_GUID_H

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_jhash.h>
#include <rte_memcpy.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

    /** Size of GUID, 8-20 bytes preferred, better align to 4 bytes. */
#define GPS_GUID_SIZE 12

#if GPS_GUID_SIZE == 20
#define GPS_GUID_FMT_SIZE (49)
#elif GPS_GUID_SIZE == 16
#define GPS_GUID_FMT_SIZE (40)
#elif GPS_GUID_SIZE == 12
#define GPS_GUID_FMT_SIZE (31)
#elif GPS_GUID_SIZE == 8
#define GPS_GUID_FMT_SIZE (22)
#else
#define GPS_GUID_FMT_SIZE (17)
#endif

    struct gps_guid {
        uint8_t content[GPS_GUID_SIZE];
    } __rte_packed;

    static __rte_always_inline void
    gps_guid_copy(struct gps_guid *dst, const struct gps_guid *src) {
        rte_memcpy(dst, src, GPS_GUID_SIZE);
    }

    static __rte_always_inline void
    gps_guid_clear(struct gps_guid *dst) {
        memset(dst, 0, GPS_GUID_SIZE);
    }

    static __rte_always_inline void
    gps_guid_set(struct gps_guid *dst, const uint32_t src) {
        gps_guid_clear(dst);
        *((uint32_t *) (dst->content + GPS_GUID_SIZE - sizeof (uint32_t))) = rte_cpu_to_be_32(src);
    }

    static __rte_always_inline int
    gps_guid_cmp(const struct gps_guid *guid1, const struct gps_guid *guid2) {
        return memcmp(guid1, guid2, GPS_GUID_SIZE);
    }

    static __rte_always_inline char *
    gps_guid_format(char *buf, uint16_t size, const struct gps_guid *guid) {
#if GPS_GUID_SIZE == 20
        snprintf(buf, size, "<<%02X%02X%02X%02X:%02X%02X%02X%02X:%02X%02X%02X%02X:%02X%02X%02X%02X:%02X%02X%02X%02X>>",
                guid->content[0], guid->content[1], guid->content[2], guid->content[3],
                guid->content[4], guid->content[5], guid->content[6], guid->content[7],
                guid->content[8], guid->content[9], guid->content[10], guid->content[11],
                guid->content[12], guid->content[13], guid->content[14], guid->content[15],
                guid->content[16], guid->content[17], guid->content[18], guid->content[19]);
#elif GPS_GUID_SIZE == 16
        snprintf(buf, size, "<<%02X%02X%02X%02X:%02X%02X%02X%02X:%02X%02X%02X%02X:%02X%02X%02X%02X>>",
                guid->content[0], guid->content[1], guid->content[2], guid->content[3],
                guid->content[4], guid->content[5], guid->content[6], guid->content[7],
                guid->content[8], guid->content[9], guid->content[10], guid->content[11],
                guid->content[12], guid->content[13], guid->content[14], guid->content[15]);
#elif GPS_GUID_SIZE == 12
        snprintf(buf, size, "<<%02X%02X%02X%02X:%02X%02X%02X%02X:%02X%02X%02X%02X>>",
                guid->content[0], guid->content[1], guid->content[2], guid->content[3],
                guid->content[4], guid->content[5], guid->content[6], guid->content[7],
                guid->content[8], guid->content[9], guid->content[10], guid->content[11]);
#elif GPS_GUID_SIZE == 8
        snprintf(buf, size, "<<%02X%02X%02X%02X:%02X%02X%02X%02X>>",
                guid->content[0], guid->content[1], guid->content[2], guid->content[3],
                guid->content[4], guid->content[5], guid->content[6], guid->content[7]);
#else
        RTE_SET_USED(buf);
        RTE_SET_USED(size);
        RTE_SET_USED(guid);
        snprintf(buf, size, "<<CANNOT PRINT>>");
#endif
        return buf;
    }

    static __rte_always_inline uint32_t
    gps_guid_hash(const void *key, uint32_t key_len __rte_unused, uint32_t init_val) {
        //        printf("GUID_HASH: key=%p\n", key);
#if GPS_GUID_SIZE == 12
        const union {
            struct gps_guid guid;
            uint32_t vals[3];
        } *x = key;
        return rte_jhash_3words(x->vals[0], x->vals[1], x->vals[2], init_val);
#elif GPS_GUID_SIZE == 8

        const union {
            struct gps_guid guid;
            uint32_t vals[2];
        } *x = key;
        return rte_jhash_2words(x->vals[0], x->vals[1], init_val);
#else
        return rte_jhash(key GPS_GUID_SIZE, init_val);
#endif

    }

#ifdef __cplusplus
}
#endif

#endif /* GPS_GUID_H */

