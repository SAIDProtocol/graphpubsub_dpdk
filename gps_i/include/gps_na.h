/* 
 * File:   gps_na.h
 * Author: Jiachen Chen
 *
 * Created on April 12, 2019, 11:16 AM
 */

#ifndef GPS_NA_H
#define GPS_NA_H

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_memcpy.h>
#include <rte_jhash.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GPS_NA_FMT_SIZE (11)

    struct gps_na {
        uint32_t value;
    } __rte_packed;

    static __rte_always_inline struct gps_na *
    gps_na_copy(struct gps_na *dst, const struct gps_na *src) {
        dst->value = src->value;
        return dst;
    }

    static __rte_always_inline struct gps_na *
    gps_na_clear(struct gps_na *dst) {
        dst->value = 0;
        return dst;
    }

    static __rte_always_inline struct gps_na *
    gps_na_set(struct gps_na *dst, const uint32_t src) {
        dst->value = rte_cpu_to_be_32(src);
        return dst;
    }

    static __rte_always_inline int
    gps_na_cmp(const struct gps_na *na1, const struct gps_na *na2) {
        return (uint32_t) na1->value - (uint32_t) na2->value;
    }

    static __rte_always_inline bool
    gps_na_is_empty(const struct gps_na *na) {
        return na->value == 0;
    }

    static __rte_always_inline char *
    gps_na_format(char *buf, uint16_t size, const struct gps_na *na) {
        snprintf(buf, size, "<%08" PRIX32 ">", rte_be_to_cpu_32(na->value));
        return buf;
    }

    static __rte_always_inline uint32_t
    gps_na_hash(const void *key, uint32_t key_len __rte_unused, uint32_t init_val) {
//        printf("NA_HASH: key=%p\n", key);
        return rte_jhash_1word(((const struct gps_na *)key)->value, init_val);
    }


#ifdef __cplusplus
}
#endif

#endif /* GPS_NA_H */

