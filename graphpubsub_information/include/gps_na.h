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
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GPS_NA_FMT_SIZE (9)

    struct gps_na {
        uint32_t value;
    } __rte_packed;

    static __rte_always_inline void
    gps_na_copy(struct gps_na *dst, const struct gps_na *src) {
        dst->value = src->value;
    }

    static __rte_always_inline void
    gps_na_clear(struct gps_na *dst) {
        dst->value = 0;
    }

    static __rte_always_inline void
    gps_na_set(struct gps_na *dst, const uint32_t src) {
        dst->value = rte_cpu_to_be_32(src);
    }

    static __rte_always_inline int
    gps_na_cmp(const struct gps_na *na1, const struct gps_na *na2) {
        return (int) na1->value - (int) na2->value;
    }

    static __rte_always_inline bool
    gps_na_is_empty(const struct gps_na *na) {
        return na->value == 0;
    }

    static __rte_always_inline char *
    gps_na_format(char *buf, uint16_t size, const struct gps_na *na) {
        snprintf(buf, size, "%08" PRIX32, rte_be_to_cpu_32(na->value));
        return buf;
    }
    
#ifdef __cplusplus
}
#endif

#endif /* GPS_NA_H */

