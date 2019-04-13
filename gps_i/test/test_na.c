/* 
 * File:   test_na.c
 * Author: Jiachen Chen
 *
 * Created on April 12, 2019, 5:57 PM
 */

#include <gps_na.h>
#include <inttypes.h>
#include <rte_jhash.h>

extern void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void test_na(void);

void
test_na(void) {
    struct gps_na na1, na2;
    char na_format[GPS_NA_FMT_SIZE];
    char content[] = {0xde, 0xad, 0xbe, 0xef};
    rte_memcpy(&na2.value, content, sizeof (struct gps_na));

    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("gps_na size: %zd\n", sizeof (struct gps_na));

    gps_na_clear(&na1);
    printf("NA1=%s\n", gps_na_format(na_format, GPS_NA_FMT_SIZE, &na1));
    printf("\tjhash NA1 %" PRIu32 "\n", rte_jhash(&na1, sizeof (na1), 0));

    gps_na_set(&na1, 0x567890ab);
    printf("NA1=%s\n", gps_na_format(na_format, GPS_NA_FMT_SIZE, &na1));
    printf("\tjhash NA1 %" PRIu32 "\n", rte_jhash(&na1, sizeof (na1), 0));

    printf("NA2=%s\n", gps_na_format(na_format, GPS_NA_FMT_SIZE, &na2));
    printf("\tcmp NA1 NA2: %d\n", gps_na_cmp(&na1, &na2));
    printf("\tjhash NA2 %" PRIu32 "\n", rte_jhash(&na2, sizeof (na2), 0));

    gps_na_copy(&na1, &na2);
    printf("NA1=%s\n", gps_na_format(na_format, GPS_NA_FMT_SIZE, &na1));
    printf("\tcmp NA1 NA2: %d\n", gps_na_cmp(&na1, &na2));
    printf("\tjhash NA1 %" PRIu32 "\n", rte_jhash(&na1, sizeof (na1), 0));
}