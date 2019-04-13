/* 
 * File:   test_guid.c
 * Author: Jiachen Chen
 *
 * Created on April 12, 2019, 5:57 PM
 */

#include <gps_guid.h>
#include <inttypes.h>
#include <rte_jhash.h>

extern void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void test_guid(void);

void
test_guid(void) {
    struct gps_guid guid1, guid2;
    char guid_format[GPS_GUID_FMT_SIZE];

    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("gps_guid size: %zd\n", sizeof (struct gps_guid));
    char content[] = {0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x09,
        0x87, 0x65, 0x43, 0x21,
        0xde, 0xad, 0xbe, 0xef};
    rte_memcpy(guid2.content, content, GPS_GUID_SIZE);

    gps_guid_clear(&guid1);
    printf("GUID1=%s\n", gps_guid_format(guid_format, GPS_GUID_FMT_SIZE, &guid1));
    printf("\tjhash GUID1 %" PRIu32 "\n", rte_jhash(&guid1, GPS_GUID_SIZE, 0));

    gps_guid_set(&guid1, 0x567890ab);
    printf("GUID1=%s\n", gps_guid_format(guid_format, GPS_GUID_FMT_SIZE, &guid1));
    printf("\tjhash GUID1 %" PRIu32 "\n", rte_jhash(&guid1, GPS_GUID_SIZE, 0));

    printf("GUID2=%s\n", gps_guid_format(guid_format, GPS_GUID_FMT_SIZE, &guid2));
    printf("\tcmp GUID1 GUID2: %d\n", gps_guid_cmp(&guid1, &guid2));
    printf("\tjhash GUID2 %" PRIu32 "\n", rte_jhash(&guid2, GPS_GUID_SIZE, 0));

    gps_guid_copy(&guid1, &guid2);
    printf("GUID1=%s\n", gps_guid_format(guid_format, GPS_GUID_FMT_SIZE, &guid1));
    printf("\tcmp GUID1 GUID2: %d\n", gps_guid_cmp(&guid1, &guid2));
    printf("\tjhash GUID1 %" PRIu32 "\n", rte_jhash(&guid1, GPS_GUID_SIZE, 0));
}
