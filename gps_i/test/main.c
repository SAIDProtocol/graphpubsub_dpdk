/* 
 * File:   main.c
 * Author: Jiachen Chen
 *
 * Created on April 11, 2019, 4:43 PM
 */

#define RTE_ENABLE_ASSERT

#include <gps_headers.h>
#include <gps_guid.h>
#include <gps_na.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_jhash.h>

#define DEFAULT_WRAP 16

static void 
print_buf(const void *buf, uint32_t size, uint32_t wrap) {
    uint32_t i, j;
    for (i = 0; i < size;) {
        printf("%04X:", i);
        for (j = 0; i < size && j < wrap; i++, j++) {
            printf(" %02X", ((const uint8_t *) buf)[i]);
        }
        printf("\n");
    }
}

static void
test_guid(void) {
    struct gps_guid guid1, guid2;
    char guid_format[GPS_GUID_FMT_SIZE];

    printf("======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
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

static void
test_na(void) {
    struct gps_na na1, na2;
    char na_format[GPS_NA_FMT_SIZE];
    char content[] = {0xde, 0xad, 0xbe, 0xef};
    rte_memcpy(&na2.value, content, sizeof (struct gps_na));

    printf("======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
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

static void
test_header_lsa(void) {

    printf("======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("gps_pkt_common size: %zd\n", sizeof (struct gps_pkt_common));
    printf("gps_pkt_lsa size: %zd\n", sizeof (struct gps_pkt_lsa));
    struct gps_pkt_lsa lsa;

    struct gps_na src_na, intermediate_na;
    char buf[1024];
    gps_na_set(&src_na, 0x567890ab);
    gps_na_set(&intermediate_na, 0x7890abcd);

    gps_pkt_lsa_init(&lsa, &src_na, &intermediate_na, 0x90abcdef);
    printf("pkt=%s\n", gps_pkt_lsa_format(buf, sizeof (buf), &lsa));
    print_buf(&lsa, sizeof (lsa), DEFAULT_WRAP);
    
    printf("src_na comp=%d, intermediate_na comp=%d, nonce=0x%08" PRIX32 "\n", 
            gps_na_cmp(gps_pkt_lsa_get_src_na(&lsa), &src_na),
            gps_na_cmp(gps_pkt_lsa_get_intermediate_na(&lsa), &intermediate_na),
            gps_pkt_lsa_get_nonce(&lsa));
    
    gps_pkt_lsa_set_src_na(&lsa, &intermediate_na);
    gps_pkt_lsa_set_intermediate_na(&lsa, &src_na);
    gps_pkt_lsa_set_nonce(&lsa, 0xdeadbeef);
    printf("pkt=%s\n", gps_pkt_lsa_format(buf, sizeof (buf), &lsa));
    print_buf(&lsa, sizeof (lsa), DEFAULT_WRAP);

    printf("src_na comp=%d, intermediate_na comp=%d, nonce=0x%08" PRIX32 "\n", 
            gps_na_cmp(gps_pkt_lsa_get_src_na(&lsa), &src_na),
            gps_na_cmp(gps_pkt_lsa_get_intermediate_na(&lsa), &intermediate_na),
            gps_pkt_lsa_get_nonce(&lsa));
}

static void
test_headers(void) {
    printf("======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("gps_pkt_application size: %zd\n", sizeof (struct gps_pkt_application));
    printf("gps_pkt_publication size: %zd\n", sizeof (struct gps_pkt_publication));
    printf("gps_pkt_subscription size: %zd\n", sizeof (struct gps_pkt_subscription));
    printf("gps_pkt_gnrs_request size: %zd\n", sizeof (struct gps_pkt_gnrs_request));
    printf("gps_pkt_gnrs_response size: %zd\n", sizeof (struct gps_pkt_gnrs_response));
    printf("gps_packet_gnrs_association size: %zd\n", sizeof (struct gps_packet_gnrs_association));
}

int
main(int argc, char **argv) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;


    test_guid();
    test_na();
    test_header_lsa();
    test_headers();

    return 0;
}


