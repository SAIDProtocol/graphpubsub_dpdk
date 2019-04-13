/* 
 * File:   test_guid.c
 * Author: Jiachen Chen
 *
 * Created on April 12, 2019, 5:57 PM
 */

#define RTE_ENABLE_ASSERT

#include <gps_headers.h>
#include <inttypes.h>
#include <rte_jhash.h>
#include <rte_malloc.h>

#define DEFAULT_WRAP 16

extern void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void test_headers(void);

static void
test_header_lsa(void) {
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
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
            gps_na_cmp(gps_pkt_lsa_const_get_src_na(&lsa), &src_na),
            gps_na_cmp(gps_pkt_lsa_const_get_intermediate_na(&lsa), &intermediate_na),
            gps_pkt_lsa_const_get_nonce(&lsa));

    gps_pkt_lsa_set_src_na(&lsa, &intermediate_na);
    gps_pkt_lsa_set_intermediate_na(&lsa, &src_na);
    gps_pkt_lsa_set_nonce(&lsa, 0xdeadbeef);
    printf("pkt=%s\n", gps_pkt_lsa_format(buf, sizeof (buf), &lsa));
    print_buf(&lsa, sizeof (lsa), DEFAULT_WRAP);

    printf("src_na comp=%d, intermediate_na comp=%d, nonce=0x%08" PRIX32 "\n",
            gps_na_cmp(gps_pkt_lsa_const_get_src_na(&lsa), &src_na),
            gps_na_cmp(gps_pkt_lsa_const_get_intermediate_na(&lsa), &intermediate_na),
            gps_pkt_lsa_const_get_nonce(&lsa));
}

static void
test_header_publication(void) {
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("gps_pkt_application size: %zd\n", sizeof (struct gps_pkt_application));
    printf("gps_pkt_publication size: %zd\n", sizeof (struct gps_pkt_publication));

    //    struct gps_pkt_publication *pub;
    uint8_t *publication;

    struct gps_guid src_guid, dst_guid;
    struct gps_na src_na, dst_na;
    char src_guid_content[] = {
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x09,
        0x87, 0x65, 0x43, 0x21,
        0xde, 0xad, 0xbe, 0xef
    };
    char dst_guid_content[] = {
        0x1f, 0xed, 0xcb, 0xa0,
        0x98, 0x76, 0x54, 0x32,
        0x23, 0x45, 0x67, 0x89,
        0x0a, 0xbc, 0xde, 0xf1,
        0xda, 0xed, 0xfe, 0xeb
    };
    uint32_t size = 10, buf_size = sizeof (struct gps_pkt_publication) +size;
    char buf_print[1024];
    printf("size=%" PRIu32 ", buf_size=%" PRIu32 "\n", size, buf_size);


    rte_memcpy(src_guid.content, src_guid_content, GPS_GUID_SIZE);
    rte_memcpy(dst_guid.content, dst_guid_content, GPS_GUID_SIZE);

    gps_na_set(&src_na, 0x567890ab);
    gps_na_set(&dst_na, 0x7890abcd);

    publication = rte_malloc("publication", buf_size, 16);

    if (publication == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot malloc content!");
    }

    gps_pkt_publication_init(publication, &src_guid, &dst_guid, &src_na, &dst_na, size);
    printf("pkt=%s\n", gps_pkt_publication_format(buf_print, sizeof(buf_print), publication));

    print_buf(publication, buf_size, 16);


    rte_free(publication);
}

static void
test_header_subscription(void) {
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("gps_pkt_subscription size: %zd\n", sizeof (struct gps_pkt_subscription));

    struct gps_pkt_subscription sub;

    struct gps_guid src_guid, dst_guid;
    struct gps_na src_na, dst_na;
    char src_guid_content[] = {
        0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x09,
        0x87, 0x65, 0x43, 0x21,
        0xde, 0xad, 0xbe, 0xef
    };
    char dst_guid_content[] = {
        0x1f, 0xed, 0xcb, 0xa0,
        0x98, 0x76, 0x54, 0x32,
        0x23, 0x45, 0x67, 0x89,
        0x0a, 0xbc, 0xde, 0xf1,
        0xda, 0xed, 0xfe, 0xeb
    };
    char buf_print[1024];


    rte_memcpy(src_guid.content, src_guid_content, GPS_GUID_SIZE);
    rte_memcpy(dst_guid.content, dst_guid_content, GPS_GUID_SIZE);

    gps_na_set(&src_na, 0x567890ab);
    gps_na_set(&dst_na, 0x7890abcd);

    gps_pkt_subscription_init(&sub, &src_guid, &dst_guid, &src_na, &dst_na, true);
    printf("pkt=%s\n", gps_pkt_subscription_format(buf_print, sizeof(buf_print), &sub));
    print_buf(&sub, sizeof(sub), 16);

    gps_pkt_subscription_set_subscribe(&sub, false);
    printf("pkt=%s\n", gps_pkt_subscription_format(buf_print, sizeof(buf_print), &sub));
    print_buf(&sub, sizeof(sub), 16);
}

void
test_headers(void) {
    test_header_lsa();
    test_header_publication();
    test_header_subscription();
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("gps_pkt_gnrs_request size: %zd\n", sizeof (struct gps_pkt_gnrs_request));
    printf("gps_pkt_gnrs_response size: %zd\n", sizeof (struct gps_pkt_gnrs_response));
    printf("gps_packet_gnrs_association size: %zd\n", sizeof (struct gps_packet_gnrs_association));
}