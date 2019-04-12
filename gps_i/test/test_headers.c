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

#define DEFAULT_WRAP 16

extern void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void test_headers(void);

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

void
test_headers(void) {
    test_header_lsa();
    printf("======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    printf("gps_pkt_application size: %zd\n", sizeof (struct gps_pkt_application));
    printf("gps_pkt_publication size: %zd\n", sizeof (struct gps_pkt_publication));
    printf("gps_pkt_subscription size: %zd\n", sizeof (struct gps_pkt_subscription));
    printf("gps_pkt_gnrs_request size: %zd\n", sizeof (struct gps_pkt_gnrs_request));
    printf("gps_pkt_gnrs_response size: %zd\n", sizeof (struct gps_pkt_gnrs_response));
    printf("gps_packet_gnrs_association size: %zd\n", sizeof (struct gps_packet_gnrs_association));
}