/* 
 * File:   test_neighbor_table.c
 * Author: Jiachen Chen
 *
 * Created on April 14, 2019, 2:56 AM
 */
#include <inttypes.h>
#include <rte_hash.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include "gps_i_neighbor_table.h"

extern void print_buf(const void *buf, uint32_t size, uint32_t wrap);
void test_neighbor_table(void);

static void
print_neighbor_table(void) {
    printf("#### Neighbor Table (%" PRIi32 ") ####\n", rte_hash_count(gps_i_neighbor_keys));

    const void *na;
    void *data;
    uint32_t next = 0;
    int32_t position;
    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];

    for (;;) {
        position = rte_hash_iterate(gps_i_neighbor_keys, &na, &data, &next);
        if (position == -ENOENT)
            break;

        if (position < 0)
            rte_exit(EXIT_FAILURE, "Error in iterating neighbor table. position=%" PRIi32 ".\n", position);

        printf("  %s (%d)\t %s\n",
                gps_na_format(na_buf, GPS_NA_FMT_SIZE, na),
                position,
                gps_i_neighbor_info_format(info_buf, sizeof (info_buf), gps_i_neighbor_values + position));

    }

    printf("##########\n");
}

static void
test_neighbor_table_basic(void) {
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);

    struct gps_i_neighbor_info info = {
        .ether =
        {.addr_bytes =
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
        .ip = IPv4(192, 168, 123, 234),
        .port = 54321,
        .use_ip = true
    };
    const struct gps_i_neighbor_info *result;
    struct gps_na na;
    gps_na_set(&na, 0x12345678);

    char na_buf[GPS_NA_FMT_SIZE], info_buf[GPS_I_NEIGHBOR_INFO_FMT_SIZE];
    struct ether_addr addr2 = {.addr_bytes =
        {0x11, 0x22, 0x33, 0x44, 0x55, 0x66}};
    int32_t ret;

    printf("buf=%s\n", gps_i_neighbor_info_format(info_buf, sizeof (info_buf), &info));
    print_buf(&info, sizeof (info), 16);


    gps_i_neighbor_table_init(1023, rte_socket_id());

    print_neighbor_table();

    ret = gps_i_neighbor_table_set(&na, &info);
    printf("set %s->%s: %" PRIi32 "\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), &info),
            ret);
    print_neighbor_table();

    info.ip = IPv4(192, 168, 1, 2);
    info.port = 1234;
    rte_memcpy(&info.ether, &addr2, sizeof (struct ether_addr));


    ret = gps_i_neighbor_table_set(&na, &info);
    printf("set %s->%s: %" PRIi32 "\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), &info),
            ret);
    print_neighbor_table();

    memset(&info.ether, 0x39, sizeof (info.ether));
    info.port = 7890;
    gps_na_set(&na, 0x87654321);

    info.use_ip = false;
    ret = gps_i_neighbor_table_set(&na, &info);
    printf("set %s->%s: %" PRIi32 "\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), &info),
            ret);
    print_neighbor_table();

    gps_na_set(&na, 0x12345678);
    result = gps_i_neighbor_table_lookup(&na);
    printf("lookup %s -> [%p] %s\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result,
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result));

    gps_na_set(&na, 0x87654321);
    result = gps_i_neighbor_table_lookup(&na);
    printf("lookup %s -> [%p] %s\n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result,
            gps_i_neighbor_info_format(info_buf, sizeof (info_buf), result));

    gps_na_set(&na, 0x77654321);
    result = gps_i_neighbor_table_lookup(&na);
    printf("lookup %s -> [%p] \n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result);

    ret = gps_i_neighbor_table_delete(&na);
    printf("delete %s: %" PRIi32 "\n", gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    print_neighbor_table();

    gps_na_set(&na, 0x12345678);
    ret = gps_i_neighbor_table_delete(&na);
    printf("delete %s: %" PRIi32 "\n", gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    print_neighbor_table();

    result = gps_i_neighbor_table_lookup(&na);
    printf("lookup %s -> [%p] \n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result);

    gps_na_set(&na, 0x87654321);
    ret = gps_i_neighbor_table_delete(&na);
    printf("delete %s: %" PRIi32 "\n", gps_na_format(na_buf, sizeof (na_buf), &na), ret);
    print_neighbor_table();

    result = gps_i_neighbor_table_lookup(&na);
    printf("lookup %s -> [%p] \n",
            gps_na_format(na_buf, sizeof (na_buf), &na),
            result);

    gps_i_neighbor_table_destroy();
}

static void test_neighbor_table_rcu(void) {
    printf("\n======%s:%d %s()======\n", __FILE__, __LINE__, __FUNCTION__);
    gps_i_neighbor_table_init(1023, rte_socket_id());

    gps_i_neighbor_table_destroy();
}

void
test_neighbor_table(void) {
    test_neighbor_table_basic();
    test_neighbor_table_rcu();
}