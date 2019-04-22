#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_eal.h>
#include <stddef.h>
#include <stdint.h>

#define MEMPOOL_CACHE_SIZE 256

struct private_data {
    uint64_t d1;
    uint32_t d2;
    MARKER64 marker;
    uint8_t d3[16];
} __rte_aligned(RTE_MBUF_PRIV_ALIGN);

static void
my_mbuf_free_callback(void *addr, __rte_unused void *opaque) {
    printf("free: %p\n", addr);
}

static void
test_mbuf(void) {

    struct rte_mempool *pool;
    struct rte_mbuf *buf1, *buf2, *buf3, *buf;
    struct rte_mbuf_ext_shared_info *shinfo;

    printf("size of private data: %zd, d1@%" PRIuPTR
            ", d2@%" PRIuPTR
            ", marker@%" PRIuPTR
            ", d3@%" PRIuPTR "\n",
            sizeof (struct private_data),
            offsetof(struct private_data, d1),
            offsetof(struct private_data, d2),
            offsetof(struct private_data, marker),
            offsetof(struct private_data, d3));



    pool = rte_pktmbuf_pool_create(__FUNCTION__, 1023, MEMPOOL_CACHE_SIZE, sizeof (struct private_data), RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (pool == NULL) {
        rte_exit(EXIT_FAILURE, "[%s:%d] %s: Cannot create pool.\n", __FILE__, __LINE__, __FUNCTION__);
    }

    printf("[%s:%d] %s: Created pool.\n", __FILE__, __LINE__, __FUNCTION__);

    printf("buf size: %zd, shinfo size: %zd\n", sizeof (*buf), sizeof(*shinfo));

    buf = buf1 = rte_pktmbuf_alloc(pool);
    if (buf == NULL) {
        rte_exit(EXIT_FAILURE, "[%s:%d] %s: Cannot create buf.\n", __FILE__, __LINE__, __FUNCTION__);
    }
    printf("buf=%p, buf->buf_len=%" PRIu16 ", priv=%p, addr=%p, data=%p\n", buf, buf->buf_len, rte_mbuf_to_priv(buf), buf->buf_addr, rte_pktmbuf_mtod(buf, void *));
    shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf->buf_addr, &buf->buf_len, my_mbuf_free_callback, NULL);
    if (shinfo == NULL) {
        rte_exit(EXIT_FAILURE, "[%s:%d] %s: Cannot create shinfo.\n", __FILE__, __LINE__, __FUNCTION__);
    }
    printf("shinfo=%p, buf->buf_len=%" PRIu16 "\n", shinfo, buf->buf_len);
    rte_pktmbuf_attach_extbuf(buf, buf->buf_addr, buf->buf_iova, buf->buf_len, shinfo);

    buf = buf2 = rte_pktmbuf_alloc(pool);
    if (buf == NULL) {
        rte_exit(EXIT_FAILURE, "[%s:%d] %s: Cannot create buf.\n", __FILE__, __LINE__, __FUNCTION__);
    }
    printf("buf=%p, buf->buf_len=%" PRIu16 ", priv=%p, addr=%p, data=%p\n", buf, buf->buf_len, rte_mbuf_to_priv(buf), buf->buf_addr, rte_pktmbuf_mtod(buf, void *));
    shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf->buf_addr, &buf->buf_len, my_mbuf_free_callback, NULL);
    if (shinfo == NULL) {
        rte_exit(EXIT_FAILURE, "[%s:%d] %s: Cannot create shinfo.\n", __FILE__, __LINE__, __FUNCTION__);
    }
    printf("shinfo=%p, buf->buf_len=%" PRIu16 "\n", shinfo, buf->buf_len);
    rte_pktmbuf_attach_extbuf(buf, buf->buf_addr, buf->buf_iova, buf->buf_len, shinfo);

    buf = buf3 = rte_pktmbuf_alloc(pool);
    rte_pktmbuf_attach(buf2, buf3);
    if (buf == NULL) {
        rte_exit(EXIT_FAILURE, "[%s:%d] %s: Cannot create buf.\n", __FILE__, __LINE__, __FUNCTION__);
    }
    printf("buf=%p, buf->buf_len=%" PRIu16 ", priv=%p, addr=%p, data=%p\n", buf, buf->buf_len, rte_mbuf_to_priv(buf), buf->buf_addr, rte_pktmbuf_mtod(buf, void *));
    shinfo = rte_pktmbuf_ext_shinfo_init_helper(buf->buf_addr, &buf->buf_len, my_mbuf_free_callback, NULL);
    if (shinfo == NULL) {
        rte_exit(EXIT_FAILURE, "[%s:%d] %s: Cannot create shinfo.\n", __FILE__, __LINE__, __FUNCTION__);
    }
    printf("shinfo=%p, buf->buf_len=%" PRIu16 "\n", shinfo, buf->buf_len);
    rte_pktmbuf_attach_extbuf(buf, buf->buf_addr, buf->buf_iova, buf->buf_len, shinfo);

    
    
    rte_pktmbuf_free(buf1);
    rte_pktmbuf_free(buf2);
//    rte_pktmbuf_free(buf3);
}

int
main(int argc, char **argv) {
    int ret;

    ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
    argc -= ret;
    argv += ret;

    test_mbuf();

    return 0;
}

