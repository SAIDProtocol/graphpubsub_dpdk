/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright(c) 2018 Arm Limited
 */

#include <inttypes.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_memory.h>         /* for definition of RTE_CACHE_LINE_SIZE */
#include <rte_log.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_per_lcore.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_rwlock.h>
#include <rte_spinlock.h>
#include <rte_ring.h>
#include <rte_compat.h>

#include "rte_hash.h"
#include "rte_cuckoo_hash.h"

#define FOR_EACH_BUCKET(CURRENT_BKT, START_BUCKET)                            \
	for (CURRENT_BKT = START_BUCKET;                                      \
		CURRENT_BKT != NULL;                                          \
		CURRENT_BKT = CURRENT_BKT->next)

TAILQ_HEAD(rte_hash_list, rte_tailq_entry);

static struct rte_tailq_elem rte_hash_tailq = {
	.name = "RTE_HASH_x",
};
EAL_REGISTER_TAILQ(rte_hash_tailq)

struct rte_hash_x *
rte_hash_find_existing_x(const char *name)
{
	struct rte_hash_x *h = NULL;
	struct rte_tailq_entry *te;
	struct rte_hash_list *hash_list;

	hash_list = RTE_TAILQ_CAST(rte_hash_tailq.head, rte_hash_list);

	rte_rwlock_read_lock(RTE_EAL_TAILQ_RWLOCK);
	TAILQ_FOREACH(te, hash_list, next) {
		h = (struct rte_hash_x *) te->data;
		if (strncmp(name, h->name, RTE_HASH_NAMESIZE) == 0)
			break;
	}
	rte_rwlock_read_unlock(RTE_EAL_TAILQ_RWLOCK);

	if (te == NULL) {
		rte_errno = ENOENT;
		return NULL;
	}
	return h;
}

static inline struct rte_hash_bucket_x *
rte_hash_get_last_bkt_x(struct rte_hash_bucket_x *lst_bkt)
{
	while (lst_bkt->next != NULL)
		lst_bkt = lst_bkt->next;
	return lst_bkt;
}

void rte_hash_set_cmp_func_x(struct rte_hash_x *h, rte_hash_cmp_eq_t func)
{
	h->cmp_jump_table_idx = KEY_CUSTOM;
	h->rte_hash_custom_cmp_eq = func;
}

static inline int
rte_hash_cmp_eq_x(const void *key1, const void *key2, const struct rte_hash_x *h)
{
	if (h->cmp_jump_table_idx == KEY_CUSTOM)
		return h->rte_hash_custom_cmp_eq(key1, key2, h->key_len);
	else
		return cmp_jump_table_x[h->cmp_jump_table_idx](key1, key2, h->key_len);
}

/*
 * We use higher 16 bits of hash as the signature value stored in table.
 * We use the lower bits for the primary bucket
 * location. Then we XOR primary bucket location and the signature
 * to get the secondary bucket location. This is same as
 * proposed in Bin Fan, et al's paper
 * "MemC3: Compact and Concurrent MemCache with Dumber Caching and
 * Smarter Hashing". The benefit to use
 * XOR is that one could derive the alternative bucket location
 * by only using the current bucket location and the signature.
 */
static inline uint16_t
get_short_sig_x(const hash_sig_t hash)
{
	return hash >> 16;
}

static inline uint32_t
get_prim_bucket_index_x(const struct rte_hash_x *h, const hash_sig_t hash)
{
	return hash & h->bucket_bitmask;
}

static inline uint32_t
get_alt_bucket_index_x(const struct rte_hash_x *h,
			uint32_t cur_bkt_idx, uint16_t sig)
{
	return (cur_bkt_idx ^ sig) & h->bucket_bitmask;
}

struct rte_hash_x *
rte_hash_create_x(const struct rte_hash_parameters_x *params)
{
	struct rte_hash_x *h = NULL;
	struct rte_tailq_entry *te = NULL;
	struct rte_hash_list *hash_list;
	struct rte_ring *r = NULL;
	struct rte_ring *r_ext = NULL;
	char hash_name[RTE_HASH_NAMESIZE];
	void *k = NULL;
	void *buckets = NULL;
	void *buckets_ext = NULL;
	char ring_name[RTE_RING_NAMESIZE];
	char ext_ring_name[RTE_RING_NAMESIZE];
	unsigned num_key_slots;
	unsigned i;
	unsigned int hw_trans_mem_support = 0, use_local_cache = 0;
	unsigned int ext_table_support = 0;
	unsigned int readwrite_concur_support = 0;
	unsigned int writer_takes_lock = 0;
	unsigned int no_free_on_del = 0;
	uint32_t *tbl_chng_cnt = NULL;
	unsigned int readwrite_concur_lf_support = 0;

	rte_hash_function default_hash_func = (rte_hash_function)rte_jhash;

	hash_list = RTE_TAILQ_CAST(rte_hash_tailq.head, rte_hash_list);

	if (params == NULL) {
		RTE_LOG(ERR, HASH, "rte_hash_create has no parameters\n");
		return NULL;
	}

	/* Check for valid parameters */
	if ((params->entries > RTE_HASH_ENTRIES_MAX) ||
			(params->entries < RTE_HASH_BUCKET_ENTRIES) ||
			(params->key_len == 0)) {
		rte_errno = EINVAL;
		RTE_LOG(ERR, HASH, "rte_hash_create has invalid parameters\n");
		return NULL;
	}

	/* Validate correct usage of extra options */
	if ((params->extra_flag & RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY) &&
	    (params->extra_flag & RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF)) {
		rte_errno = EINVAL;
		RTE_LOG(ERR, HASH, "rte_hash_create: choose rw concurrency or "
			"rw concurrency lock free\n");
		return NULL;
	}

	if ((params->extra_flag & RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF) &&
	    (params->extra_flag & RTE_HASH_EXTRA_FLAGS_EXT_TABLE)) {
		rte_errno = EINVAL;
		RTE_LOG(ERR, HASH, "rte_hash_create: extendable bucket "
			"feature not supported with rw concurrency "
			"lock free\n");
		return NULL;
	}

	/* Check extra flags field to check extra options. */
	if (params->extra_flag & RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT)
		hw_trans_mem_support = 1;

	if (params->extra_flag & RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD) {
		use_local_cache = 1;
		writer_takes_lock = 1;
	}

	if (params->extra_flag & RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY) {
		readwrite_concur_support = 1;
		writer_takes_lock = 1;
	}

	if (params->extra_flag & RTE_HASH_EXTRA_FLAGS_EXT_TABLE)
		ext_table_support = 1;

	if (params->extra_flag & RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL)
		no_free_on_del = 1;

	if (params->extra_flag & RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF) {
		readwrite_concur_lf_support = 1;
		/* Enable not freeing internal memory/index on delete */
		no_free_on_del = 1;
	}

	/* Store all keys and leave the first entry as a dummy entry for lookup_bulk */
	if (use_local_cache)
		/*
		 * Increase number of slots by total number of indices
		 * that can be stored in the lcore caches
		 * except for the first cache
		 */
		num_key_slots = params->entries + (RTE_MAX_LCORE - 1) *
					(LCORE_CACHE_SIZE - 1) + 1;
	else
		num_key_slots = params->entries + 1;

	snprintf(ring_name, sizeof(ring_name), "HT_%s", params->name);
	/* Create ring (Dummy slot index is not enqueued) */
	r = rte_ring_create(ring_name, rte_align32pow2(num_key_slots),
			params->socket_id, 0);
//        RTE_LOG(DEBUG, HASH, "free slot size=%" PRIu32 "\n", r->size);
	if (r == NULL) {
		RTE_LOG(ERR, HASH, "memory allocation failed\n");
		goto err;
	}

	const uint32_t num_buckets = rte_align32pow2(params->entries) /
						RTE_HASH_BUCKET_ENTRIES;
//        RTE_LOG(DEBUG, HASH,"num_buckets=%" PRIu32 "\n", num_buckets);

	/* Create ring for extendable buckets. */
	if (ext_table_support) {
		snprintf(ext_ring_name, sizeof(ext_ring_name), "HT_EXT_%s",
								params->name);
		r_ext = rte_ring_create(ext_ring_name,
				rte_align32pow2(num_buckets + 1),
				params->socket_id, 0);

		if (r_ext == NULL) {
			RTE_LOG(ERR, HASH, "ext buckets memory allocation "
								"failed\n");
			goto err;
		}
	}

	snprintf(hash_name, sizeof(hash_name), "HT_%s", params->name);

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* guarantee there's no existing: this is normally already checked
	 * by ring creation above */
	TAILQ_FOREACH(te, hash_list, next) {
		h = (struct rte_hash_x *) te->data;
		if (strncmp(params->name, h->name, RTE_HASH_NAMESIZE) == 0)
			break;
	}
	h = NULL;
	if (te != NULL) {
		rte_errno = EEXIST;
		te = NULL;
		goto err_unlock;
	}

	te = rte_zmalloc("HASH_TAILQ_ENTRY", sizeof(*te), 0);
	if (te == NULL) {
		RTE_LOG(ERR, HASH, "tailq entry allocation failed\n");
		goto err_unlock;
	}

	h = (struct rte_hash_x *)rte_zmalloc_socket(hash_name, sizeof(struct rte_hash_x),
					RTE_CACHE_LINE_SIZE, params->socket_id);

	if (h == NULL) {
		RTE_LOG(ERR, HASH, "memory allocation failed\n");
		goto err_unlock;
	}

	buckets = rte_zmalloc_socket(NULL,
				num_buckets * sizeof(struct rte_hash_bucket_x),
				RTE_CACHE_LINE_SIZE, params->socket_id);

	if (buckets == NULL) {
		RTE_LOG(ERR, HASH, "buckets memory allocation failed\n");
		goto err_unlock;
	}

	/* Allocate same number of extendable buckets */
	if (ext_table_support) {
		buckets_ext = rte_zmalloc_socket(NULL,
				num_buckets * sizeof(struct rte_hash_bucket_x),
				RTE_CACHE_LINE_SIZE, params->socket_id);
		if (buckets_ext == NULL) {
			RTE_LOG(ERR, HASH, "ext buckets memory allocation "
							"failed\n");
			goto err_unlock;
		}
		/* Populate ext bkt ring. We reserve 0 similar to the
		 * key-data slot, just in case in future we want to
		 * use bucket index for the linked list and 0 means NULL
		 * for next bucket
		 */
		for (i = 1; i <= num_buckets; i++)
			rte_ring_sp_enqueue(r_ext, (void *)((uintptr_t) i));
	}

	const uint32_t key_entry_size =
		RTE_ALIGN(sizeof(struct rte_hash_key_x) + params->key_len,
			  KEY_ALIGNMENT);
	const uint64_t key_tbl_size = (uint64_t) key_entry_size * num_key_slots;
//        RTE_LOG(DEBUG, HASH, "key_tbl_size=%" PRIu64 ", key_entry_size=%" PRIu32 
//		", num_key_slots=%u\n", key_tbl_size, key_entry_size, num_key_slots);

	k = rte_zmalloc_socket(NULL, key_tbl_size,
			RTE_CACHE_LINE_SIZE, params->socket_id);

	if (k == NULL) {
		RTE_LOG(ERR, HASH, "memory allocation failed\n");
		goto err_unlock;
	}

	tbl_chng_cnt = rte_zmalloc_socket(NULL, sizeof(uint32_t),
			RTE_CACHE_LINE_SIZE, params->socket_id);

	if (tbl_chng_cnt == NULL) {
		RTE_LOG(ERR, HASH, "memory allocation failed\n");
		goto err_unlock;
	}

/*
 * If x86 architecture is used, select appropriate compare function,
 * which may use x86 intrinsics, otherwise use memcmp
 */
#if defined(RTE_ARCH_X86) || defined(RTE_ARCH_ARM64)
	/* Select function to compare keys */
	switch (params->key_len) {
	case 4:
		h->cmp_jump_table_idx = KEY_4_BYTES;
		break;
	case 8:
		h->cmp_jump_table_idx = KEY_8_BYTES;
		break;
	case 12:
		h->cmp_jump_table_idx = KEY_12_BYTES;
		break;
	case 16:
		h->cmp_jump_table_idx = KEY_16_BYTES;
		break;
	case 32:
		h->cmp_jump_table_idx = KEY_32_BYTES;
		break;
	case 48:
		h->cmp_jump_table_idx = KEY_48_BYTES;
		break;
	case 64:
		h->cmp_jump_table_idx = KEY_64_BYTES;
		break;
	case 80:
		h->cmp_jump_table_idx = KEY_80_BYTES;
		break;
	case 96:
		h->cmp_jump_table_idx = KEY_96_BYTES;
		break;
	case 112:
		h->cmp_jump_table_idx = KEY_112_BYTES;
		break;
	case 128:
		h->cmp_jump_table_idx = KEY_128_BYTES;
		break;
	default:
		/* If key is not multiple of 16, use generic memcmp */
		h->cmp_jump_table_idx = KEY_OTHER_BYTES;
	}
#else
	h->cmp_jump_table_idx = KEY_OTHER_BYTES;
#endif

	if (use_local_cache) {
		h->local_free_slots = rte_zmalloc_socket(NULL,
				sizeof(struct lcore_cache_x) * RTE_MAX_LCORE,
				RTE_CACHE_LINE_SIZE, params->socket_id);
	}

	/* Default hash function */
#if defined(RTE_ARCH_X86)
	default_hash_func = (rte_hash_function)rte_hash_crc;
#elif defined(RTE_ARCH_ARM64)
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_CRC32))
		default_hash_func = (rte_hash_function)rte_hash_crc;
#endif
	/* Setup hash context */
	snprintf(h->name, sizeof(h->name), "%s", params->name);
	h->entries = params->entries;
	h->key_len = params->key_len;
	h->key_entry_size = key_entry_size;
	h->hash_func_init_val = params->hash_func_init_val;

	h->num_buckets = num_buckets;
	h->bucket_bitmask = h->num_buckets - 1;
	h->buckets = buckets;
	h->buckets_ext = buckets_ext;
	h->free_ext_bkts = r_ext;
	h->hash_func = (params->hash_func == NULL) ?
		default_hash_func : params->hash_func;
	h->key_store = k;
	h->free_slots = r;
	h->tbl_chng_cnt = tbl_chng_cnt;
	*h->tbl_chng_cnt = 0;
	h->hw_trans_mem_support = hw_trans_mem_support;
	h->use_local_cache = use_local_cache;
	h->readwrite_concur_support = readwrite_concur_support;
	h->ext_table_support = ext_table_support;
	h->writer_takes_lock = writer_takes_lock;
	h->no_free_on_del = no_free_on_del;
	h->readwrite_concur_lf_support = readwrite_concur_lf_support;

#if defined(RTE_ARCH_X86)
	if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE2))
		h->sig_cmp_fn = RTE_HASH_COMPARE_SSE;
	else
#endif
		h->sig_cmp_fn = RTE_HASH_COMPARE_SCALAR;

	/* Writer threads need to take the lock when:
	 * 1) RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY is enabled OR
	 * 2) RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD is enabled
	 */
	if (h->writer_takes_lock) {
		h->readwrite_lock = rte_malloc(NULL, sizeof(rte_rwlock_t),
						RTE_CACHE_LINE_SIZE);
		if (h->readwrite_lock == NULL)
			goto err_unlock;

		rte_rwlock_init(h->readwrite_lock);
	}

	/* Populate free slots ring. Entry zero is reserved for key misses. */
	for (i = 1; i < num_key_slots; i++)
		rte_ring_sp_enqueue(r, (void *)((uintptr_t) i));

	te->data = (void *) h;
	TAILQ_INSERT_TAIL(hash_list, te, next);
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	return h;
err_unlock:
	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);
err:
	rte_ring_free(r);
	rte_ring_free(r_ext);
	rte_free(te);
	rte_free(h);
	rte_free(buckets);
	rte_free(buckets_ext);
	rte_free(k);
	rte_free(tbl_chng_cnt);
	return NULL;
}

void
rte_hash_free_x(struct rte_hash_x *h)
{
	struct rte_tailq_entry *te;
	struct rte_hash_list *hash_list;

	if (h == NULL)
		return;

	hash_list = RTE_TAILQ_CAST(rte_hash_tailq.head, rte_hash_list);

	rte_rwlock_write_lock(RTE_EAL_TAILQ_RWLOCK);

	/* find out tailq entry */
	TAILQ_FOREACH(te, hash_list, next) {
		if (te->data == (void *) h)
			break;
	}

	if (te == NULL) {
		rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);
		return;
	}

	TAILQ_REMOVE(hash_list, te, next);

	rte_rwlock_write_unlock(RTE_EAL_TAILQ_RWLOCK);

	if (h->use_local_cache)
		rte_free(h->local_free_slots);
	if (h->writer_takes_lock)
		rte_free(h->readwrite_lock);
	rte_ring_free(h->free_slots);
	rte_ring_free(h->free_ext_bkts);
	rte_free(h->key_store);
	rte_free(h->buckets);
	rte_free(h->buckets_ext);
	rte_free(h->tbl_chng_cnt);
	rte_free(h);
	rte_free(te);
}

hash_sig_t
rte_hash_hash_x(const struct rte_hash_x *h, const void *key)
{
	/* calc hash result by key */
	return h->hash_func(key, h->key_len, h->hash_func_init_val);
}

int32_t
rte_hash_count_x(const struct rte_hash_x *h)
{
	uint32_t tot_ring_cnt, cached_cnt = 0;
	uint32_t i, ret;

	if (h == NULL)
		return -EINVAL;

	if (h->use_local_cache) {
		tot_ring_cnt = h->entries + (RTE_MAX_LCORE - 1) *
					(LCORE_CACHE_SIZE - 1);
		for (i = 0; i < RTE_MAX_LCORE; i++)
			cached_cnt += h->local_free_slots[i].len;

		ret = tot_ring_cnt - rte_ring_count(h->free_slots) -
								cached_cnt;
	} else {
		tot_ring_cnt = h->entries;
		ret = tot_ring_cnt - rte_ring_count(h->free_slots);
	}
	return ret;
}

/* Read write locks implemented using rte_rwlock */
static inline void
__hash_rw_writer_lock_x(const struct rte_hash_x *h)
{
	if (h->writer_takes_lock && h->hw_trans_mem_support)
		rte_rwlock_write_lock_tm(h->readwrite_lock);
	else if (h->writer_takes_lock)
		rte_rwlock_write_lock(h->readwrite_lock);
}

static inline void
__hash_rw_reader_lock_x(const struct rte_hash_x *h)
{
	if (h->readwrite_concur_support && h->hw_trans_mem_support)
		rte_rwlock_read_lock_tm(h->readwrite_lock);
	else if (h->readwrite_concur_support)
		rte_rwlock_read_lock(h->readwrite_lock);
}

static inline void
__hash_rw_writer_unlock_x(const struct rte_hash_x *h)
{
	if (h->writer_takes_lock && h->hw_trans_mem_support)
		rte_rwlock_write_unlock_tm(h->readwrite_lock);
	else if (h->writer_takes_lock)
		rte_rwlock_write_unlock(h->readwrite_lock);
}

static inline void
__hash_rw_reader_unlock_x(const struct rte_hash_x *h)
{
	if (h->readwrite_concur_support && h->hw_trans_mem_support)
		rte_rwlock_read_unlock_tm(h->readwrite_lock);
	else if (h->readwrite_concur_support)
		rte_rwlock_read_unlock(h->readwrite_lock);
}

void
rte_hash_reset_x(struct rte_hash_x *h)
{
	void *ptr;
	uint32_t tot_ring_cnt, i;

	if (h == NULL)
		return;

	__hash_rw_writer_lock_x(h);
	memset(h->buckets, 0, h->num_buckets * sizeof(struct rte_hash_bucket_x));
        
        uint32_t num_key_slots = h->use_local_cache ?
            (h->entries + (RTE_MAX_LCORE - 1) * (LCORE_CACHE_SIZE - 1) + 1) :
            (h->entries + 1);
        
	memset(h->key_store, 0, h->key_entry_size * num_key_slots);
	*h->tbl_chng_cnt = 0;

	/* clear the free ring */
	while (rte_ring_dequeue(h->free_slots, &ptr) == 0)
		continue;

	/* clear free extendable bucket ring and memory */
	if (h->ext_table_support) {
		memset(h->buckets_ext, 0, h->num_buckets *
						sizeof(struct rte_hash_bucket_x));
		while (rte_ring_dequeue(h->free_ext_bkts, &ptr) == 0)
			continue;
	}

	/* Repopulate the free slots ring. Entry zero is reserved for key misses */
	if (h->use_local_cache)
		tot_ring_cnt = h->entries + (RTE_MAX_LCORE - 1) *
					(LCORE_CACHE_SIZE - 1);
	else
		tot_ring_cnt = h->entries;

	for (i = 1; i < tot_ring_cnt + 1; i++)
		rte_ring_sp_enqueue(h->free_slots, (void *)((uintptr_t) i));

	/* Repopulate the free ext bkt ring. */
	if (h->ext_table_support) {
		for (i = 1; i <= h->num_buckets; i++)
			rte_ring_sp_enqueue(h->free_ext_bkts,
						(void *)((uintptr_t) i));
	}

	if (h->use_local_cache) {
		/* Reset local caches per lcore */
		for (i = 0; i < RTE_MAX_LCORE; i++)
			h->local_free_slots[i].len = 0;
	}
	__hash_rw_writer_unlock_x(h);
}

/*
 * Function called to enqueue back an index in the cache/ring,
 * as slot has not being used and it can be used in the
 * next addition attempt.
 */
static inline void
enqueue_slot_back_x(const struct rte_hash_x *h,
		struct lcore_cache_x *cached_free_slots,
		void *slot_id)
{
	if (h->use_local_cache) {
		cached_free_slots->objs[cached_free_slots->len] = slot_id;
		cached_free_slots->len++;
	} else
		rte_ring_sp_enqueue(h->free_slots, slot_id);
}

/* Search a key from bucket and update its data.
 * Writer holds the lock before calling this.
 */
/* static inline int32_t
 * search_and_update_x(const struct rte_hash_x *h, void *data, 
 * 	const void *key, struct rte_hash_bucket_x *bkt, uint16_t sig)
 */
static inline int32_t
search_and_update_x(const struct rte_hash_x *h, void *data, void **orig_data, 
	const void *key, struct rte_hash_bucket_x *bkt, uint16_t sig)
{
	int i;
	struct rte_hash_key_x *k, *keys = h->key_store;
        void *pdata;

	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		/* Need to make sure that the key is not pointing to empty slot */
		if (bkt->sig_current[i] == sig && bkt->key_idx[i] != EMPTY_SLOT) {
			k = (struct rte_hash_key_x *) ((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);
			if (rte_hash_cmp_eq_x(key, k->key, h) == 0) {
//				RTE_LOG(DEBUG, HASH, "bkt->key_idx[i]=%" PRIu32 "\n", bkt->key_idx[i]);
				/* 'pdata' acts as the synchronization point
				 * when an existing hash entry is updated.
				 * Key is not updated in this case.
				 */
				/*
				 * __atomic_store_n(&k->pdata,
				 * 	data,
				 *	__ATOMIC_RELEASE);
				 */
				pdata = __atomic_exchange_n(&k->pdata, 
							data,
							__ATOMIC_RELEASE);
				if (orig_data != NULL)
					*orig_data = pdata;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
	}
	return -1;
}

/* Only tries to insert at one bucket (@prim_bkt) without trying to push
 * buckets around.
 * return 1 if matching existing key, return 0 if succeeds, return -1 for no
 * empty entry.
 */
/*
 * static inline int32_t
 * rte_hash_cuckoo_insert_mw_x(const struct rte_hash_x *h,
 * 		struct rte_hash_bucket_x *prim_bkt,
 * 		struct rte_hash_bucket_x *sec_bkt,
 * 		const struct rte_hash_key_x *key, void *data,
 * 		uint16_t sig, uint32_t new_idx,
 * 		int32_t *ret_val)
 */
static inline int32_t
rte_hash_cuckoo_insert_mw_x(const struct rte_hash_x *h,
		struct rte_hash_bucket_x *prim_bkt,
		struct rte_hash_bucket_x *sec_bkt,
		const struct rte_hash_key_x *key, void *data, void **orig_data,
		uint16_t sig, uint32_t new_idx,
		int32_t *ret_val)
{
	unsigned int i;
	struct rte_hash_bucket_x *cur_bkt;
	int32_t ret;

//        RTE_LOG(DEBUG, HASH, "%d: *orig_data=%p\n", __LINE__, *orig_data);
	__hash_rw_writer_lock_x(h);
	/* Check if key was inserted after last check but before this
	 * protected region in case of inserting duplicated keys.
	 */
	ret = search_and_update_x(h, data, orig_data, key, prim_bkt, sig);
	if (ret != -1) {
		__hash_rw_writer_unlock_x(h);
		*ret_val = ret;
		return 1;
	}

	FOR_EACH_BUCKET(cur_bkt, sec_bkt) {
		ret = search_and_update_x(h, data, orig_data, key, cur_bkt, sig);
		if (ret != -1) {
			__hash_rw_writer_unlock_x(h);
			*ret_val = ret;
			return 1;
		}
	}
//        RTE_LOG(DEBUG, HASH, "%d: *orig_data=%p\n", __LINE__, *orig_data);

	/* Insert new entry if there is room in the primary
	 * bucket.
	 */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		/* Check if slot is available */
		if (likely(prim_bkt->key_idx[i] == EMPTY_SLOT)) {
			prim_bkt->sig_current[i] = sig;
			/* Key can be of arbitrary length, so it is
			 * not possible to store it atomically.
			 * Hence the new key element's memory stores
			 * (key as well as data) should be complete
			 * before it is referenced.
			 */
			__atomic_store_n(&prim_bkt->key_idx[i],
					 new_idx,
					 __ATOMIC_RELEASE);
			/* this is a new entry, orig data set to NULL */
			break;
		}
	}
	__hash_rw_writer_unlock_x(h);

	if (i != RTE_HASH_BUCKET_ENTRIES)
		return 0;

	/* no empty entry */
	return -1;
}

/* Shift buckets along provided cuckoo_path (@leaf and @leaf_slot) and fill
 * the path head with new entry (sig, alt_hash, new_idx)
 * return 1 if matched key found, return -1 if cuckoo path invalided and fail,
 * return 0 if succeeds.
 */
/*
 * static inline int
 * rte_hash_cuckoo_move_insert_mw_x(const struct rte_hash_x *h,
 * 			struct rte_hash_bucket_x *bkt,
 * 			struct rte_hash_bucket_x *alt_bkt,
 * 			const struct rte_hash_key_x *key, void *data,
 * 			struct queue_node_x *leaf, uint32_t leaf_slot,
 * 			uint16_t sig, uint32_t new_idx,
 * 			int32_t *ret_val)
 */
static inline int
rte_hash_cuckoo_move_insert_mw_x(const struct rte_hash_x *h,
			struct rte_hash_bucket_x *bkt,
			struct rte_hash_bucket_x *alt_bkt,
			const struct rte_hash_key_x *key, void *data, void **orig_data,
			struct queue_node_x *leaf, uint32_t leaf_slot,
			uint16_t sig, uint32_t new_idx,
			int32_t *ret_val)
{
	uint32_t prev_alt_bkt_idx;
	struct rte_hash_bucket_x *cur_bkt;
	struct queue_node_x *prev_node, *curr_node = leaf;
	struct rte_hash_bucket_x *prev_bkt, *curr_bkt = leaf->bkt;
	uint32_t prev_slot, curr_slot = leaf_slot;
	int32_t ret;

	__hash_rw_writer_lock_x(h);

	/* In case empty slot was gone before entering protected region */
	if (curr_bkt->key_idx[curr_slot] != EMPTY_SLOT) {
		__hash_rw_writer_unlock_x(h);
		return -1;
	}

	/* Check if key was inserted after last check but before this
	 * protected region.
	 */
	ret = search_and_update_x(h, data, orig_data, key, bkt, sig);
	if (ret != -1) {
		__hash_rw_writer_unlock_x(h);
		*ret_val = ret;
		return 1;
	}

	FOR_EACH_BUCKET(cur_bkt, alt_bkt) {
		ret = search_and_update_x(h, data, orig_data, key, cur_bkt, sig);
		if (ret != -1) {
			__hash_rw_writer_unlock_x(h);
			*ret_val = ret;
			return 1;
		}
	}

	while (likely(curr_node->prev != NULL)) {
		prev_node = curr_node->prev;
		prev_bkt = prev_node->bkt;
		prev_slot = curr_node->prev_slot;

		prev_alt_bkt_idx = get_alt_bucket_index_x(h,
					prev_node->cur_bkt_idx,
					prev_bkt->sig_current[prev_slot]);

		if (unlikely(&h->buckets[prev_alt_bkt_idx]
				!= curr_bkt)) {
			/* revert it to empty, otherwise duplicated keys */
			__atomic_store_n(&curr_bkt->key_idx[curr_slot],
				EMPTY_SLOT,
				__ATOMIC_RELEASE);
			__hash_rw_writer_unlock_x(h);
			return -1;
		}

		if (h->readwrite_concur_lf_support) {
			/* Inform the previous move. The current move need
			 * not be informed now as the current bucket entry
			 * is present in both primary and secondary.
			 * Since there is one writer, load acquires on
			 * tbl_chng_cnt are not required.
			 */
			__atomic_store_n(h->tbl_chng_cnt,
					 *h->tbl_chng_cnt + 1,
					 __ATOMIC_RELEASE);
			/* The stores to sig_alt and sig_current should not
			 * move above the store to tbl_chng_cnt.
			 */
			__atomic_thread_fence(__ATOMIC_RELEASE);
		}

		/* Need to swap current/alt sig to allow later
		 * Cuckoo insert to move elements back to its
		 * primary bucket if available
		 */
		curr_bkt->sig_current[curr_slot] =
			prev_bkt->sig_current[prev_slot];
		/* Release the updated bucket entry */
		__atomic_store_n(&curr_bkt->key_idx[curr_slot],
			prev_bkt->key_idx[prev_slot],
			__ATOMIC_RELEASE);

		curr_slot = prev_slot;
		curr_node = prev_node;
		curr_bkt = curr_node->bkt;
	}

	if (h->readwrite_concur_lf_support) {
		/* Inform the previous move. The current move need
		 * not be informed now as the current bucket entry
		 * is present in both primary and secondary.
		 * Since there is one writer, load acquires on
		 * tbl_chng_cnt are not required.
		 */
		__atomic_store_n(h->tbl_chng_cnt,
				 *h->tbl_chng_cnt + 1,
				 __ATOMIC_RELEASE);
		/* The stores to sig_alt and sig_current should not
		 * move above the store to tbl_chng_cnt.
		 */
		__atomic_thread_fence(__ATOMIC_RELEASE);
	}

	curr_bkt->sig_current[curr_slot] = sig;
	/* Release the new bucket entry */
	__atomic_store_n(&curr_bkt->key_idx[curr_slot],
			 new_idx,
			 __ATOMIC_RELEASE);

	__hash_rw_writer_unlock_x(h);

	return 0;

}

/*
 * Make space for new key, using bfs Cuckoo Search and Multi-Writer safe
 * Cuckoo
 */
/*
 * static inline int
 * rte_hash_cuckoo_make_space_mw_x(const struct rte_hash_x *h,
 * 			struct rte_hash_bucket_x *bkt,
 * 			struct rte_hash_bucket_x *sec_bkt,
 * 			const struct rte_hash_key_x *key, void *data,
 * 			uint16_t sig, uint32_t bucket_idx,
 * 			uint32_t new_idx, int32_t *ret_val)
 */
static inline int
rte_hash_cuckoo_make_space_mw_x(const struct rte_hash_x *h,
			struct rte_hash_bucket_x *bkt,
			struct rte_hash_bucket_x *sec_bkt,
			const struct rte_hash_key_x *key, void *data, void **orig_data,
			uint16_t sig, uint32_t bucket_idx,
			uint32_t new_idx, int32_t *ret_val)
{
	unsigned int i;
	struct queue_node_x queue[RTE_HASH_BFS_QUEUE_MAX_LEN];
	struct queue_node_x *tail, *head;
	struct rte_hash_bucket_x *curr_bkt, *alt_bkt;
	uint32_t cur_idx, alt_idx;

	tail = queue;
	head = queue + 1;
	tail->bkt = bkt;
	tail->prev = NULL;
	tail->prev_slot = -1;
	tail->cur_bkt_idx = bucket_idx;

	/* Cuckoo bfs Search */
	while (likely(tail != head && head <
					queue + RTE_HASH_BFS_QUEUE_MAX_LEN -
					RTE_HASH_BUCKET_ENTRIES)) {
		curr_bkt = tail->bkt;
		cur_idx = tail->cur_bkt_idx;
		for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
			if (curr_bkt->key_idx[i] == EMPTY_SLOT) {
				int32_t ret = rte_hash_cuckoo_move_insert_mw_x(h,
						bkt, sec_bkt, key, data, orig_data,
						tail, i, sig,
						new_idx, ret_val);
				if (likely(ret != -1))
					return ret;
			}

			/* Enqueue new node and keep prev node info */
			alt_idx = get_alt_bucket_index_x(h, cur_idx,
						curr_bkt->sig_current[i]);
			alt_bkt = &(h->buckets[alt_idx]);
			head->bkt = alt_bkt;
			head->cur_bkt_idx = alt_idx;
			head->prev = tail;
			head->prev_slot = i;
			head++;
		}
		tail++;
	}

	return -ENOSPC;
}

/*
 * static inline int32_t
 *__rte_hash_add_key_with_hash_x(const struct rte_hash_x *h, const void *key,
 *						hash_sig_t sig, void *data)
 */
static inline int32_t
__rte_hash_add_key_with_hash_x(const struct rte_hash_x *h, const void *key,
						hash_sig_t sig, void *data, 
						void **orig_data)
{
	uint16_t short_sig;
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct rte_hash_bucket_x *prim_bkt, *sec_bkt, *cur_bkt;
	struct rte_hash_key_x *new_k, *keys = h->key_store;
	void *slot_id = NULL;
	void *ext_bkt_id = NULL;
	uint32_t new_idx, bkt_id;
	int ret;
	unsigned n_slots;
	unsigned lcore_id;
	unsigned int i;
	struct lcore_cache_x *cached_free_slots = NULL;
	int32_t ret_val;
	struct rte_hash_bucket_x *last;

	short_sig = get_short_sig_x(sig);
	prim_bucket_idx = get_prim_bucket_index_x(h, sig);
	sec_bucket_idx = get_alt_bucket_index_x(h, prim_bucket_idx, short_sig);
//	RTE_LOG(DEBUG, HASH, "prim_bucket_idx=%" PRIu32 ", sec_bucket_idx=%" PRIu32 "\n", prim_bucket_idx, sec_bucket_idx);
	prim_bkt = &h->buckets[prim_bucket_idx];
	sec_bkt = &h->buckets[sec_bucket_idx];
	rte_prefetch0(prim_bkt);
	rte_prefetch0(sec_bkt);

	/* Check if key is already inserted in primary location */
	__hash_rw_writer_lock_x(h);
	ret = search_and_update_x(h, data, orig_data, key, prim_bkt, short_sig);
	if (ret != -1) {
		__hash_rw_writer_unlock_x(h);
		return ret;
	}

	/* Check if key is already inserted in secondary location */
	FOR_EACH_BUCKET(cur_bkt, sec_bkt) {
		ret = search_and_update_x(h, data, orig_data, key, cur_bkt, short_sig);
		if (ret != -1) {
			__hash_rw_writer_unlock_x(h);
			return ret;
		}
	}

	__hash_rw_writer_unlock_x(h);

	/* Did not find a match, so get a new slot for storing the new key */
	if (h->use_local_cache) {
		lcore_id = rte_lcore_id();
		cached_free_slots = &h->local_free_slots[lcore_id];
		/* Try to get a free slot from the local cache */
		if (cached_free_slots->len == 0) {
			/* Need to get another burst of free slots from global ring */
			n_slots = rte_ring_mc_dequeue_burst(h->free_slots,
					cached_free_slots->objs,
					LCORE_CACHE_SIZE, NULL);
			if (n_slots == 0) {
				return -ENOSPC;
			}

			cached_free_slots->len += n_slots;
		}

		/* Get a free slot from the local cache */
		cached_free_slots->len--;
		slot_id = cached_free_slots->objs[cached_free_slots->len];
	} else {
		if (rte_ring_sc_dequeue(h->free_slots, &slot_id) != 0) {
			return -ENOSPC;
		}
	}

	new_k = RTE_PTR_ADD(keys, (uintptr_t)slot_id * h->key_entry_size);
	new_idx = (uint32_t)((uintptr_t) slot_id);
//        RTE_LOG(DEBUG, HASH, "new_idx=%" PRIu32 "\n", new_idx);
	/* Copy key */
	memcpy(new_k->key, key, h->key_len);
	/* Key can be of arbitrary length, so it is not possible to store
	 * it atomically. Hence the new key element's memory stores
	 * (key as well as data) should be complete before it is referenced.
	 * 'pdata' acts as the synchronization point when an existing hash
	 * entry is updated.
	 */
	__atomic_store_n(&new_k->pdata,
		data,
		__ATOMIC_RELEASE);
	/* The original data is NULL */
        if (orig_data != NULL) 
            *orig_data = NULL;
        
//        RTE_LOG(DEBUG, HASH, "%d: ret=%d, *orig_data=%p\n", __LINE__, ret, *orig_data);

	/* Find an empty slot and insert */
	ret = rte_hash_cuckoo_insert_mw_x(h, prim_bkt, sec_bkt, key, data, orig_data,
					short_sig, new_idx, &ret_val);
//        RTE_LOG(DEBUG, HASH, "%d: ret=%d, *orig_data=%p\n", __LINE__, ret, *orig_data);
	if (ret == 0)
		return new_idx - 1;
	else if (ret == 1) {
		enqueue_slot_back_x(h, cached_free_slots, slot_id);
		return ret_val;
	}

	/* Primary bucket full, need to make space for new entry */
	ret = rte_hash_cuckoo_make_space_mw_x(h, prim_bkt, sec_bkt, key, data, orig_data,
				short_sig, prim_bucket_idx, new_idx, &ret_val);
	if (ret == 0)
		return new_idx - 1;
	else if (ret == 1) {
		enqueue_slot_back_x(h, cached_free_slots, slot_id);
		return ret_val;
	}

	/* Also search secondary bucket to get better occupancy */
	ret = rte_hash_cuckoo_make_space_mw_x(h, sec_bkt, prim_bkt, key, data, orig_data,
				short_sig, sec_bucket_idx, new_idx, &ret_val);

	if (ret == 0)
		return new_idx - 1;
	else if (ret == 1) {
		enqueue_slot_back_x(h, cached_free_slots, slot_id);
		return ret_val;
	}

	/* if ext table not enabled, we failed the insertion */
	if (!h->ext_table_support) {
		enqueue_slot_back_x(h, cached_free_slots, slot_id);
		return ret;
	}

	/* Now we need to go through the extendable bucket. Protection is needed
	 * to protect all extendable bucket processes.
	 */
	__hash_rw_writer_lock_x(h);
	/* We check for duplicates again since could be inserted before the lock */
	ret = search_and_update_x(h, data, orig_data, key, prim_bkt, short_sig);
	if (ret != -1) {
		enqueue_slot_back_x(h, cached_free_slots, slot_id);
		goto failure;
	}

	FOR_EACH_BUCKET(cur_bkt, sec_bkt) {
		ret = search_and_update_x(h, data, orig_data, key, cur_bkt, short_sig);
		if (ret != -1) {
			enqueue_slot_back_x(h, cached_free_slots, slot_id);
			goto failure;
		}
	}

	/* Search sec and ext buckets to find an empty entry to insert. */
	FOR_EACH_BUCKET(cur_bkt, sec_bkt) {
		for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
			/* Check if slot is available */
			if (likely(cur_bkt->key_idx[i] == EMPTY_SLOT)) {
				cur_bkt->sig_current[i] = short_sig;
				cur_bkt->key_idx[i] = new_idx;
				__hash_rw_writer_unlock_x(h);
				return new_idx - 1;
			}
		}
	}

	/* Failed to get an empty entry from extendable buckets. Link a new
	 * extendable bucket. We first get a free bucket from ring.
	 */
	if (rte_ring_sc_dequeue(h->free_ext_bkts, &ext_bkt_id) != 0) {
		ret = -ENOSPC;
		goto failure;
	}

	bkt_id = (uint32_t)((uintptr_t)ext_bkt_id) - 1;
	/* Use the first location of the new bucket */
	(h->buckets_ext[bkt_id]).sig_current[0] = short_sig;
	(h->buckets_ext[bkt_id]).key_idx[0] = new_idx;
	/* Link the new bucket to sec bucket linked list */
	last = rte_hash_get_last_bkt_x(sec_bkt);
	last->next = &h->buckets_ext[bkt_id];
	__hash_rw_writer_unlock_x(h);
	return new_idx - 1;

failure:
	__hash_rw_writer_unlock_x(h);
	return ret;

}

int32_t
rte_hash_add_key_with_hash_x(const struct rte_hash_x *h,
			const void *key, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
        void *tmp;
	return __rte_hash_add_key_with_hash_x(h, key, sig, 0, &tmp);
}

int32_t
rte_hash_add_key_x(const struct rte_hash_x *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
        void *tmp;
	return __rte_hash_add_key_with_hash_x(h, key, rte_hash_hash_x(h, key), 0, &tmp);
}

/* int
 * rte_hash_add_key_with_hash_data_x(const struct rte_hash_x *h,
 * 			const void *key, hash_sig_t sig, void *data, void **orig_data)
 */
int32_t
rte_hash_add_key_with_hash_data_x(const struct rte_hash_x *h,
			const void *key, hash_sig_t sig, void *data, void **orig_data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __rte_hash_add_key_with_hash_x(h, key, sig, data, orig_data);
}

/*
 * int
 * rte_hash_add_key_data_x(const struct rte_hash_x *h, const void *key, void *data)
 */
int32_t
rte_hash_add_key_data_x(const struct rte_hash_x *h, const void *key, void *data, void **orig_data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	return __rte_hash_add_key_with_hash_x(h, key, rte_hash_hash_x(h, key), data, orig_data);
}

/* Search one bucket to find the match key - uses rw lock */
static inline int32_t
search_one_bucket_l_x(const struct rte_hash_x *h, const void *key,
		uint16_t sig, void **data,
		const struct rte_hash_bucket_x *bkt)
{
	int i;
	struct rte_hash_key_x *k, *keys = h->key_store;

	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		if (bkt->sig_current[i] == sig &&
				bkt->key_idx[i] != EMPTY_SLOT) {
			k = (struct rte_hash_key_x *) ((char *)keys +
					bkt->key_idx[i] * h->key_entry_size);

			if (rte_hash_cmp_eq_x(key, k->key, h) == 0) {
				if (data != NULL)
					*data = k->pdata;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return bkt->key_idx[i] - 1;
			}
		}
	}
	return -1;
}

/* Search one bucket to find the match key */
static inline int32_t
search_one_bucket_lf_x(const struct rte_hash_x *h, const void *key, uint16_t sig,
			void **data, const struct rte_hash_bucket_x *bkt)
{
	int i;
	uint32_t key_idx;
	void *pdata;
	struct rte_hash_key_x *k, *keys = h->key_store;

	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		key_idx = __atomic_load_n(&bkt->key_idx[i],
					  __ATOMIC_ACQUIRE);
		if (bkt->sig_current[i] == sig && key_idx != EMPTY_SLOT) {
			k = (struct rte_hash_key_x *) ((char *)keys +
					key_idx * h->key_entry_size);
			pdata = __atomic_load_n(&k->pdata,
					__ATOMIC_ACQUIRE);

			if (rte_hash_cmp_eq_x(key, k->key, h) == 0) {
				if (data != NULL)
					*data = pdata;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return key_idx - 1;
			}
		}
	}
	return -1;
}

static inline int32_t
__rte_hash_lookup_with_hash_l_x(const struct rte_hash_x *h, const void *key,
				hash_sig_t sig, void **data)
{
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct rte_hash_bucket_x *bkt, *cur_bkt;
	int ret;
	uint16_t short_sig;

	short_sig = get_short_sig_x(sig);
	prim_bucket_idx = get_prim_bucket_index_x(h, sig);
	sec_bucket_idx = get_alt_bucket_index_x(h, prim_bucket_idx, short_sig);

	bkt = &h->buckets[prim_bucket_idx];

	__hash_rw_reader_lock_x(h);

	/* Check if key is in primary location */
	ret = search_one_bucket_l_x(h, key, short_sig, data, bkt);
	if (ret != -1) {
		__hash_rw_reader_unlock_x(h);
		return ret;
	}
	/* Calculate secondary hash */
	bkt = &h->buckets[sec_bucket_idx];

	/* Check if key is in secondary location */
	FOR_EACH_BUCKET(cur_bkt, bkt) {
		ret = search_one_bucket_l_x(h, key, short_sig,
					data, cur_bkt);
		if (ret != -1) {
			__hash_rw_reader_unlock_x(h);
			return ret;
		}
	}

	__hash_rw_reader_unlock_x(h);

	return -ENOENT;
}

static inline int32_t
__rte_hash_lookup_with_hash_lf_x(const struct rte_hash_x *h, const void *key,
					hash_sig_t sig, void **data)
{
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct rte_hash_bucket_x *bkt, *cur_bkt;
	uint32_t cnt_b, cnt_a;
	int ret;
	uint16_t short_sig;

	short_sig = get_short_sig_x(sig);
	prim_bucket_idx = get_prim_bucket_index_x(h, sig);
	sec_bucket_idx = get_alt_bucket_index_x(h, prim_bucket_idx, short_sig);

	do {
		/* Load the table change counter before the lookup
		 * starts. Acquire semantics will make sure that
		 * loads in search_one_bucket are not hoisted.
		 */
		cnt_b = __atomic_load_n(h->tbl_chng_cnt,
				__ATOMIC_ACQUIRE);

		/* Check if key is in primary location */
		bkt = &h->buckets[prim_bucket_idx];
		ret = search_one_bucket_lf_x(h, key, short_sig, data, bkt);
		if (ret != -1) {
			__hash_rw_reader_unlock_x(h);
			return ret;
		}
		/* Calculate secondary hash */
		bkt = &h->buckets[sec_bucket_idx];

		/* Check if key is in secondary location */
		FOR_EACH_BUCKET(cur_bkt, bkt) {
			ret = search_one_bucket_lf_x(h, key, short_sig,
						data, cur_bkt);
			if (ret != -1) {
				__hash_rw_reader_unlock_x(h);
				return ret;
			}
		}

		/* The loads of sig_current in search_one_bucket
		 * should not move below the load from tbl_chng_cnt.
		 */
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		/* Re-read the table change counter to check if the
		 * table has changed during search. If yes, re-do
		 * the search.
		 * This load should not get hoisted. The load
		 * acquires on cnt_b, key index in primary bucket
		 * and key index in secondary bucket will make sure
		 * that it does not get hoisted.
		 */
		cnt_a = __atomic_load_n(h->tbl_chng_cnt,
					__ATOMIC_ACQUIRE);
	} while (cnt_b != cnt_a);

	return -ENOENT;
}

static inline int32_t
__rte_hash_lookup_with_hash_x(const struct rte_hash_x *h, const void *key,
					hash_sig_t sig, void **data)
{
	if (h->readwrite_concur_lf_support)
		return __rte_hash_lookup_with_hash_lf_x(h, key, sig, data);
	else
		return __rte_hash_lookup_with_hash_l_x(h, key, sig, data);
}

int32_t
rte_hash_lookup_with_hash_x(const struct rte_hash_x *h,
			const void *key, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __rte_hash_lookup_with_hash_x(h, key, sig, NULL);
}

int32_t
rte_hash_lookup_x(const struct rte_hash_x *h, const void *key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __rte_hash_lookup_with_hash_x(h, key, rte_hash_hash_x(h, key), NULL);
}

int32_t
rte_hash_lookup_with_hash_data_x(const struct rte_hash_x *h,
			const void *key, hash_sig_t sig, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __rte_hash_lookup_with_hash_x(h, key, sig, data);
}

int32_t
rte_hash_lookup_data_x(const struct rte_hash_x *h, const void *key, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __rte_hash_lookup_with_hash_x(h, key, rte_hash_hash_x(h, key), data);
}

/*
 * static inline void
 * remove_entry_x(const struct rte_hash_x *h, struct rte_hash_bucket_x *bkt, unsigned i)
 */
static inline void
remove_entry_x(const struct rte_hash_x *h, struct rte_hash_bucket_x *bkt, unsigned i)
{
	unsigned lcore_id, n_slots;
	struct lcore_cache_x *cached_free_slots;

	if (h->use_local_cache) {
		lcore_id = rte_lcore_id();
		cached_free_slots = &h->local_free_slots[lcore_id];
		/* Cache full, need to free it. */
		if (cached_free_slots->len == LCORE_CACHE_SIZE) {
			/* Need to enqueue the free slots in global ring. */
			n_slots = rte_ring_mp_enqueue_burst(h->free_slots,
						cached_free_slots->objs,
						LCORE_CACHE_SIZE, NULL);
                        RETURN_IF_TRUE(n_slots == 0, -EINVAL);
			cached_free_slots->len -= n_slots;
		}
		/* Put index of new free slot in cache. */
		cached_free_slots->objs[cached_free_slots->len] =
				(void *)((uintptr_t)bkt->key_idx[i]);
		cached_free_slots->len++;
	} else {
		rte_ring_sp_enqueue(h->free_slots,
				(void *)((uintptr_t)bkt->key_idx[i]));
	}
}

/* Compact the linked list by moving key from last entry in linked list to the
 * empty slot.
 */
static inline void
__rte_hash_compact_ll_x(struct rte_hash_bucket_x *cur_bkt, int pos) {
	int i;
	struct rte_hash_bucket_x *last_bkt;

	if (!cur_bkt->next)
		return;

	last_bkt = rte_hash_get_last_bkt_x(cur_bkt);

	for (i = RTE_HASH_BUCKET_ENTRIES - 1; i >= 0; i--) {
		if (last_bkt->key_idx[i] != EMPTY_SLOT) {
			cur_bkt->key_idx[pos] = last_bkt->key_idx[i];
			cur_bkt->sig_current[pos] = last_bkt->sig_current[i];
			last_bkt->sig_current[i] = NULL_SIGNATURE;
			last_bkt->key_idx[i] = EMPTY_SLOT;
			return;
		}
	}
}

/* Search one bucket and remove the matched key.
 * Writer is expected to hold the lock while calling this
 * function.
 */
/*
 * static inline int32_t
 * search_and_remove_x(const struct rte_hash_x *h, const void *key,
 * 			struct rte_hash_bucket_x *bkt, uint16_t sig, int *pos)
 */
static inline int32_t
search_and_remove_x(const struct rte_hash_x *h, const void *key, void **orig_data,
			struct rte_hash_bucket_x *bkt, uint16_t sig, int *pos)
{
	struct rte_hash_key_x *k, *keys = h->key_store;
	unsigned int i;
	uint32_t key_idx;

	/* Check if key is in bucket */
	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		key_idx = __atomic_load_n(&bkt->key_idx[i],
					  __ATOMIC_ACQUIRE);
		if (bkt->sig_current[i] == sig && key_idx != EMPTY_SLOT) {
			k = (struct rte_hash_key_x *) ((char *)keys +
					key_idx * h->key_entry_size);
			if (rte_hash_cmp_eq_x(key, k->key, h) == 0) {
				bkt->sig_current[i] = NULL_SIGNATURE;
				/* Free the key store index if
				 * no_free_on_del is disabled.
				 */
				if (!h->no_free_on_del)
					remove_entry_x(h, bkt, i);

				__atomic_store_n(&bkt->key_idx[i],
						 EMPTY_SLOT,
						 __ATOMIC_RELEASE);
				if (orig_data != NULL)
					*orig_data = k->pdata;

				*pos = i;
				/*
				 * Return index where key is stored,
				 * subtracting the first dummy index
				 */
				return key_idx - 1;
			}
		}
	}
	return -1;
}

/* static inline int32_t
 * __rte_hash_del_key_with_hash_x(const struct rte_hash_x *h, const void *key,
 * 						hash_sig_t sig)
 */
static inline int32_t
__rte_hash_del_key_with_hash_x(const struct rte_hash_x *h, const void *key,
						void **orig_data, hash_sig_t sig)
{
	uint32_t prim_bucket_idx, sec_bucket_idx;
	struct rte_hash_bucket_x *prim_bkt, *sec_bkt, *prev_bkt, *last_bkt;
	struct rte_hash_bucket_x *cur_bkt;
	int pos;
	int32_t ret, i;
	uint16_t short_sig;

	short_sig = get_short_sig_x(sig);
	prim_bucket_idx = get_prim_bucket_index_x(h, sig);
	sec_bucket_idx = get_alt_bucket_index_x(h, prim_bucket_idx, short_sig);
	prim_bkt = &h->buckets[prim_bucket_idx];

	__hash_rw_writer_lock_x(h);
	/* look for key in primary bucket */
	ret = search_and_remove_x(h, key, orig_data, prim_bkt, short_sig, &pos);
	if (ret != -1) {
		__rte_hash_compact_ll_x(prim_bkt, pos);
		last_bkt = prim_bkt->next;
		prev_bkt = prim_bkt;
		goto return_bkt;
	}

	/* Calculate secondary hash */
	sec_bkt = &h->buckets[sec_bucket_idx];

	FOR_EACH_BUCKET(cur_bkt, sec_bkt) {
		ret = search_and_remove_x(h, key, orig_data, cur_bkt, short_sig, &pos);
		if (ret != -1) {
			__rte_hash_compact_ll_x(cur_bkt, pos);
			last_bkt = sec_bkt->next;
			prev_bkt = sec_bkt;
			goto return_bkt;
		}
	}

	__hash_rw_writer_unlock_x(h);
	return -ENOENT;

/* Search last bucket to see if empty to be recycled */
return_bkt:
	if (!last_bkt) {
		__hash_rw_writer_unlock_x(h);
		return ret;
	}
	while (last_bkt->next) {
		prev_bkt = last_bkt;
		last_bkt = last_bkt->next;
	}

	for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		if (last_bkt->key_idx[i] != EMPTY_SLOT)
			break;
	}
	/* found empty bucket and recycle */
	if (i == RTE_HASH_BUCKET_ENTRIES) {
		prev_bkt->next = last_bkt->next = NULL;
		uint32_t index = last_bkt - h->buckets_ext + 1;
		rte_ring_sp_enqueue(h->free_ext_bkts, (void *)(uintptr_t)index);
	}

	__hash_rw_writer_unlock_x(h);
	return ret;
}

/*
 * int32_t
 * rte_hash_del_key_with_hash_x(const struct rte_hash_x *h,
 * 			const void *key, hash_sig_t sig)
 */
int32_t
rte_hash_del_key_with_hash_x(const struct rte_hash_x *h,
			const void *key, void **orig_data, hash_sig_t sig)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __rte_hash_del_key_with_hash_x(h, key, orig_data, sig);
}

/*
 * int32_t
 * rte_hash_del_key_x(const struct rte_hash_x *h, const void *key)
 */
int32_t
rte_hash_del_key_x(const struct rte_hash_x *h, const void *key, void **orig_data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);
	return __rte_hash_del_key_with_hash_x(h, key, orig_data, rte_hash_hash_x(h, key));
}

int32_t
rte_hash_get_key_with_position_x(const struct rte_hash_x *h, const int32_t position,
			       const void **key)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	struct rte_hash_key_x *k, *keys = h->key_store;
	k = (struct rte_hash_key_x *) ((char *) keys + (position + 1) *
				     h->key_entry_size);
	*key = k->key;

	if (position !=
	    __rte_hash_lookup_with_hash_x(h, *key, rte_hash_hash_x(h, *key),
					NULL)) {
		return -ENOENT;
	}

	return 0;
}

int32_t
rte_hash_get_key_data_with_position_x(const struct rte_hash_x *h, const int32_t position,
			       const void **key, void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	struct rte_hash_key_x *k, *keys = h->key_store;
	k = (struct rte_hash_key_x *) ((char *) keys + (position + 1) *
				     h->key_entry_size);
	*key = k->key;

	if (position !=
	    __rte_hash_lookup_with_hash_x(h, *key, rte_hash_hash_x(h, *key),
					data)) {
		return -ENOENT;
	}

	return 0;
}

void
rte_hash_get_key_data_with_position_force_x(const struct rte_hash_x *h, const int32_t position,
			       const void **key, const void **data)
{
	RETURN_IF_TRUE(((h == NULL) || (key == NULL)), -EINVAL);

	struct rte_hash_key_x *k, *keys = h->key_store;
	k = (struct rte_hash_key_x *) ((char *) keys + (position + 1) *
				     h->key_entry_size);
	*key = k->key;
        *data = k->pdata;
}


int32_t /* __rte_experimental */
rte_hash_free_key_with_position_x(const struct rte_hash_x *h,
				const int32_t position, void **data)
{

	unsigned int lcore_id, n_slots;
	struct lcore_cache_x *cached_free_slots;
	struct rte_hash_key_x *k, *keys = h->key_store;
        void *pdata;
        const int32_t real_position = position + 1;

	RETURN_IF_TRUE(((h == NULL) || (real_position == EMPTY_SLOT)), -EINVAL);

	if (h->use_local_cache) {
		const int32_t total_entries = h->entries + (RTE_MAX_LCORE - 1) *
					(LCORE_CACHE_SIZE - 1) + 1;
//		RTE_LOG(DEBUG, HASH, "(position + 1)=%" PRIu32 ", total_entries=%" PRIi32 ", h->entries=%" PRIu32 " \n", real_position, total_entries, h->entries);
		/* Out of bounds */
		if (real_position >= total_entries)
			return -EINVAL;

		k = (struct rte_hash_key_x *) ((char *)keys +
			real_position * h->key_entry_size);
		pdata = __atomic_load_n(&k->pdata,
			__ATOMIC_ACQUIRE);
                
		lcore_id = rte_lcore_id();
		cached_free_slots = &h->local_free_slots[lcore_id];
		/* Cache full, need to free it. */
		if (cached_free_slots->len == LCORE_CACHE_SIZE) {
			/* Need to enqueue the free slots in global ring. */
			n_slots = rte_ring_mp_enqueue_burst(h->free_slots,
						cached_free_slots->objs,
						LCORE_CACHE_SIZE, NULL);
                        RETURN_IF_TRUE(n_slots == 0, -EINVAL);
			cached_free_slots->len -= n_slots;
		}
		/* Put index of new free slot in cache. */
		cached_free_slots->objs[cached_free_slots->len] =
					(void *)((uintptr_t)real_position);
		cached_free_slots->len++;
	} else {
		const int32_t total_entries = h->entries + 1;
//		RTE_LOG(DEBUG, HASH, "(position + 1)=%" PRIu32 ", total_entries=%" PRIi32 ", h->entries=%" PRIu32 " \n", real_position, total_entries, h->entries);
		if (real_position >= total_entries)
			return -EINVAL;

		k = (struct rte_hash_key_x *) ((char *)keys +
			real_position * h->key_entry_size);
		pdata = __atomic_load_n(&k->pdata,
			__ATOMIC_ACQUIRE);

		rte_ring_sp_enqueue(h->free_slots,
				(void *)((uintptr_t)real_position));
	}
        if (data != NULL) 
            *data = pdata;

	return 0;
}

static inline void
compare_signatures_x(uint32_t *prim_hash_matches, uint32_t *sec_hash_matches,
			const struct rte_hash_bucket_x *prim_bkt,
			const struct rte_hash_bucket_x *sec_bkt,
			uint16_t sig,
			enum rte_hash_sig_compare_function_x sig_cmp_fn)
{
	unsigned int i;

	/* For match mask the first bit of every two bits indicates the match */
	switch (sig_cmp_fn) {
#ifdef RTE_MACHINE_CPUFLAG_SSE2
	case RTE_HASH_COMPARE_SSE:
		/* Compare all signatures in the bucket */
		*prim_hash_matches = _mm_movemask_epi8(_mm_cmpeq_epi16(
				_mm_load_si128(
					(__m128i const *)prim_bkt->sig_current),
				_mm_set1_epi16(sig)));
		/* Compare all signatures in the bucket */
		*sec_hash_matches = _mm_movemask_epi8(_mm_cmpeq_epi16(
				_mm_load_si128(
					(__m128i const *)sec_bkt->sig_current),
				_mm_set1_epi16(sig)));
		break;
#endif
	default:
		for (i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
			*prim_hash_matches |=
				((sig == prim_bkt->sig_current[i]) << (i << 1));
			*sec_hash_matches |=
				((sig == sec_bkt->sig_current[i]) << (i << 1));
		}
	}
}

#define PREFETCH_OFFSET 4
static inline void
__rte_hash_lookup_bulk_l_x(const struct rte_hash_x *h, const void **keys,
			int32_t num_keys, int32_t *positions,
			uint64_t *hit_mask, void *data[])
{
	uint64_t hits = 0;
	int32_t i;
	int32_t ret;
	uint32_t prim_hash[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t prim_index[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t sec_index[RTE_HASH_LOOKUP_BULK_MAX];
	uint16_t sig[RTE_HASH_LOOKUP_BULK_MAX];
	const struct rte_hash_bucket_x *primary_bkt[RTE_HASH_LOOKUP_BULK_MAX];
	const struct rte_hash_bucket_x *secondary_bkt[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t prim_hitmask[RTE_HASH_LOOKUP_BULK_MAX] = {0};
	uint32_t sec_hitmask[RTE_HASH_LOOKUP_BULK_MAX] = {0};
	struct rte_hash_bucket_x *cur_bkt, *next_bkt;

	/* Prefetch first keys */
	for (i = 0; i < PREFETCH_OFFSET && i < num_keys; i++)
		rte_prefetch0(keys[i]);

	/*
	 * Prefetch rest of the keys, calculate primary and
	 * secondary bucket and prefetch them
	 */
	for (i = 0; i < (num_keys - PREFETCH_OFFSET); i++) {
		rte_prefetch0(keys[i + PREFETCH_OFFSET]);

		prim_hash[i] = rte_hash_hash_x(h, keys[i]);

		sig[i] = get_short_sig_x(prim_hash[i]);
		prim_index[i] = get_prim_bucket_index_x(h, prim_hash[i]);
		sec_index[i] = get_alt_bucket_index_x(h, prim_index[i], sig[i]);

		primary_bkt[i] = &h->buckets[prim_index[i]];
		secondary_bkt[i] = &h->buckets[sec_index[i]];

		rte_prefetch0(primary_bkt[i]);
		rte_prefetch0(secondary_bkt[i]);
	}

	/* Calculate and prefetch rest of the buckets */
	for (; i < num_keys; i++) {
		prim_hash[i] = rte_hash_hash_x(h, keys[i]);

		sig[i] = get_short_sig_x(prim_hash[i]);
		prim_index[i] = get_prim_bucket_index_x(h, prim_hash[i]);
		sec_index[i] = get_alt_bucket_index_x(h, prim_index[i], sig[i]);

		primary_bkt[i] = &h->buckets[prim_index[i]];
		secondary_bkt[i] = &h->buckets[sec_index[i]];

		rte_prefetch0(primary_bkt[i]);
		rte_prefetch0(secondary_bkt[i]);
	}

	__hash_rw_reader_lock_x(h);

	/* Compare signatures and prefetch key slot of first hit */
	for (i = 0; i < num_keys; i++) {
		compare_signatures_x(&prim_hitmask[i], &sec_hitmask[i],
			primary_bkt[i], secondary_bkt[i],
			sig[i], h->sig_cmp_fn);

		if (prim_hitmask[i]) {
			uint32_t first_hit =
					__builtin_ctzl(prim_hitmask[i])
					>> 1;
			uint32_t key_idx =
				primary_bkt[i]->key_idx[first_hit];
			const struct rte_hash_key_x *key_slot =
				(const struct rte_hash_key_x *)(
				(const char *)h->key_store +
				key_idx * h->key_entry_size);
			rte_prefetch0(key_slot);
			continue;
		}

		if (sec_hitmask[i]) {
			uint32_t first_hit =
					__builtin_ctzl(sec_hitmask[i])
					>> 1;
			uint32_t key_idx =
				secondary_bkt[i]->key_idx[first_hit];
			const struct rte_hash_key_x *key_slot =
				(const struct rte_hash_key_x *)(
				(const char *)h->key_store +
				key_idx * h->key_entry_size);
			rte_prefetch0(key_slot);
		}
	}

	/* Compare keys, first hits in primary first */
	for (i = 0; i < num_keys; i++) {
		positions[i] = -ENOENT;
		while (prim_hitmask[i]) {
			uint32_t hit_index =
					__builtin_ctzl(prim_hitmask[i])
					>> 1;
			uint32_t key_idx =
				primary_bkt[i]->key_idx[hit_index];
			const struct rte_hash_key_x *key_slot =
				(const struct rte_hash_key_x *)(
				(const char *)h->key_store +
				key_idx * h->key_entry_size);

			/*
			 * If key index is 0, do not compare key,
			 * as it is checking the dummy slot
			 */
			if (!!key_idx &
				!rte_hash_cmp_eq_x(
					key_slot->key, keys[i], h)) {
				if (data != NULL)
					data[i] = key_slot->pdata;

				hits |= 1ULL << i;
				positions[i] = key_idx - 1;
				goto next_key;
			}
			prim_hitmask[i] &= ~(3ULL << (hit_index << 1));
		}

		while (sec_hitmask[i]) {
			uint32_t hit_index =
					__builtin_ctzl(sec_hitmask[i])
					>> 1;
			uint32_t key_idx =
				secondary_bkt[i]->key_idx[hit_index];
			const struct rte_hash_key_x *key_slot =
				(const struct rte_hash_key_x *)(
				(const char *)h->key_store +
				key_idx * h->key_entry_size);

			/*
			 * If key index is 0, do not compare key,
			 * as it is checking the dummy slot
			 */

			if (!!key_idx &
				!rte_hash_cmp_eq_x(
					key_slot->key, keys[i], h)) {
				if (data != NULL)
					data[i] = key_slot->pdata;

				hits |= 1ULL << i;
				positions[i] = key_idx - 1;
				goto next_key;
			}
			sec_hitmask[i] &= ~(3ULL << (hit_index << 1));
		}
next_key:
		continue;
	}

	/* all found, do not need to go through ext bkt */
	if ((hits == ((1ULL << num_keys) - 1)) || !h->ext_table_support) {
		if (hit_mask != NULL)
			*hit_mask = hits;
		__hash_rw_reader_unlock_x(h);
		return;
	}

	/* need to check ext buckets for match */
	for (i = 0; i < num_keys; i++) {
		if ((hits & (1ULL << i)) != 0)
			continue;
		next_bkt = secondary_bkt[i]->next;
		FOR_EACH_BUCKET(cur_bkt, next_bkt) {
			if (data != NULL)
				ret = search_one_bucket_l_x(h, keys[i],
						sig[i], &data[i], cur_bkt);
			else
				ret = search_one_bucket_l_x(h, keys[i],
						sig[i], NULL, cur_bkt);
			if (ret != -1) {
				positions[i] = ret;
				hits |= 1ULL << i;
				break;
			}
		}
	}

	__hash_rw_reader_unlock_x(h);

	if (hit_mask != NULL)
		*hit_mask = hits;
}

static inline void
__rte_hash_lookup_bulk_lf_x(const struct rte_hash_x *h, const void **keys,
			int32_t num_keys, int32_t *positions,
			uint64_t *hit_mask, void *data[])
{
	uint64_t hits = 0;
	int32_t i;
	int32_t ret;
	uint32_t prim_hash[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t prim_index[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t sec_index[RTE_HASH_LOOKUP_BULK_MAX];
	uint16_t sig[RTE_HASH_LOOKUP_BULK_MAX];
	const struct rte_hash_bucket_x *primary_bkt[RTE_HASH_LOOKUP_BULK_MAX];
	const struct rte_hash_bucket_x *secondary_bkt[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t prim_hitmask[RTE_HASH_LOOKUP_BULK_MAX] = {0};
	uint32_t sec_hitmask[RTE_HASH_LOOKUP_BULK_MAX] = {0};
	struct rte_hash_bucket_x *cur_bkt, *next_bkt;
	void *pdata[RTE_HASH_LOOKUP_BULK_MAX];
	uint32_t cnt_b, cnt_a;

	/* Prefetch first keys */
	for (i = 0; i < PREFETCH_OFFSET && i < num_keys; i++)
		rte_prefetch0(keys[i]);

	/*
	 * Prefetch rest of the keys, calculate primary and
	 * secondary bucket and prefetch them
	 */
	for (i = 0; i < (num_keys - PREFETCH_OFFSET); i++) {
		rte_prefetch0(keys[i + PREFETCH_OFFSET]);

		prim_hash[i] = rte_hash_hash_x(h, keys[i]);

		sig[i] = get_short_sig_x(prim_hash[i]);
		prim_index[i] = get_prim_bucket_index_x(h, prim_hash[i]);
		sec_index[i] = get_alt_bucket_index_x(h, prim_index[i], sig[i]);

		primary_bkt[i] = &h->buckets[prim_index[i]];
		secondary_bkt[i] = &h->buckets[sec_index[i]];

		rte_prefetch0(primary_bkt[i]);
		rte_prefetch0(secondary_bkt[i]);
	}

	/* Calculate and prefetch rest of the buckets */
	for (; i < num_keys; i++) {
		prim_hash[i] = rte_hash_hash_x(h, keys[i]);

		sig[i] = get_short_sig_x(prim_hash[i]);
		prim_index[i] = get_prim_bucket_index_x(h, prim_hash[i]);
		sec_index[i] = get_alt_bucket_index_x(h, prim_index[i], sig[i]);

		primary_bkt[i] = &h->buckets[prim_index[i]];
		secondary_bkt[i] = &h->buckets[sec_index[i]];

		rte_prefetch0(primary_bkt[i]);
		rte_prefetch0(secondary_bkt[i]);
	}

	do {
		/* Load the table change counter before the lookup
		 * starts. Acquire semantics will make sure that
		 * loads in compare_signatures are not hoisted.
		 */
		cnt_b = __atomic_load_n(h->tbl_chng_cnt,
					__ATOMIC_ACQUIRE);

		/* Compare signatures and prefetch key slot of first hit */
		for (i = 0; i < num_keys; i++) {
			compare_signatures_x(&prim_hitmask[i], &sec_hitmask[i],
				primary_bkt[i], secondary_bkt[i],
				sig[i], h->sig_cmp_fn);

			if (prim_hitmask[i]) {
				uint32_t first_hit =
						__builtin_ctzl(prim_hitmask[i])
						>> 1;
				uint32_t key_idx =
					primary_bkt[i]->key_idx[first_hit];
				const struct rte_hash_key_x *key_slot =
					(const struct rte_hash_key_x *)(
					(const char *)h->key_store +
					key_idx * h->key_entry_size);
				rte_prefetch0(key_slot);
				continue;
			}

			if (sec_hitmask[i]) {
				uint32_t first_hit =
						__builtin_ctzl(sec_hitmask[i])
						>> 1;
				uint32_t key_idx =
					secondary_bkt[i]->key_idx[first_hit];
				const struct rte_hash_key_x *key_slot =
					(const struct rte_hash_key_x *)(
					(const char *)h->key_store +
					key_idx * h->key_entry_size);
				rte_prefetch0(key_slot);
			}
		}

		/* Compare keys, first hits in primary first */
		for (i = 0; i < num_keys; i++) {
			positions[i] = -ENOENT;
			while (prim_hitmask[i]) {
				uint32_t hit_index =
						__builtin_ctzl(prim_hitmask[i])
						>> 1;
				uint32_t key_idx =
				__atomic_load_n(
					&primary_bkt[i]->key_idx[hit_index],
					__ATOMIC_ACQUIRE);
				const struct rte_hash_key_x *key_slot =
					(const struct rte_hash_key_x *)(
					(const char *)h->key_store +
					key_idx * h->key_entry_size);

				if (key_idx != EMPTY_SLOT)
					pdata[i] = __atomic_load_n(
							&key_slot->pdata,
							__ATOMIC_ACQUIRE);
				/*
				 * If key index is 0, do not compare key,
				 * as it is checking the dummy slot
				 */
				if (!!key_idx &
					!rte_hash_cmp_eq_x(
						key_slot->key, keys[i], h)) {
					if (data != NULL)
						data[i] = pdata[i];

					hits |= 1ULL << i;
					positions[i] = key_idx - 1;
					goto next_key;
				}
				prim_hitmask[i] &= ~(3ULL << (hit_index << 1));
			}

			while (sec_hitmask[i]) {
				uint32_t hit_index =
						__builtin_ctzl(sec_hitmask[i])
						>> 1;
				uint32_t key_idx =
				__atomic_load_n(
					&secondary_bkt[i]->key_idx[hit_index],
					__ATOMIC_ACQUIRE);
				const struct rte_hash_key_x *key_slot =
					(const struct rte_hash_key_x *)(
					(const char *)h->key_store +
					key_idx * h->key_entry_size);

				if (key_idx != EMPTY_SLOT)
					pdata[i] = __atomic_load_n(
							&key_slot->pdata,
							__ATOMIC_ACQUIRE);
				/*
				 * If key index is 0, do not compare key,
				 * as it is checking the dummy slot
				 */

				if (!!key_idx &
					!rte_hash_cmp_eq_x(
						key_slot->key, keys[i], h)) {
					if (data != NULL)
						data[i] = pdata[i];

					hits |= 1ULL << i;
					positions[i] = key_idx - 1;
					goto next_key;
				}
				sec_hitmask[i] &= ~(3ULL << (hit_index << 1));
			}
next_key:
			continue;
		}

		/* The loads of sig_current in compare_signatures
		 * should not move below the load from tbl_chng_cnt.
		 */
		__atomic_thread_fence(__ATOMIC_ACQUIRE);
		/* Re-read the table change counter to check if the
		 * table has changed during search. If yes, re-do
		 * the search.
		 * This load should not get hoisted. The load
		 * acquires on cnt_b, primary key index and secondary
		 * key index will make sure that it does not get
		 * hoisted.
		 */
		cnt_a = __atomic_load_n(h->tbl_chng_cnt,
					__ATOMIC_ACQUIRE);
	} while (cnt_b != cnt_a);

	/* all found, do not need to go through ext bkt */
	if ((hits == ((1ULL << num_keys) - 1)) || !h->ext_table_support) {
		if (hit_mask != NULL)
			*hit_mask = hits;
		__hash_rw_reader_unlock_x(h);
		return;
	}

	/* need to check ext buckets for match */
	for (i = 0; i < num_keys; i++) {
		if ((hits & (1ULL << i)) != 0)
			continue;
		next_bkt = secondary_bkt[i]->next;
		FOR_EACH_BUCKET(cur_bkt, next_bkt) {
			if (data != NULL)
				ret = search_one_bucket_lf_x(h, keys[i],
						sig[i], &data[i], cur_bkt);
			else
				ret = search_one_bucket_lf_x(h, keys[i],
						sig[i], NULL, cur_bkt);
			if (ret != -1) {
				positions[i] = ret;
				hits |= 1ULL << i;
				break;
			}
		}
	}

	if (hit_mask != NULL)
		*hit_mask = hits;
}

static inline void
__rte_hash_lookup_bulk_x(const struct rte_hash_x *h, const void **keys,
			int32_t num_keys, int32_t *positions,
			uint64_t *hit_mask, void *data[])
{
	if (h->readwrite_concur_lf_support)
		return __rte_hash_lookup_bulk_lf_x(h, keys, num_keys,
						positions, hit_mask, data);
	else
		return __rte_hash_lookup_bulk_l_x(h, keys, num_keys,
						positions, hit_mask, data);
}

int32_t
rte_hash_lookup_bulk_x(const struct rte_hash_x *h, const void **keys,
		      uint32_t num_keys, int32_t *positions)
{
	RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (num_keys == 0) ||
			(num_keys > RTE_HASH_LOOKUP_BULK_MAX) ||
			(positions == NULL)), -EINVAL);
        uint64_t hit_mask;
        
	__rte_hash_lookup_bulk_x(h, keys, num_keys, positions, &hit_mask, NULL);
	return __builtin_popcountl(hit_mask);
}

int32_t
rte_hash_lookup_bulk_data_x(const struct rte_hash_x *h, const void **keys,
		      uint32_t num_keys, uint64_t *hit_mask, void *data[])
{
	RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (num_keys == 0) ||
			(num_keys > RTE_HASH_LOOKUP_BULK_MAX) ||
			(hit_mask == NULL)), -EINVAL);
        
        int32_t positions[num_keys];

	__rte_hash_lookup_bulk_x(h, keys, num_keys, positions, hit_mask, data);

	/* Return number of hits */
	return __builtin_popcountl(*hit_mask);
}

int32_t
rte_hash_lookup_bulk_data_with_position_x(const struct rte_hash_x *h, const void **keys,
		      uint32_t num_keys, int32_t *positions, uint64_t *hit_mask, void *data[])
{
	RETURN_IF_TRUE(((h == NULL) || (keys == NULL) || (num_keys == 0) ||
			(num_keys > RTE_HASH_LOOKUP_BULK_MAX) ||
			(hit_mask == NULL)), -EINVAL);

	__rte_hash_lookup_bulk_x(h, keys, num_keys, positions, hit_mask, data);

	/* Return number of hits */
	return __builtin_popcountl(*hit_mask);
}

int32_t
rte_hash_iterate_x(const struct rte_hash_x *h, const void **key, void **data, uint32_t *next)
{
	uint32_t bucket_idx, idx, position;
	struct rte_hash_key_x *next_key;

	RETURN_IF_TRUE(((h == NULL) || (next == NULL)), -EINVAL);

	const uint32_t total_entries_main = h->num_buckets *
							RTE_HASH_BUCKET_ENTRIES;
	const uint32_t total_entries = total_entries_main << 1;

	/* Out of bounds of all buckets (both main table and ext table) */
	if (*next >= total_entries_main)
		goto extend_table;

	/* Calculate bucket and index of current iterator */
	bucket_idx = *next / RTE_HASH_BUCKET_ENTRIES;
	idx = *next % RTE_HASH_BUCKET_ENTRIES;

	/* If current position is empty, go to the next one */
	while ((position = __atomic_load_n(&h->buckets[bucket_idx].key_idx[idx],
					__ATOMIC_ACQUIRE)) == EMPTY_SLOT) {
		(*next)++;
		/* End of table */
		if (*next == total_entries_main)
			goto extend_table;
		bucket_idx = *next / RTE_HASH_BUCKET_ENTRIES;
		idx = *next % RTE_HASH_BUCKET_ENTRIES;
	}

	__hash_rw_reader_lock_x(h);
	next_key = (struct rte_hash_key_x *) ((char *)h->key_store +
				position * h->key_entry_size);
	/* Return key and data */
	*key = next_key->key;
	*data = next_key->pdata;

	__hash_rw_reader_unlock_x(h);

	/* Increment iterator */
	(*next)++;

	return position - 1;

/* Begin to iterate extendable buckets */
extend_table:
	/* Out of total bound or if ext bucket feature is not enabled */
	if (*next >= total_entries || !h->ext_table_support)
		return -ENOENT;

	bucket_idx = (*next - total_entries_main) / RTE_HASH_BUCKET_ENTRIES;
	idx = (*next - total_entries_main) % RTE_HASH_BUCKET_ENTRIES;

	while ((position = h->buckets_ext[bucket_idx].key_idx[idx]) == EMPTY_SLOT) {
		(*next)++;
		if (*next == total_entries)
			return -ENOENT;
		bucket_idx = (*next - total_entries_main) /
						RTE_HASH_BUCKET_ENTRIES;
		idx = (*next - total_entries_main) % RTE_HASH_BUCKET_ENTRIES;
	}
	__hash_rw_reader_lock_x(h);
	next_key = (struct rte_hash_key_x *) ((char *)h->key_store +
				position * h->key_entry_size);
	/* Return key and data */
	*key = next_key->key;
	*data = next_key->pdata;

	__hash_rw_reader_unlock_x(h);

	/* Increment iterator */
	(*next)++;
	return position - 1;
}
