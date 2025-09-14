/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "sortedcache.h"
#include "hashmap.h"

int git3_sortedcache_new(
	git3_sortedcache **out,
	size_t item_path_offset,
	git3_sortedcache_free_item_fn free_item,
	void *free_item_payload,
	git3_vector_cmp item_cmp,
	const char *path)
{
	git3_sortedcache *sc;
	size_t pathlen, alloclen;

	pathlen = path ? strlen(path) : 0;

	GIT3_ERROR_CHECK_ALLOC_ADD(&alloclen, sizeof(git3_sortedcache), pathlen);
	GIT3_ERROR_CHECK_ALLOC_ADD(&alloclen, alloclen, 1);
	sc = git3__calloc(1, alloclen);
	GIT3_ERROR_CHECK_ALLOC(sc);

	if (git3_pool_init(&sc->pool, 1) < 0 ||
	    git3_vector_init(&sc->items, 4, item_cmp) < 0)
		goto fail;

	if (git3_rwlock_init(&sc->lock)) {
		git3_error_set(GIT3_ERROR_OS, "failed to initialize lock");
		goto fail;
	}

	sc->item_path_offset  = item_path_offset;
	sc->free_item         = free_item;
	sc->free_item_payload = free_item_payload;
	GIT3_REFCOUNT_INC(sc);
	if (pathlen)
		memcpy(sc->path, path, pathlen);

	*out = sc;
	return 0;

fail:
	git3_vector_dispose(&sc->items);
	git3_pool_clear(&sc->pool);
	git3__free(sc);
	return -1;
}

void git3_sortedcache_incref(git3_sortedcache *sc)
{
	GIT3_REFCOUNT_INC(sc);
}

const char *git3_sortedcache_path(git3_sortedcache *sc)
{
	return sc->path;
}

static void sortedcache_clear(git3_sortedcache *sc)
{
	git3_hashmap_str_clear(&sc->map);

	if (sc->free_item) {
		size_t i;
		void *item;

		git3_vector_foreach(&sc->items, i, item) {
			sc->free_item(sc->free_item_payload, item);
		}
	}

	git3_vector_clear(&sc->items);

	git3_pool_clear(&sc->pool);
}

static void sortedcache_free(git3_sortedcache *sc)
{
	/* acquire write lock to make sure everyone else is done */
	if (git3_sortedcache_wlock(sc) < 0)
		return;

	sortedcache_clear(sc);
	git3_vector_dispose(&sc->items);
	git3_hashmap_str_dispose(&sc->map);

	git3_sortedcache_wunlock(sc);

	git3_rwlock_free(&sc->lock);
	git3__free(sc);
}

void git3_sortedcache_free(git3_sortedcache *sc)
{
	if (!sc)
		return;
	GIT3_REFCOUNT_DEC(sc, sortedcache_free);
}

static int sortedcache_copy_item(void *payload, void *tgt_item, void *src_item)
{
	git3_sortedcache *sc = payload;
	/* path will already have been copied by upsert */
	memcpy(tgt_item, src_item, sc->item_path_offset);
	return 0;
}

/* copy a sorted cache */
int git3_sortedcache_copy(
	git3_sortedcache **out,
	git3_sortedcache *src,
	bool lock,
	int (*copy_item)(void *payload, void *tgt_item, void *src_item),
	void *payload)
{
	int error = 0;
	git3_sortedcache *tgt;
	size_t i;
	void *src_item, *tgt_item;

	/* just use memcpy if no special copy fn is passed in */
	if (!copy_item) {
		copy_item = sortedcache_copy_item;
		payload   = src;
	}

	if ((error = git3_sortedcache_new(
			&tgt, src->item_path_offset,
			src->free_item, src->free_item_payload,
			src->items._cmp, src->path)) < 0)
		return error;

	if (lock && git3_sortedcache_rlock(src) < 0) {
		git3_sortedcache_free(tgt);
		return -1;
	}

	git3_vector_foreach(&src->items, i, src_item) {
		char *path = ((char *)src_item) + src->item_path_offset;

		if ((error = git3_sortedcache_upsert(&tgt_item, tgt, path)) < 0 ||
			(error = copy_item(payload, tgt_item, src_item)) < 0)
			break;
	}

	if (lock)
		git3_sortedcache_runlock(src);
	if (error)
		git3_sortedcache_free(tgt);

	*out = !error ? tgt : NULL;

	return error;
}

/* lock sortedcache while making modifications */
int git3_sortedcache_wlock(git3_sortedcache *sc)
{
	GIT3_UNUSED(sc); /* prevent warning when compiled w/o threads */

	if (git3_rwlock_wrlock(&sc->lock) < 0) {
		git3_error_set(GIT3_ERROR_OS, "unable to acquire write lock on cache");
		return -1;
	}
	return 0;
}

/* unlock sorted cache when done with modifications */
void git3_sortedcache_wunlock(git3_sortedcache *sc)
{
	git3_vector_sort(&sc->items);
	git3_rwlock_wrunlock(&sc->lock);
}

/* lock sortedcache for read */
int git3_sortedcache_rlock(git3_sortedcache *sc)
{
	GIT3_UNUSED(sc); /* prevent warning when compiled w/o threads */

	if (git3_rwlock_rdlock(&sc->lock) < 0) {
		git3_error_set(GIT3_ERROR_OS, "unable to acquire read lock on cache");
		return -1;
	}
	return 0;
}

/* unlock sorted cache when done reading */
void git3_sortedcache_runlock(git3_sortedcache *sc)
{
	GIT3_UNUSED(sc); /* prevent warning when compiled w/o threads */
	git3_rwlock_rdunlock(&sc->lock);
}

/* if the file has changed, lock cache and load file contents into buf;
 * returns <0 on error, >0 if file has not changed
 */
int git3_sortedcache_lockandload(git3_sortedcache *sc, git3_str *buf)
{
	int error, fd;
	struct stat st;

	if ((error = git3_sortedcache_wlock(sc)) < 0)
		return error;

	if ((error = git3_futils_filestamp_check(&sc->stamp, sc->path)) <= 0)
		goto unlock;

	if ((fd = git3_futils_open_ro(sc->path)) < 0) {
		error = fd;
		goto unlock;
	}

	if (p_fstat(fd, &st) < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to stat file");
		error = -1;
		(void)p_close(fd);
		goto unlock;
	}

	if (!git3__is_sizet(st.st_size)) {
		git3_error_set(GIT3_ERROR_INVALID, "unable to load file larger than size_t");
		error = -1;
		(void)p_close(fd);
		goto unlock;
	}

	if (buf)
		error = git3_futils_readbuffer_fd(buf, fd, (size_t)st.st_size);

	(void)p_close(fd);

	if (error < 0)
		goto unlock;

	return 1; /* return 1 -> file needs reload and was successfully loaded */

unlock:
	git3_sortedcache_wunlock(sc);
	return error;
}

void git3_sortedcache_updated(git3_sortedcache *sc)
{
	/* update filestamp to latest value */
	git3_futils_filestamp_check(&sc->stamp, sc->path);
}

/* release all items in sorted cache */
int git3_sortedcache_clear(git3_sortedcache *sc, bool wlock)
{
	if (wlock && git3_sortedcache_wlock(sc) < 0)
		return -1;

	sortedcache_clear(sc);

	if (wlock)
		git3_sortedcache_wunlock(sc);

	return 0;
}

/* find and/or insert item, returning pointer to item data */
int git3_sortedcache_upsert(void **out, git3_sortedcache *sc, const char *key)
{
	size_t keylen, itemlen;
	int error = 0;
	char *item_key;
	void *item;

	if (git3_hashmap_str_get(&item, &sc->map, key) == 0)
		goto done;

	keylen  = strlen(key);
	itemlen = sc->item_path_offset + keylen + 1;
	itemlen = (itemlen + 7) & ~7;

	if ((item = git3_pool_mallocz(&sc->pool, itemlen)) == NULL) {
		/* don't use GIT3_ERROR_CHECK_ALLOC b/c of lock */
		error = -1;
		goto done;
	}

	/* one strange thing is that even if the vector or hash table insert
	 * fail, there is no way to free the pool item so we just abandon it
	 */

	item_key = ((char *)item) + sc->item_path_offset;
	memcpy(item_key, key, keylen);

	if ((error = git3_hashmap_str_put(&sc->map, item_key, item)) < 0)
		goto done;

	if ((error = git3_vector_insert(&sc->items, item)) < 0)
		git3_hashmap_str_remove(&sc->map, item_key);

done:
	if (out)
		*out = !error ? item : NULL;
	return error;
}

/* lookup item by key */
void *git3_sortedcache_lookup(git3_sortedcache *sc, const char *key)
{
	void *value;

	return git3_hashmap_str_get(&value, &sc->map, key) == 0 ? value : NULL;
}

/* find out how many items are in the cache */
size_t git3_sortedcache_entrycount(const git3_sortedcache *sc)
{
	return git3_vector_length(&sc->items);
}

/* lookup item by index */
void *git3_sortedcache_entry(git3_sortedcache *sc, size_t pos)
{
	/* make sure the items are sorted so this gets the correct item */
	if (!git3_vector_is_sorted(&sc->items))
		git3_vector_sort(&sc->items);

	return git3_vector_get(&sc->items, pos);
}

/* helper struct so bsearch callback can know offset + key value for cmp */
struct sortedcache_magic_key {
	size_t offset;
	const char *key;
};

static int sortedcache_magic_cmp(const void *key, const void *value)
{
	const struct sortedcache_magic_key *magic = key;
	const char *value_key = ((const char *)value) + magic->offset;
	return strcmp(magic->key, value_key);
}

/* lookup index of item by key */
int git3_sortedcache_lookup_index(
	size_t *out, git3_sortedcache *sc, const char *key)
{
	struct sortedcache_magic_key magic;

	magic.offset = sc->item_path_offset;
	magic.key    = key;

	return git3_vector_bsearch2(out, &sc->items, sortedcache_magic_cmp, &magic);
}

/* remove entry from cache */
int git3_sortedcache_remove(git3_sortedcache *sc, size_t pos)
{
	char *item;

	/*
	 * Because of pool allocation, this can't actually remove the item,
	 * but we can remove it from the items vector and the hash table.
	 */

	if ((item = git3_vector_get(&sc->items, pos)) == NULL) {
		git3_error_set(GIT3_ERROR_INVALID, "removing item out of range");
		return GIT3_ENOTFOUND;
	}

	(void)git3_vector_remove(&sc->items, pos);

	git3_hashmap_str_remove(&sc->map, item + sc->item_path_offset);

	if (sc->free_item)
		sc->free_item(sc->free_item_payload, item);

	return 0;
}

