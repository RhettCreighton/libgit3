/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "cache.h"

#include "repository.h"
#include "commit.h"
#include "thread.h"
#include "util.h"
#include "odb.h"
#include "object.h"
#include "git3/oid.h"
#include "hashmap_oid.h"

GIT3_HASHMAP_OID_FUNCTIONS(git3_cache_oidmap, GIT3_HASHMAP_INLINE, git3_cached_obj *);

bool git3_cache__enabled = true;
ssize_t git3_cache__max_storage = (256 * 1024 * 1024);
git3_atomic_ssize git3_cache__current_storage = {0};

static size_t git3_cache__max_object_size[8] = {
	0,     /* GIT3_OBJECT__EXT1 */
	4096,  /* GIT3_OBJECT_COMMIT */
	4096,  /* GIT3_OBJECT_TREE */
	0,     /* GIT3_OBJECT_BLOB */
	4096,  /* GIT3_OBJECT_TAG */
	0,     /* GIT3_OBJECT__EXT2 */
	0,     /* GIT3_OBJECT_OFS_DELTA */
	0      /* GIT3_OBJECT_REF_DELTA */
};

int git3_cache_set_max_object_size(git3_object_t type, size_t size)
{
	if (type < 0 || (size_t)type >= ARRAY_SIZE(git3_cache__max_object_size)) {
		git3_error_set(GIT3_ERROR_INVALID, "type out of range");
		return -1;
	}

	git3_cache__max_object_size[type] = size;
	return 0;
}

int git3_cache_init(git3_cache *cache)
{
	memset(cache, 0, sizeof(*cache));

	if (git3_rwlock_init(&cache->lock)) {
		git3_error_set(GIT3_ERROR_OS, "failed to initialize cache rwlock");
		return -1;
	}

	return 0;
}

/* called with lock */
static void clear_cache(git3_cache *cache)
{
	git3_cached_obj *evict = NULL;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;

	if (git3_cache_size(cache) == 0)
		return;

	while (git3_cache_oidmap_iterate(&iter, NULL, &evict, &cache->map) == 0)
		git3_cached_obj_decref(evict);

	git3_cache_oidmap_clear(&cache->map);
	git3_atomic_ssize_add(&git3_cache__current_storage, -cache->used_memory);
	cache->used_memory = 0;
}

void git3_cache_clear(git3_cache *cache)
{
	if (git3_rwlock_wrlock(&cache->lock) < 0)
		return;

	clear_cache(cache);

	git3_rwlock_wrunlock(&cache->lock);
}

size_t git3_cache_size(git3_cache *cache)
{
	return git3_cache_oidmap_size(&cache->map);
}

void git3_cache_dispose(git3_cache *cache)
{
	git3_cache_clear(cache);
	git3_cache_oidmap_dispose(&cache->map);
	git3_rwlock_free(&cache->lock);
	git3__memzero(cache, sizeof(*cache));
}

/* Called with lock */
static void cache_evict_entries(git3_cache *cache)
{
	size_t evict_count = git3_cache_size(cache) / 2048;
	ssize_t evicted_memory = 0;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;

	if (evict_count < 8)
		evict_count = 8;

	/* do not infinite loop if there's not enough entries to evict  */
	if (evict_count > git3_cache_size(cache)) {
		clear_cache(cache);
		return;
	}

	while (evict_count > 0) {
		const git3_oid *key;
		git3_cached_obj *evict;

		if (git3_cache_oidmap_iterate(&iter, &key, &evict, &cache->map) != 0)
			break;

		evict_count--;
		evicted_memory += evict->size;
		git3_cache_oidmap_remove(&cache->map, key);
		git3_cached_obj_decref(evict);
	}

	cache->used_memory -= evicted_memory;
	git3_atomic_ssize_add(&git3_cache__current_storage, -evicted_memory);
}

static bool cache_should_store(git3_object_t object_type, size_t object_size)
{
	size_t max_size = git3_cache__max_object_size[object_type];
	return git3_cache__enabled && object_size < max_size;
}

static void *cache_get(git3_cache *cache, const git3_oid *oid, unsigned int flags)
{
	git3_cached_obj *entry = NULL;

	if (!git3_cache__enabled || git3_rwlock_rdlock(&cache->lock) < 0)
		return NULL;

	if (git3_cache_oidmap_get(&entry, &cache->map, oid) == 0) {
		if (flags && entry->flags != flags) {
			entry = NULL;
		} else {
			git3_cached_obj_incref(entry);
		}
	}

	git3_rwlock_rdunlock(&cache->lock);

	return entry;
}

static void *cache_store(git3_cache *cache, git3_cached_obj *entry)
{
	git3_cached_obj *stored_entry;

	git3_cached_obj_incref(entry);

	if (!git3_cache__enabled && cache->used_memory > 0) {
		git3_cache_clear(cache);
		return entry;
	}

	if (!cache_should_store(entry->type, entry->size))
		return entry;

	if (git3_rwlock_wrlock(&cache->lock) < 0)
		return entry;

	/* soften the load on the cache */
	if (git3_atomic_ssize_get(&git3_cache__current_storage) > git3_cache__max_storage)
		cache_evict_entries(cache);

	/* not found */
	if (git3_cache_oidmap_get(&stored_entry, &cache->map, &entry->oid) != 0) {
		if (git3_cache_oidmap_put(&cache->map, &entry->oid, entry) == 0) {
			git3_cached_obj_incref(entry);
			cache->used_memory += entry->size;
			git3_atomic_ssize_add(&git3_cache__current_storage, (ssize_t)entry->size);
		}
	}
	/* found */
	else {
		if (stored_entry->flags == entry->flags) {
			git3_cached_obj_decref(entry);
			git3_cached_obj_incref(stored_entry);
			entry = stored_entry;
		} else if (stored_entry->flags == GIT3_CACHE_STORE_RAW &&
			   entry->flags == GIT3_CACHE_STORE_PARSED) {
			if (git3_cache_oidmap_put(&cache->map, &entry->oid, entry) == 0) {
				git3_cached_obj_decref(stored_entry);
				git3_cached_obj_incref(entry);
			} else {
				git3_cached_obj_decref(entry);
				git3_cached_obj_incref(stored_entry);
				entry = stored_entry;
			}
		} else {
			/* NO OP */
		}
	}

	git3_rwlock_wrunlock(&cache->lock);
	return entry;
}

void *git3_cache_store_raw(git3_cache *cache, git3_odb_object *entry)
{
	entry->cached.flags = GIT3_CACHE_STORE_RAW;
	return cache_store(cache, (git3_cached_obj *)entry);
}

void *git3_cache_store_parsed(git3_cache *cache, git3_object *entry)
{
	entry->cached.flags = GIT3_CACHE_STORE_PARSED;
	return cache_store(cache, (git3_cached_obj *)entry);
}

git3_odb_object *git3_cache_get_raw(git3_cache *cache, const git3_oid *oid)
{
	return cache_get(cache, oid, GIT3_CACHE_STORE_RAW);
}

git3_object *git3_cache_get_parsed(git3_cache *cache, const git3_oid *oid)
{
	return cache_get(cache, oid, GIT3_CACHE_STORE_PARSED);
}

void *git3_cache_get_any(git3_cache *cache, const git3_oid *oid)
{
	return cache_get(cache, oid, GIT3_CACHE_STORE_ANY);
}

void git3_cached_obj_decref(void *_obj)
{
	git3_cached_obj *obj = _obj;

	if (git3_atomic32_dec(&obj->refcount) == 0) {
		switch (obj->flags) {
		case GIT3_CACHE_STORE_RAW:
			git3_odb_object__free(_obj);
			break;

		case GIT3_CACHE_STORE_PARSED:
			git3_object__free(_obj);
			break;

		default:
			git3__free(_obj);
			break;
		}
	}
}
