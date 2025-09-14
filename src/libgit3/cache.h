/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_cache_h__
#define INCLUDE_cache_h__

#include "common.h"

#include "git3/common.h"
#include "git3/oid.h"
#include "git3/odb.h"

#include "thread.h"
#include "hashmap_oid.h"

enum {
	GIT3_CACHE_STORE_ANY = 0,
	GIT3_CACHE_STORE_RAW = 1,
	GIT3_CACHE_STORE_PARSED = 2
};

typedef struct {
	git3_oid      oid;
	int16_t      type;  /* git3_object_t value */
	uint16_t     flags; /* GIT3_CACHE_STORE value */
	size_t       size;
	git3_atomic32 refcount;
} git3_cached_obj;

GIT3_HASHMAP_OID_STRUCT(git3_cache_oidmap, git3_cached_obj *);

typedef struct {
	git3_cache_oidmap map;
	git3_rwlock       lock;
	ssize_t          used_memory;
} git3_cache;

extern bool git3_cache__enabled;
extern ssize_t git3_cache__max_storage;
extern git3_atomic_ssize git3_cache__current_storage;

int git3_cache_set_max_object_size(git3_object_t type, size_t size);

int git3_cache_init(git3_cache *cache);
void git3_cache_dispose(git3_cache *cache);
void git3_cache_clear(git3_cache *cache);
size_t git3_cache_size(git3_cache *cache);

void *git3_cache_store_raw(git3_cache *cache, git3_odb_object *entry);
void *git3_cache_store_parsed(git3_cache *cache, git3_object *entry);

git3_odb_object *git3_cache_get_raw(git3_cache *cache, const git3_oid *oid);
git3_object *git3_cache_get_parsed(git3_cache *cache, const git3_oid *oid);
void *git3_cache_get_any(git3_cache *cache, const git3_oid *oid);

GIT3_INLINE(void) git3_cached_obj_incref(void *_obj)
{
	git3_cached_obj *obj = _obj;
	git3_atomic32_inc(&obj->refcount);
}

void git3_cached_obj_decref(void *_obj);

#endif
