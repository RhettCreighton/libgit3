/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_hashmap_oid_h__
#define INCLUDE_hashmap_oid_h__

#include "hashmap.h"

GIT3_INLINE(uint32_t) git3_hashmap_oid_hashcode(const git3_oid *oid)
{
	uint32_t hash;
	memcpy(&hash, oid->id, sizeof(uint32_t));
	return hash;
}

#define GIT3_HASHMAP_OID_STRUCT(name, val_t) \
	GIT3_HASHMAP_STRUCT(name, const git3_oid *, val_t)
#define GIT3_HASHMAP_OID_PROTOTYPES(name, val_t) \
	GIT3_HASHMAP_PROTOTYPES(name, const git3_oid *, val_t)
#define GIT3_HASHMAP_OID_FUNCTIONS(name, scope, val_t) \
	GIT3_HASHMAP_FUNCTIONS(name, scope, const git3_oid *, val_t, git3_hashmap_oid_hashcode, git3_oid_equal)

#define GIT3_HASHMAP_OID_SETUP(name, val_t) \
	GIT3_HASHMAP_OID_STRUCT(name, val_t) \
	GIT3_HASHMAP_OID_FUNCTIONS(name, GIT3_HASHMAP_INLINE, val_t)

#endif
