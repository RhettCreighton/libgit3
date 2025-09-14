/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_hashmap_str_h__
#define INCLUDE_hashmap_str_h__

#include "hashmap.h"

GIT3_INLINE(uint32_t) git3_hashmap_str_hash(const char *s)
{
	uint32_t h = (uint32_t)*s;

	if (h) {
		for (++s; *s; ++s)
			h = (h << 5) - h + (uint32_t)*s;
	}

	return h;
}

GIT3_INLINE(bool) git3_hashmap_str_equal(const char *one, const char *two)
{
	return strcmp(one, two) == 0;
}

#define GIT3_HASHMAP_STR_STRUCT(name, val_t) \
	GIT3_HASHMAP_STRUCT(name, const char *, val_t)
#define GIT3_HASHMAP_STR_PROTOTYPES(name, val_t) \
	GIT3_HASHMAP_PROTOTYPES(name, const char *, val_t)
#define GIT3_HASHMAP_STR_FUNCTIONS(name, scope, val_t) \
	GIT3_HASHMAP_FUNCTIONS(name, scope, const char *, val_t, git3_hashmap_str_hash, git3_hashmap_str_equal)

#define GIT3_HASHMAP_STR_SETUP(name, val_t) \
	GIT3_HASHMAP_STR_STRUCT(name, val_t) \
	GIT3_HASHMAP_STR_FUNCTIONS(name, GIT3_HASHMAP_INLINE, val_t)

GIT3_HASHSET_SETUP(git3_hashset_str, const char *, git3_hashmap_str_hash, git3_hashmap_str_equal);
GIT3_HASHMAP_SETUP(git3_hashmap_str, const char *, void *, git3_hashmap_str_hash, git3_hashmap_str_equal);

#endif
