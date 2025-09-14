/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "hashmap.h"
#include "index_map.h"

typedef git3_index_entrymap git3_index_entrymap_default;
typedef git3_index_entrymap git3_index_entrymap_icase;

/* This is __ac_X31_hash_string but with tolower and it takes the entry's stage into account */
GIT3_INLINE(uint32_t) git3_index_entrymap_hash(const git3_index_entry *e)
{
	const char *s = e->path;
	uint32_t h = (uint32_t)git3__tolower(*s);
	if (h) {
		for (++s ; *s; ++s)
			h = (h << 5) - h + (uint32_t)git3__tolower(*s);
	}
	return h + GIT3_INDEX_ENTRY_STAGE(e);
}

#define git3_index_entrymap_equal_default(a, b) (GIT3_INDEX_ENTRY_STAGE(a) == GIT3_INDEX_ENTRY_STAGE(b) && strcmp(a->path, b->path) == 0)
#define git3_index_entrymap_equal_icase(a, b) (GIT3_INDEX_ENTRY_STAGE(a) == GIT3_INDEX_ENTRY_STAGE(b) && strcasecmp(a->path, b->path) == 0)

GIT3_HASHMAP_FUNCTIONS(git3_index_entrymap_default, GIT3_HASHMAP_INLINE, git3_index_entry *, git3_index_entry *, git3_index_entrymap_hash, git3_index_entrymap_equal_default)
GIT3_HASHMAP_FUNCTIONS(git3_index_entrymap_icase, GIT3_HASHMAP_INLINE, git3_index_entry *, git3_index_entry *, git3_index_entrymap_hash, git3_index_entrymap_equal_icase)

int git3_index_entrymap_put(git3_index_entrymap *map, git3_index_entry *e)
{
	if (map->ignore_case)
		return git3_index_entrymap_icase_put((git3_index_entrymap_icase *)map, e, e);
	else
		return git3_index_entrymap_default_put((git3_index_entrymap_default *)map, e, e);
}

int git3_index_entrymap_get(git3_index_entry **out, git3_index_entrymap *map, git3_index_entry *e)
{
	if (map->ignore_case)
		return git3_index_entrymap_icase_get(out, (git3_index_entrymap_icase *)map, e);
	else
		return git3_index_entrymap_default_get(out, (git3_index_entrymap_default *)map, e);
}

int git3_index_entrymap_remove(git3_index_entrymap *map, git3_index_entry *e)
{
	if (map->ignore_case)
		return git3_index_entrymap_icase_remove((git3_index_entrymap_icase *)map, e);
	else
		return git3_index_entrymap_default_remove((git3_index_entrymap_default *)map, e);
}

int git3_index_entrymap_resize(git3_index_entrymap *map, size_t count)
{
	if (count > UINT32_MAX) {
		git3_error_set(GIT3_ERROR_INDEX, "index map is out of bounds");
		return -1;
	}

	if (map->ignore_case)
		return git3_index_entrymap_icase__resize((git3_index_entrymap_icase *)map, (uint32_t)count);
	else
		return git3_index_entrymap_default__resize((git3_index_entrymap_default *)map, (uint32_t)count);
}

void git3_index_entrymap_swap(git3_index_entrymap *a, git3_index_entrymap *b)
{
	git3_index_entrymap t;

	if (a != b) {
		memcpy(&t, a, sizeof(t));
		memcpy(a, b, sizeof(t));
		memcpy(b, &t, sizeof(t));
	}
}

void git3_index_entrymap_clear(git3_index_entrymap *map)
{
	if (map->ignore_case)
		git3_index_entrymap_icase_clear((git3_index_entrymap_icase *)map);
	else
		git3_index_entrymap_default_clear((git3_index_entrymap_default *)map);
}

void git3_index_entrymap_dispose(git3_index_entrymap *map)
{
	if (map->ignore_case)
		git3_index_entrymap_icase_dispose((git3_index_entrymap_icase *)map);
	else
		git3_index_entrymap_default_dispose((git3_index_entrymap_default *)map);
}
