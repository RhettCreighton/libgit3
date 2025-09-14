/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_index_map_h__
#define INCLUDE_index_map_h__

#include "common.h"
#include "hashmap.h"

typedef struct {
	unsigned int ignore_case;
	GIT3_HASHMAP_STRUCT_MEMBERS(git3_index_entry *, git3_index_entry *)
} git3_index_entrymap;

#define GIT3_INDEX_ENTRYMAP_INIT { 0 }

extern int git3_index_entrymap_get(git3_index_entry **out, git3_index_entrymap *map, git3_index_entry *e);
extern int git3_index_entrymap_put(git3_index_entrymap *map, git3_index_entry *e);
extern int git3_index_entrymap_remove(git3_index_entrymap *map, git3_index_entry *e);
extern int git3_index_entrymap_resize(git3_index_entrymap *map, size_t count);
extern void git3_index_entrymap_swap(git3_index_entrymap *a, git3_index_entrymap *b);
extern void git3_index_entrymap_clear(git3_index_entrymap *map);
extern void git3_index_entrymap_dispose(git3_index_entrymap *map);

#endif
