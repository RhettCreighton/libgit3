/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_tree_h__
#define INCLUDE_tree_h__

#include "common.h"

#include "git3/tree.h"
#include "repository.h"
#include "odb.h"
#include "vector.h"
#include "pool.h"

struct git3_tree_entry {
	uint16_t attr;
	uint16_t filename_len;
	git3_oid oid;
	const char *filename;
};

struct git3_tree {
	git3_object object;
	git3_odb_object *odb_obj;
	git3_array_t(git3_tree_entry) entries;
};

GIT3_HASHMAP_STR_STRUCT(git3_treebuilder_entrymap, git3_tree_entry *);

struct git3_treebuilder {
	git3_repository *repo;
	git3_treebuilder_entrymap map;
	git3_str write_cache;
};

GIT3_INLINE(bool) git3_tree_entry__is_tree(const struct git3_tree_entry *e)
{
	return (S_ISDIR(e->attr) && !S_ISGITLINK(e->attr));
}

void git3_tree__free(void *tree);
int git3_tree__parse(void *tree, git3_odb_object *obj, git3_oid_t oid_type);
int git3_tree__parse_raw(void *_tree, const char *data, size_t size, git3_oid_t oid_type);

/**
 * Write a tree to the given repository
 */
int git3_tree__write_index(
	git3_oid *oid, git3_index *index, git3_repository *repo);

/**
 * Obsolete mode kept for compatibility reasons
 */
#define GIT3_FILEMODE_BLOB_GROUP_WRITABLE 0100664

#endif
