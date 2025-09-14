/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_tree_cache_h__
#define INCLUDE_tree_cache_h__

#include "common.h"

#include "pool.h"
#include "str.h"
#include "git3/oid.h"

typedef struct git3_tree_cache {
	struct git3_tree_cache **children;
	size_t children_count;

	git3_oid_t oid_type;

	ssize_t entry_count;
	git3_oid oid;
	size_t namelen;
	char name[GIT3_FLEX_ARRAY];
} git3_tree_cache;

int git3_tree_cache_write(git3_str *out, git3_tree_cache *tree);
int git3_tree_cache_read(git3_tree_cache **tree, const char *buffer, size_t buffer_size, git3_oid_t oid_type, git3_pool *pool);
void git3_tree_cache_invalidate_path(git3_tree_cache *tree, const char *path);
const git3_tree_cache *git3_tree_cache_get(const git3_tree_cache *tree, const char *path);
int git3_tree_cache_new(git3_tree_cache **out, const char *name, git3_oid_t oid_type, git3_pool *pool);
/**
 * Read a tree as the root of the tree cache (like for `git read-tree`)
 */
int git3_tree_cache_read_tree(git3_tree_cache **out, const git3_tree *tree, git3_oid_t oid_type, git3_pool *pool);
void git3_tree_cache_free(git3_tree_cache *tree);

#endif
