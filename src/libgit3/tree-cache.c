/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "tree-cache.h"

#include "pool.h"
#include "tree.h"

static git3_tree_cache *find_child(
	const git3_tree_cache *tree, const char *path, const char *end)
{
	size_t i, dirlen = end ? (size_t)(end - path) : strlen(path);

	for (i = 0; i < tree->children_count; ++i) {
		git3_tree_cache *child = tree->children[i];

		if (child->namelen == dirlen && !memcmp(path, child->name, dirlen))
			return child;
	}

	return NULL;
}

void git3_tree_cache_invalidate_path(git3_tree_cache *tree, const char *path)
{
	const char *ptr = path, *end;

	if (tree == NULL)
		return;

	tree->entry_count = -1;

	while (ptr != NULL) {
		end = strchr(ptr, '/');

		if (end == NULL) /* End of path */
			break;

		tree = find_child(tree, ptr, end);
		if (tree == NULL) /* We don't have that tree */
			return;

		tree->entry_count = -1;
		ptr = end + 1;
	}
}

const git3_tree_cache *git3_tree_cache_get(const git3_tree_cache *tree, const char *path)
{
	const char *ptr = path, *end;

	if (tree == NULL) {
		return NULL;
	}

	while (1) {
		end = strchr(ptr, '/');

		tree = find_child(tree, ptr, end);
		if (tree == NULL) /* Can't find it */
			return NULL;

		if (end == NULL || *end + 1 == '\0')
			return tree;

		ptr = end + 1;
	}
}

static int read_tree_internal(
	git3_tree_cache **out,
	const char **buffer_in,
	const char *buffer_end,
	git3_oid_t oid_type,
	git3_pool *pool)
{
	git3_tree_cache *tree = NULL;
	const char *name_start, *buffer;
	size_t oid_size = git3_oid_size(oid_type);
	int count;

	buffer = name_start = *buffer_in;

	if ((buffer = memchr(buffer, '\0', buffer_end - buffer)) == NULL)
		goto corrupted;

	if (++buffer >= buffer_end)
		goto corrupted;

	if (git3_tree_cache_new(&tree, name_start, oid_type, pool) < 0)
		return -1;

	/* Blank-terminated ASCII decimal number of entries in this tree */
	if (git3__strntol32(&count, buffer, buffer_end - buffer, &buffer, 10) < 0)
		goto corrupted;

	tree->entry_count = count;

	if (*buffer != ' ' || ++buffer >= buffer_end)
		goto corrupted;

	 /* Number of children of the tree, newline-terminated */
	if (git3__strntol32(&count, buffer, buffer_end - buffer, &buffer, 10) < 0 || count < 0)
		goto corrupted;

	tree->children_count = count;

	if (*buffer != '\n' || ++buffer > buffer_end)
		goto corrupted;

	/* The OID is only there if it's not invalidated */
	if (tree->entry_count >= 0) {
		/* 160-bit SHA-1 for this tree and it's children */
		if (buffer + oid_size > buffer_end)
			goto corrupted;

		git3_oid_from_raw(&tree->oid, (const unsigned char *)buffer, oid_type);
		buffer += oid_size;
	}

	/* Parse children: */
	if (tree->children_count > 0) {
		size_t i, bufsize;

		GIT3_ERROR_CHECK_ALLOC_MULTIPLY(&bufsize, tree->children_count, sizeof(git3_tree_cache*));

		tree->children = git3_pool_malloc(pool, bufsize);
		GIT3_ERROR_CHECK_ALLOC(tree->children);

		memset(tree->children, 0x0, bufsize);

		for (i = 0; i < tree->children_count; ++i) {
			if (read_tree_internal(&tree->children[i], &buffer, buffer_end, oid_type, pool) < 0)
				goto corrupted;
		}
	}

	*buffer_in = buffer;
	*out = tree;
	return 0;

 corrupted:
	git3_error_set(GIT3_ERROR_INDEX, "corrupted TREE extension in index");
	return -1;
}

int git3_tree_cache_read(
	git3_tree_cache **tree,
	const char *buffer,
	size_t buffer_size,
	git3_oid_t oid_type,
	git3_pool *pool)
{
	const char *buffer_end = buffer + buffer_size;

	if (read_tree_internal(tree, &buffer, buffer_end, oid_type, pool) < 0)
		return -1;

	if (buffer < buffer_end) {
		git3_error_set(GIT3_ERROR_INDEX, "corrupted TREE extension in index (unexpected trailing data)");
		return -1;
	}

	return 0;
}

static int read_tree_recursive(git3_tree_cache *cache, const git3_tree *tree, git3_pool *pool)
{
	git3_repository *repo;
	size_t i, j, nentries, ntrees, alloc_size;
	int error;

	repo = git3_tree_owner(tree);

	git3_oid_cpy(&cache->oid, git3_tree_id(tree));
	nentries = git3_tree_entrycount(tree);

	/*
	 * We make sure we know how many trees we need to allocate for
	 * so we don't have to realloc and change the pointers for the
	 * parents.
	 */
	ntrees = 0;
	for (i = 0; i < nentries; i++) {
		const git3_tree_entry *entry;

		entry = git3_tree_entry_byindex(tree, i);
		if (git3_tree_entry_filemode(entry) == GIT3_FILEMODE_TREE)
			ntrees++;
	}

	GIT3_ERROR_CHECK_ALLOC_MULTIPLY(&alloc_size, ntrees, sizeof(git3_tree_cache *));

	cache->children_count = ntrees;
	cache->children = git3_pool_mallocz(pool, alloc_size);
	GIT3_ERROR_CHECK_ALLOC(cache->children);

	j = 0;
	for (i = 0; i < nentries; i++) {
		const git3_tree_entry *entry;
		git3_tree *subtree;

		entry = git3_tree_entry_byindex(tree, i);
		if (git3_tree_entry_filemode(entry) != GIT3_FILEMODE_TREE) {
			cache->entry_count++;
			continue;
		}

		if ((error = git3_tree_cache_new(&cache->children[j], git3_tree_entry_name(entry), cache->oid_type, pool)) < 0)
			return error;

		if ((error = git3_tree_lookup(&subtree, repo, git3_tree_entry_id(entry))) < 0)
			return error;

		error = read_tree_recursive(cache->children[j], subtree, pool);
		git3_tree_free(subtree);
		cache->entry_count += cache->children[j]->entry_count;
		j++;

		if (error < 0)
			return error;
	}

	return 0;
}

int git3_tree_cache_read_tree(git3_tree_cache **out, const git3_tree *tree, git3_oid_t oid_type, git3_pool *pool)
{
	int error;
	git3_tree_cache *cache;

	if ((error = git3_tree_cache_new(&cache, "", oid_type, pool)) < 0)
		return error;

	if ((error = read_tree_recursive(cache, tree, pool)) < 0)
		return error;

	*out = cache;
	return 0;
}

int git3_tree_cache_new(git3_tree_cache **out, const char *name, git3_oid_t oid_type, git3_pool *pool)
{
	size_t name_len, alloc_size;
	git3_tree_cache *tree;

	name_len = strlen(name);

	GIT3_ERROR_CHECK_ALLOC_ADD3(&alloc_size, sizeof(git3_tree_cache), name_len, 1);

	tree = git3_pool_malloc(pool, alloc_size);
	GIT3_ERROR_CHECK_ALLOC(tree);

	memset(tree, 0x0, sizeof(git3_tree_cache));
	/* NUL-terminated tree name */
	tree->oid_type = oid_type;
	tree->namelen = name_len;
	memcpy(tree->name, name, name_len);
	tree->name[name_len] = '\0';

	*out = tree;
	return 0;
}

static void write_tree(git3_str *out, git3_tree_cache *tree)
{
	size_t i;

	git3_str_printf(out, "%s%c%"PRIdZ" %"PRIuZ"\n", tree->name, 0, tree->entry_count, tree->children_count);

	if (tree->entry_count != -1)
		git3_str_put(out, (char *)&tree->oid.id, git3_oid_size(tree->oid_type));

	for (i = 0; i < tree->children_count; i++)
		write_tree(out, tree->children[i]);
}

int git3_tree_cache_write(git3_str *out, git3_tree_cache *tree)
{
	write_tree(out, tree);

	return git3_str_oom(out) ? -1 : 0;
}
