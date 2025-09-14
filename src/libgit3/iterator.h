/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_iterator_h__
#define INCLUDE_iterator_h__

#include "common.h"

#include "git3/index.h"
#include "vector.h"
#include "str.h"
#include "ignore.h"

typedef struct git3_iterator git3_iterator;

typedef enum {
	GIT3_ITERATOR_EMPTY = 0,
	GIT3_ITERATOR_TREE = 1,
	GIT3_ITERATOR_INDEX = 2,
	GIT3_ITERATOR_WORKDIR = 3,
	GIT3_ITERATOR_FS = 4
} git3_iterator_t;

typedef enum {
	/** ignore case for entry sort order */
	GIT3_ITERATOR_IGNORE_CASE = (1u << 0),
	/** force case sensitivity for entry sort order */
	GIT3_ITERATOR_DONT_IGNORE_CASE = (1u << 1),
	/** return tree items in addition to blob items */
	GIT3_ITERATOR_INCLUDE_TREES    = (1u << 2),
	/** don't flatten trees, requiring advance_into (implies INCLUDE_TREES) */
	GIT3_ITERATOR_DONT_AUTOEXPAND  = (1u << 3),
	/** convert precomposed unicode to decomposed unicode */
	GIT3_ITERATOR_PRECOMPOSE_UNICODE = (1u << 4),
	/** never convert precomposed unicode to decomposed unicode */
	GIT3_ITERATOR_DONT_PRECOMPOSE_UNICODE = (1u << 5),
	/** include conflicts */
	GIT3_ITERATOR_INCLUDE_CONFLICTS = (1u << 6),
	/** descend into symlinked directories */
	GIT3_ITERATOR_DESCEND_SYMLINKS = (1u << 7),
	/** hash files in workdir or filesystem iterators */
	GIT3_ITERATOR_INCLUDE_HASH = (1u << 8)
} git3_iterator_flag_t;

typedef enum {
	GIT3_ITERATOR_STATUS_NORMAL = 0,
	GIT3_ITERATOR_STATUS_IGNORED = 1,
	GIT3_ITERATOR_STATUS_EMPTY = 2,
	GIT3_ITERATOR_STATUS_FILTERED = 3
} git3_iterator_status_t;

typedef struct {
	const char *start;
	const char *end;

	/* paths to include in the iterator (literal).  if set, any paths not
	 * listed here will be excluded from iteration.
	 */
	git3_strarray pathlist;

	/* flags, from above */
	unsigned int flags;

	/* oid type - necessary for non-workdir filesystem iterators */
	git3_oid_t oid_type;
} git3_iterator_options;

#define GIT3_ITERATOR_OPTIONS_INIT {0}

typedef struct {
	int (*current)(const git3_index_entry **, git3_iterator *);
	int (*advance)(const git3_index_entry **, git3_iterator *);
	int (*advance_into)(const git3_index_entry **, git3_iterator *);
	int (*advance_over)(
		const git3_index_entry **, git3_iterator_status_t *, git3_iterator *);
	int (*reset)(git3_iterator *);
	void (*free)(git3_iterator *);
} git3_iterator_callbacks;

struct git3_iterator {
	git3_iterator_t type;
	git3_iterator_callbacks *cb;

	git3_repository *repo;
	git3_index *index;

	char *start;
	size_t start_len;

	char *end;
	size_t end_len;

	bool started;
	bool ended;
	git3_vector pathlist;
	size_t pathlist_walk_idx;
	int (*strcomp)(const char *a, const char *b);
	int (*strncomp)(const char *a, const char *b, size_t n);
	int (*prefixcomp)(const char *str, const char *prefix);
	int (*entry_srch)(const void *key, const void *array_member);
	size_t stat_calls;
	unsigned int flags;
};

extern int git3_iterator_for_nothing(
	git3_iterator **out,
	git3_iterator_options *options);

/* tree iterators will match the ignore_case value from the index of the
 * repository, unless you override with a non-zero flag value
 */
extern int git3_iterator_for_tree(
	git3_iterator **out,
	git3_tree *tree,
	git3_iterator_options *options);

/* index iterators will take the ignore_case value from the index; the
 * ignore_case flags are not used
 */
extern int git3_iterator_for_index(
	git3_iterator **out,
	git3_repository *repo,
	git3_index *index,
	git3_iterator_options *options);

extern int git3_iterator_for_workdir_ext(
	git3_iterator **out,
	git3_repository *repo,
	const char *repo_workdir,
	git3_index *index,
	git3_tree *tree,
	git3_iterator_options *options);

/* workdir iterators will match the ignore_case value from the index of the
 * repository, unless you override with a non-zero flag value
 */
GIT3_INLINE(int) git3_iterator_for_workdir(
	git3_iterator **out,
	git3_repository *repo,
	git3_index *index,
	git3_tree *tree,
	git3_iterator_options *options)
{
	return git3_iterator_for_workdir_ext(out, repo, NULL, index, tree, options);
}

/* for filesystem iterators, you have to explicitly pass in the ignore_case
 * behavior that you desire
 */
extern int git3_iterator_for_filesystem(
	git3_iterator **out,
	const char *root,
	git3_iterator_options *options);

extern void git3_iterator_free(git3_iterator *iter);

/* Return a git3_index_entry structure for the current value the iterator
 * is looking at or NULL if the iterator is at the end.
 *
 * The entry may noy be fully populated.  Tree iterators will only have a
 * value mode, OID, and path.  Workdir iterators will not have an OID (but
 * you can use `git3_iterator_current_oid()` to calculate it on demand).
 *
 * You do not need to free the entry.  It is still "owned" by the iterator.
 * Once you call `git3_iterator_advance()` then the old entry is no longer
 * guaranteed to be valid - it may be freed or just overwritten in place.
 */
GIT3_INLINE(int) git3_iterator_current(
	const git3_index_entry **entry, git3_iterator *iter)
{
	return iter->cb->current(entry, iter);
}

/**
 * Advance to the next item for the iterator.
 *
 * If GIT3_ITERATOR_INCLUDE_TREES is set, this may be a tree item.  If
 * GIT3_ITERATOR_DONT_AUTOEXPAND is set, calling this again when on a tree
 * item will skip over all the items under that tree.
 */
GIT3_INLINE(int) git3_iterator_advance(
	const git3_index_entry **entry, git3_iterator *iter)
{
	return iter->cb->advance(entry, iter);
}

/**
 * Iterate into a tree item (when GIT3_ITERATOR_DONT_AUTOEXPAND is set).
 *
 * git3_iterator_advance() steps through all items being iterated over
 * (either with or without trees, depending on GIT3_ITERATOR_INCLUDE_TREES),
 * but if GIT3_ITERATOR_DONT_AUTOEXPAND is set, it will skip to the next
 * sibling of a tree instead of going to the first child of the tree.  In
 * that case, use this function to advance to the first child of the tree.
 *
 * If the current item is not a tree, this is a no-op.
 *
 * For filesystem and working directory iterators, a tree (i.e. directory)
 * can be empty.  In that case, this function returns GIT3_ENOTFOUND and
 * does not advance.  That can't happen for tree and index iterators.
 */
GIT3_INLINE(int) git3_iterator_advance_into(
	const git3_index_entry **entry, git3_iterator *iter)
{
	return iter->cb->advance_into(entry, iter);
}

/* Advance over a directory and check if it contains no files or just
 * ignored files.
 *
 * In a tree or the index, all directories will contain files, but in the
 * working directory it is possible to have an empty directory tree or a
 * tree that only contains ignored files.  Many Git operations treat these
 * cases specially.  This advances over a directory (presumably an
 * untracked directory) but checks during the scan if there are any files
 * and any non-ignored files.
 */
GIT3_INLINE(int) git3_iterator_advance_over(
	const git3_index_entry **entry,
	git3_iterator_status_t *status,
	git3_iterator *iter)
{
	return iter->cb->advance_over(entry, status, iter);
}

/**
 * Go back to the start of the iteration.
 */
GIT3_INLINE(int) git3_iterator_reset(git3_iterator *iter)
{
	return iter->cb->reset(iter);
}

/**
 * Go back to the start of the iteration after updating the `start` and
 * `end` pathname boundaries of the iteration.
 */
extern int git3_iterator_reset_range(
	git3_iterator *iter, const char *start, const char *end);

GIT3_INLINE(git3_iterator_t) git3_iterator_type(git3_iterator *iter)
{
	return iter->type;
}

GIT3_INLINE(git3_repository *) git3_iterator_owner(git3_iterator *iter)
{
	return iter->repo;
}

GIT3_INLINE(git3_index *) git3_iterator_index(git3_iterator *iter)
{
	return iter->index;
}

GIT3_INLINE(git3_iterator_flag_t) git3_iterator_flags(git3_iterator *iter)
{
	return iter->flags;
}

GIT3_INLINE(bool) git3_iterator_ignore_case(git3_iterator *iter)
{
	return ((iter->flags & GIT3_ITERATOR_IGNORE_CASE) != 0);
}

extern int git3_iterator_set_ignore_case(
	git3_iterator *iter, bool ignore_case);

extern int git3_iterator_current_tree_entry(
	const git3_tree_entry **entry_out, git3_iterator *iter);

extern int git3_iterator_current_parent_tree(
	const git3_tree **tree_out, git3_iterator *iter, size_t depth);

extern bool git3_iterator_current_is_ignored(git3_iterator *iter);

extern bool git3_iterator_current_tree_is_ignored(git3_iterator *iter);

/**
 * Get full path of the current item from a workdir iterator.  This will
 * return NULL for a non-workdir iterator.  The git3_str is still owned by
 * the iterator; this is exposed just for efficiency.
 */
extern int git3_iterator_current_workdir_path(
	git3_str **path, git3_iterator *iter);

/**
 * Retrieve the index stored in the iterator.
 *
 * Only implemented for the workdir and index iterators.
 */
extern git3_index *git3_iterator_index(git3_iterator *iter);

typedef int (*git3_iterator_foreach_cb)(
	const git3_index_entry *entry,
	void *data);

/**
 * Walk the given iterator and invoke the callback for each path
 * contained in the iterator.
 */
extern int git3_iterator_foreach(
	git3_iterator *iterator,
	git3_iterator_foreach_cb cb,
	void *data);

typedef int (*git3_iterator_walk_cb)(
	const git3_index_entry **entries,
	void *data);

/**
 * Walk the given iterators in lock-step.  The given callback will be
 * called for each unique path, with the index entry in each iterator
 * (or NULL if the given iterator does not contain that path).
 */
extern int git3_iterator_walk(
	git3_iterator **iterators,
	size_t cnt,
	git3_iterator_walk_cb cb,
	void *data);

#endif
