/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_index_h__
#define INCLUDE_index_h__

#include "common.h"

#include "futils.h"
#include "filebuf.h"
#include "vector.h"
#include "tree-cache.h"
#include "index_map.h"
#include "git3/odb.h"
#include "git3/index.h"

#define GIT3_INDEX_FILE "index"
#define GIT3_INDEX_FILE_MODE 0666

/* Helper to create index options based on repository options */
#define GIT3_INDEX_OPTIONS_FOR_REPO(r) \
	{ GIT3_INDEX_OPTIONS_VERSION, r ? r->oid_type : 0 }

extern bool git3_index__enforce_unsaved_safety;

struct git3_index {
	git3_refcount rc;

	char *index_file_path;
	git3_futils_filestamp stamp;
	unsigned char checksum[GIT3_HASH_MAX_SIZE];

	git3_vector entries;
	git3_index_entrymap entries_map;

	git3_vector deleted; /* deleted entries if readers > 0 */
	git3_atomic32 readers; /* number of active iterators */

	git3_oid_t oid_type;

	unsigned int on_disk:1;
	unsigned int ignore_case:1;
	unsigned int distrust_filemode:1;
	unsigned int no_symlinks:1;
	unsigned int dirty:1;	/* whether we have unsaved changes */

	git3_tree_cache *tree;
	git3_pool tree_pool;

	git3_vector names;
	git3_vector reuc;

	git3_vector_cmp entries_cmp_path;
	git3_vector_cmp entries_search;
	git3_vector_cmp entries_search_path;
	git3_vector_cmp reuc_search;

	unsigned int version;
};

struct git3_index_iterator {
	git3_index *index;
	git3_vector snap;
	size_t cur;
};

struct git3_index_conflict_iterator {
	git3_index *index;
	size_t cur;
};

extern void git3_index_entry__init_from_stat(
	git3_index_entry *entry, struct stat *st, bool trust_mode);

/* Index entry comparison functions for array sorting */
extern int git3_index_entry_cmp(const void *a, const void *b);
extern int git3_index_entry_icmp(const void *a, const void *b);

/* Index entry search functions for search using a search spec */
extern int git3_index_entry_srch(const void *a, const void *b);
extern int git3_index_entry_isrch(const void *a, const void *b);

/* Index time handling functions */
GIT3_INLINE(bool) git3_index_time_eq(const git3_index_time *one, const git3_index_time *two)
{
	if (one->seconds != two->seconds)
		return false;

#ifdef GIT3_NSEC
	if (one->nanoseconds != two->nanoseconds)
		return false;
#endif

	return true;
}

/*
 * Test if the given index time is newer than the given existing index entry.
 * If the timestamps are exactly equivalent, then the given index time is
 * considered "racily newer" than the existing index entry.
 */
GIT3_INLINE(bool) git3_index_entry_newer_than_index(
	const git3_index_entry *entry, git3_index *index)
{
	/* If we never read the index, we can't have this race either */
	if (!index || index->stamp.mtime.tv_sec == 0)
		return false;

	/* If the timestamp is the same or newer than the index, it's racy */
#if defined(GIT3_NSEC)
	if ((int32_t)index->stamp.mtime.tv_sec < entry->mtime.seconds)
		return true;
	else if ((int32_t)index->stamp.mtime.tv_sec > entry->mtime.seconds)
		return false;
	else
		return (uint32_t)index->stamp.mtime.tv_nsec <= entry->mtime.nanoseconds;
#else
	return ((int32_t)index->stamp.mtime.tv_sec) <= entry->mtime.seconds;
#endif
}

/* Search index for `path`, returning GIT3_ENOTFOUND if it does not exist
 * (but not setting an error message).
 *
 * `at_pos` is set to the position where it is or would be inserted.
 * Pass `path_len` as strlen of path or 0 to call strlen internally.
 */
extern int git3_index__find_pos(
	size_t *at_pos, git3_index *index, const char *path, size_t path_len, int stage);

extern int git3_index__fill(git3_index *index, const git3_vector *source_entries);

extern void git3_index__set_ignore_case(git3_index *index, bool ignore_case);

extern unsigned int git3_index__create_mode(unsigned int mode);

GIT3_INLINE(const git3_futils_filestamp *) git3_index__filestamp(git3_index *index)
{
	return &index->stamp;
}

GIT3_INLINE(unsigned char *) git3_index__checksum(git3_index *index)
{
	return index->checksum;
}

/* Copy the current entries vector *and* increment the index refcount.
 * Call `git3_index__release_snapshot` when done.
 */
extern int git3_index_snapshot_new(git3_vector *snap, git3_index *index);
extern void git3_index_snapshot_release(git3_vector *snap, git3_index *index);

/* Allow searching in a snapshot; entries must already be sorted! */
extern int git3_index_snapshot_find(
	size_t *at_pos, git3_vector *snap, git3_vector_cmp entry_srch,
	const char *path, size_t path_len, int stage);

/* Replace an index with a new index */
int git3_index_read_index(git3_index *index, const git3_index *new_index);

GIT3_INLINE(int) git3_index_is_dirty(git3_index *index)
{
	return index->dirty;
}

extern int git3_index_read_safely(git3_index *index);

typedef struct {
	git3_index *index;
	git3_filebuf file;
	unsigned int should_write:1;
} git3_indexwriter;

#define GIT3_INDEXWRITER_INIT { NULL, GIT3_FILEBUF_INIT }

/* Lock the index for eventual writing. */
extern int git3_indexwriter_init(git3_indexwriter *writer, git3_index *index);

/* Lock the index for eventual writing by a repository operation: a merge,
 * revert, cherry-pick or a rebase.  Note that the given checkout strategy
 * will be updated for the operation's use so that checkout will not write
 * the index.
 */
extern int git3_indexwriter_init_for_operation(
	git3_indexwriter *writer,
	git3_repository *repo,
	unsigned int *checkout_strategy);

/* Write the index and unlock it. */
extern int git3_indexwriter_commit(git3_indexwriter *writer);

/* Cleanup an index writing session, unlocking the file (if it is still
 * locked and freeing any data structures.
 */
extern void git3_indexwriter_cleanup(git3_indexwriter *writer);

/* SHA256 support */

#ifndef GIT3_EXPERIMENTAL_SHA256

int git3_index_open_ext(
	git3_index **index_out,
	const char *index_path,
	const git3_index_options *opts);

GIT3_EXTERN(int) git3_index_new_ext(
	git3_index **index_out,
	const git3_index_options *opts);

#endif

#endif
