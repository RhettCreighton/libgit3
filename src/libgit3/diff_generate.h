/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_diff_generate_h__
#define INCLUDE_diff_generate_h__

#include "common.h"

#include "diff.h"
#include "pool.h"
#include "index.h"

enum {
	GIT3_DIFFCAPS_HAS_SYMLINKS     = (1 << 0), /* symlinks on platform? */
	GIT3_DIFFCAPS_IGNORE_STAT      = (1 << 1), /* use stat? */
	GIT3_DIFFCAPS_TRUST_MODE_BITS  = (1 << 2), /* use st_mode? */
	GIT3_DIFFCAPS_TRUST_CTIME      = (1 << 3), /* use st_ctime? */
	GIT3_DIFFCAPS_USE_DEV          = (1 << 4)  /* use st_dev? */
};

#define DIFF_FLAGS_KNOWN_BINARY (GIT3_DIFF_FLAG_BINARY|GIT3_DIFF_FLAG_NOT_BINARY)
#define DIFF_FLAGS_NOT_BINARY   (GIT3_DIFF_FLAG_NOT_BINARY|GIT3_DIFF_FLAG__NO_DATA)

enum {
	GIT3_DIFF_FLAG__FREE_PATH  = (1 << 7),  /* `path` is allocated memory */
	GIT3_DIFF_FLAG__FREE_DATA  = (1 << 8),  /* internal file data is allocated */
	GIT3_DIFF_FLAG__UNMAP_DATA = (1 << 9),  /* internal file data is mmap'ed */
	GIT3_DIFF_FLAG__NO_DATA    = (1 << 10), /* file data should not be loaded */
	GIT3_DIFF_FLAG__FREE_BLOB  = (1 << 11), /* release the blob when done */
	GIT3_DIFF_FLAG__LOADED     = (1 << 12), /* file data has been loaded */

	GIT3_DIFF_FLAG__TO_DELETE  = (1 << 16), /* delete entry during rename det. */
	GIT3_DIFF_FLAG__TO_SPLIT   = (1 << 17), /* split entry during rename det. */
	GIT3_DIFF_FLAG__IS_RENAME_TARGET = (1 << 18),
	GIT3_DIFF_FLAG__IS_RENAME_SOURCE = (1 << 19),
	GIT3_DIFF_FLAG__HAS_SELF_SIMILARITY = (1 << 20)
};

#define GIT3_DIFF_FLAG__CLEAR_INTERNAL(F) (F) = ((F) & 0x00FFFF)

#define GIT3_DIFF__VERBOSE  (1 << 30)

extern void git3_diff_addref(git3_diff *diff);

extern bool git3_diff_delta__should_skip(
	const git3_diff_options *opts, const git3_diff_delta *delta);

extern int git3_diff__from_iterators(
	git3_diff **diff_ptr,
	git3_repository *repo,
	git3_iterator *old_iter,
	git3_iterator *new_iter,
	const git3_diff_options *opts);

extern int git3_diff__commit(
	git3_diff **diff, git3_repository *repo, const git3_commit *commit, const git3_diff_options *opts);

extern int git3_diff__paired_foreach(
	git3_diff *idx2head,
	git3_diff *wd2idx,
	int (*cb)(git3_diff_delta *i2h, git3_diff_delta *w2i, void *payload),
	void *payload);

/* Merge two `git3_diff`s according to the callback given by `cb`. */

typedef git3_diff_delta *(*git3_diff__merge_cb)(
	const git3_diff_delta *left,
	const git3_diff_delta *right,
	git3_pool *pool);

extern int git3_diff__merge(
	git3_diff *onto, const git3_diff *from, git3_diff__merge_cb cb);

extern git3_diff_delta *git3_diff__merge_like_cgit(
	const git3_diff_delta *a,
	const git3_diff_delta *b,
	git3_pool *pool);

/* Duplicate a `git3_diff_delta` out of the `git3_pool` */
extern git3_diff_delta *git3_diff__delta_dup(
	const git3_diff_delta *d, git3_pool *pool);

extern int git3_diff__oid_for_file(
	git3_oid *out,
	git3_diff *diff,
	const char *path,
	uint16_t mode,
	git3_object_size_t size);

extern int git3_diff__oid_for_entry(
	git3_oid *out,
	git3_diff *diff,
	const git3_index_entry *src,
	uint16_t mode,
	const git3_oid *update_match);

/*
 * Sometimes a git3_diff_file will have a zero size; this attempts to
 * fill in the size without loading the blob if possible.  If that is
 * not possible, then it will return the git3_odb_object that had to be
 * loaded and the caller can use it or dispose of it as needed.
 */
GIT3_INLINE(int) git3_diff_file__resolve_zero_size(
	git3_diff_file *file, git3_odb_object **odb_obj, git3_repository *repo)
{
	int error;
	git3_odb *odb;
	size_t len;
	git3_object_t type;

	if ((error = git3_repository_odb(&odb, repo)) < 0)
		return error;

	error = git3_odb__read_header_or_object(
		odb_obj, &len, &type, odb, &file->id);

	git3_odb_free(odb);

	if (!error) {
		file->size = (git3_object_size_t)len;
		file->flags |= GIT3_DIFF_FLAG_VALID_SIZE;
	}

	return error;
}

#endif
