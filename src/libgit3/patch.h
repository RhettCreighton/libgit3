/*
* Copyright (C) the libgit3 contributors. All rights reserved.
*
* This file is part of libgit3, distributed under the GNU GPL v2 with
* a Linking Exception. For full terms see the included COPYING file.
*/
#ifndef INCLUDE_patch_h__
#define INCLUDE_patch_h__

#include "common.h"

#include "git3/patch.h"
#include "array.h"

/* cached information about a hunk in a patch */
typedef struct git3_patch_hunk {
	git3_diff_hunk hunk;
	size_t line_start;
	size_t line_count;
} git3_patch_hunk;

struct git3_patch {
	git3_refcount rc;

	git3_repository *repo; /* may be null */

	git3_diff_options diff_opts;

	git3_diff_delta *delta;
	git3_diff_binary binary;
	git3_array_t(git3_patch_hunk) hunks;
	git3_array_t(git3_diff_line) lines;

	size_t header_size;
	size_t content_size;
	size_t context_size;

	void (*free_fn)(git3_patch *patch);
};

extern int git3_patch__invoke_callbacks(
	git3_patch *patch,
	git3_diff_file_cb file_cb,
	git3_diff_binary_cb binary_cb,
	git3_diff_hunk_cb hunk_cb,
	git3_diff_line_cb line_cb,
	void *payload);

extern int git3_patch_line_stats(
	size_t *total_ctxt,
	size_t *total_adds,
	size_t *total_dels,
	const git3_patch *patch);

/** Options for parsing patch files. */
typedef struct {
	/**
	 * The length of the prefix (in path segments) for the filenames.
	 * This prefix will be removed when looking for files.  The default is 1.
	 */
	uint32_t prefix_len;

	/**
	 * The type of object IDs in the patch file. The default is
	 * `GIT3_OID_DEFAULT`.
	 */
	git3_oid_t oid_type;
} git3_patch_options;

#define GIT3_PATCH_OPTIONS_INIT { 1, GIT3_OID_DEFAULT }

extern int git3_patch__to_buf(git3_str *out, git3_patch *patch);
extern void git3_patch_free(git3_patch *patch);

#endif
