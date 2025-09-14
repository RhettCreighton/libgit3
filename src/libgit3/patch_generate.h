/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_patch_generate_h__
#define INCLUDE_patch_generate_h__

#include "common.h"

#include "diff.h"
#include "diff_file.h"
#include "patch.h"

enum {
	GIT3_PATCH_GENERATED_ALLOCATED = (1 << 0),
	GIT3_PATCH_GENERATED_INITIALIZED = (1 << 1),
	GIT3_PATCH_GENERATED_LOADED = (1 << 2),
	/* the two sides are different */
	GIT3_PATCH_GENERATED_DIFFABLE = (1 << 3),
	/* the difference between the two sides has been computed */
	GIT3_PATCH_GENERATED_DIFFED = (1 << 4),
	GIT3_PATCH_GENERATED_FLATTENED = (1 << 5)
};

struct git3_patch_generated {
	struct git3_patch base;

	git3_diff *diff; /* for refcount purposes, maybe NULL for blob diffs */
	size_t delta_index;
	git3_diff_file_content ofile;
	git3_diff_file_content nfile;
	uint32_t flags;
	git3_pool flattened;
};

typedef struct git3_patch_generated git3_patch_generated;

extern git3_diff_driver *git3_patch_generated_driver(git3_patch_generated *);

extern int git3_patch_generated_old_data(
	char **, long *, git3_patch_generated *);
extern int git3_patch_generated_new_data(
	char **, long *, git3_patch_generated *);
extern int git3_patch_generated_from_diff(
	git3_patch **, git3_diff *, size_t);

typedef struct git3_patch_generated_output git3_patch_generated_output;

struct git3_patch_generated_output {
	/* these callbacks are issued with the diff data */
	git3_diff_file_cb file_cb;
	git3_diff_binary_cb binary_cb;
	git3_diff_hunk_cb hunk_cb;
	git3_diff_line_cb data_cb;
	void *payload;

	/* this records the actual error in cases where it may be obscured */
	int error;

	/* this callback is used to do the diff and drive the other callbacks.
	 * see diff_xdiff.h for how to use this in practice for now.
	 */
	int (*diff_cb)(git3_patch_generated_output *output,
		git3_patch_generated *patch);
};

#endif
