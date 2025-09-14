/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_patch_parse_h__
#define INCLUDE_patch_parse_h__

#include "common.h"

#include "parse.h"
#include "patch.h"

typedef struct {
	git3_refcount rc;

	git3_patch_options opts;

	git3_parse_ctx parse_ctx;
} git3_patch_parse_ctx;

extern git3_patch_parse_ctx *git3_patch_parse_ctx_init(
	const char *content,
	size_t content_len,
	const git3_patch_options *opts);

extern void git3_patch_parse_ctx_free(git3_patch_parse_ctx *ctx);

/**
 * Create a patch for a single file from the contents of a patch buffer.
 *
 * @param out The patch to be created
 * @param contents The contents of a patch file
 * @param contents_len The length of the patch file
 * @param opts The git3_patch_options
 * @return 0 on success, <0 on failure.
 */
extern int git3_patch_from_buffer(
	git3_patch **out,
	const char *contents,
	size_t contents_len,
	const git3_patch_options *opts);

extern int git3_patch_parse(
	git3_patch **out,
	git3_patch_parse_ctx *ctx);

extern int git3_patch_parsed_from_diff(git3_patch **, git3_diff *, size_t);

#endif
