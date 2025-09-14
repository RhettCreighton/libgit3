/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "diff_parse.h"

#include "diff.h"
#include "patch.h"
#include "patch_parse.h"

static void diff_parsed_free(git3_diff *d)
{
	git3_diff_parsed *diff = (git3_diff_parsed *)d;
	git3_patch *patch;
	size_t i;

	git3_vector_foreach(&diff->patches, i, patch)
		git3_patch_free(patch);

	git3_vector_dispose(&diff->patches);

	git3_vector_dispose(&diff->base.deltas);
	git3_pool_clear(&diff->base.pool);

	git3__memzero(diff, sizeof(*diff));
	git3__free(diff);
}

static git3_diff_parsed *diff_parsed_alloc(git3_oid_t oid_type)
{
	git3_diff_parsed *diff;

	if ((diff = git3__calloc(1, sizeof(git3_diff_parsed))) == NULL)
		return NULL;

	GIT3_REFCOUNT_INC(&diff->base);
	diff->base.type = GIT3_DIFF_TYPE_PARSED;
	diff->base.strcomp = git3__strcmp;
	diff->base.strncomp = git3__strncmp;
	diff->base.pfxcomp = git3__prefixcmp;
	diff->base.entrycomp = git3_diff__entry_cmp;
	diff->base.patch_fn = git3_patch_parsed_from_diff;
	diff->base.free_fn = diff_parsed_free;

	if (git3_diff_options_init(&diff->base.opts, GIT3_DIFF_OPTIONS_VERSION) < 0) {
		git3__free(diff);
		return NULL;
	}

	diff->base.opts.flags &= ~GIT3_DIFF_IGNORE_CASE;
	diff->base.opts.oid_type = oid_type;

	if (git3_pool_init(&diff->base.pool, 1) < 0 ||
	    git3_vector_init(&diff->patches, 0, NULL) < 0 ||
		git3_vector_init(&diff->base.deltas, 0, git3_diff_delta__cmp) < 0) {
		git3_diff_free(&diff->base);
		return NULL;
	}

	git3_vector_set_cmp(&diff->base.deltas, git3_diff_delta__cmp);

	return diff;
}

int git3_diff_from_buffer(
	git3_diff **out,
	const char *content,
	size_t content_len)
{
	return git3_diff_from_buffer_ext(out, content, content_len, NULL);
}

int git3_diff_from_buffer_ext(
	git3_diff **out,
	const char *content,
	size_t content_len,
	git3_diff_parse_options *opts)
{
	git3_diff_parsed *diff;
	git3_patch *patch;
	git3_patch_parse_ctx *ctx = NULL;
	git3_patch_options patch_opts = GIT3_PATCH_OPTIONS_INIT;
	git3_oid_t oid_type;
	int error = 0;

	*out = NULL;

	oid_type = (opts && opts->oid_type) ? opts->oid_type :
		GIT3_OID_DEFAULT;

	patch_opts.oid_type = oid_type;

	diff = diff_parsed_alloc(oid_type);
	GIT3_ERROR_CHECK_ALLOC(diff);

	ctx = git3_patch_parse_ctx_init(content, content_len, &patch_opts);
	GIT3_ERROR_CHECK_ALLOC(ctx);

	while (ctx->parse_ctx.remain_len) {
		if ((error = git3_patch_parse(&patch, ctx)) < 0)
			break;

		git3_vector_insert(&diff->patches, patch);
		git3_vector_insert(&diff->base.deltas, patch->delta);
	}

	if (error == GIT3_ENOTFOUND && git3_vector_length(&diff->patches) > 0) {
		git3_error_clear();
		error = 0;
	}

	git3_patch_parse_ctx_free(ctx);

	if (error < 0)
		git3_diff_free(&diff->base);
	else
		*out = &diff->base;

	return error;
}

