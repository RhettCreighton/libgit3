/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "diff.h"

#include "common.h"
#include "buf.h"
#include "patch.h"
#include "email.h"
#include "commit.h"
#include "index.h"
#include "diff_generate.h"

#include "git3/version.h"
#include "git3/sys/email.h"

struct patch_id_args {
	git3_diff *diff;
	git3_hash_ctx ctx;
	git3_oid result;
	git3_oid_t oid_type;
	int first_file;
};

GIT3_INLINE(const char *) diff_delta__path(const git3_diff_delta *delta)
{
	const char *str = delta->old_file.path;

	if (!str ||
		delta->status == GIT3_DELTA_ADDED ||
		delta->status == GIT3_DELTA_RENAMED ||
		delta->status == GIT3_DELTA_COPIED)
		str = delta->new_file.path;

	return str;
}

int git3_diff_delta__cmp(const void *a, const void *b)
{
	const git3_diff_delta *da = a, *db = b;
	int val = strcmp(diff_delta__path(da), diff_delta__path(db));
	return val ? val : ((int)da->status - (int)db->status);
}

int git3_diff_delta__casecmp(const void *a, const void *b)
{
	const git3_diff_delta *da = a, *db = b;
	int val = strcasecmp(diff_delta__path(da), diff_delta__path(db));
	return val ? val : ((int)da->status - (int)db->status);
}

int git3_diff__entry_cmp(const void *a, const void *b)
{
	const git3_index_entry *entry_a = a;
	const git3_index_entry *entry_b = b;

	return strcmp(entry_a->path, entry_b->path);
}

int git3_diff__entry_icmp(const void *a, const void *b)
{
	const git3_index_entry *entry_a = a;
	const git3_index_entry *entry_b = b;

	return strcasecmp(entry_a->path, entry_b->path);
}

void git3_diff_free(git3_diff *diff)
{
	if (!diff)
		return;

	GIT3_REFCOUNT_DEC(diff, diff->free_fn);
}

void git3_diff_addref(git3_diff *diff)
{
	GIT3_REFCOUNT_INC(diff);
}

size_t git3_diff_num_deltas(const git3_diff *diff)
{
	GIT3_ASSERT_ARG(diff);
	return diff->deltas.length;
}

size_t git3_diff_num_deltas_of_type(const git3_diff *diff, git3_delta_t type)
{
	size_t i, count = 0;
	const git3_diff_delta *delta;

	GIT3_ASSERT_ARG(diff);

	git3_vector_foreach(&diff->deltas, i, delta) {
		count += (delta->status == type);
	}

	return count;
}

const git3_diff_delta *git3_diff_get_delta(const git3_diff *diff, size_t idx)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(diff, NULL);
	return git3_vector_get(&diff->deltas, idx);
}

int git3_diff_is_sorted_icase(const git3_diff *diff)
{
	return (diff->opts.flags & GIT3_DIFF_IGNORE_CASE) != 0;
}

int git3_diff_get_perfdata(git3_diff_perfdata *out, const git3_diff *diff)
{
	GIT3_ASSERT_ARG(out);
	GIT3_ERROR_CHECK_VERSION(out, GIT3_DIFF_PERFDATA_VERSION, "git3_diff_perfdata");
	out->stat_calls = diff->perf.stat_calls;
	out->oid_calculations = diff->perf.oid_calculations;
	return 0;
}

int git3_diff_foreach(
	git3_diff *diff,
	git3_diff_file_cb file_cb,
	git3_diff_binary_cb binary_cb,
	git3_diff_hunk_cb hunk_cb,
	git3_diff_line_cb data_cb,
	void *payload)
{
	int error = 0;
	git3_diff_delta *delta;
	size_t idx;

	GIT3_ASSERT_ARG(diff);

	git3_vector_foreach(&diff->deltas, idx, delta) {
		git3_patch *patch;

		/* check flags against patch status */
		if (git3_diff_delta__should_skip(&diff->opts, delta))
			continue;

		if ((error = git3_patch_from_diff(&patch, diff, idx)) != 0)
			break;

		error = git3_patch__invoke_callbacks(patch, file_cb, binary_cb,
						    hunk_cb, data_cb, payload);
		git3_patch_free(patch);

		if (error)
			break;
	}

	return error;
}

#ifndef GIT3_DEPRECATE_HARD

int git3_diff_format_email(
	git3_buf *out,
	git3_diff *diff,
	const git3_diff_format_email_options *opts)
{
	git3_email_create_options email_create_opts = GIT3_EMAIL_CREATE_OPTIONS_INIT;
	git3_str email = GIT3_STR_INIT;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(diff);
	GIT3_ASSERT_ARG(opts && opts->summary && opts->id && opts->author);

	GIT3_ERROR_CHECK_VERSION(opts,
		GIT3_DIFF_FORMAT_EMAIL_OPTIONS_VERSION,
		"git3_format_email_options");

	/* This is a `git3_buf` special case; subsequent calls append. */
	email.ptr = out->ptr;
	email.asize = out->reserved;
	email.size = out->size;

	out->ptr = git3_str__initstr;
	out->reserved = 0;
	out->size = 0;

	if ((opts->flags & GIT3_DIFF_FORMAT_EMAIL_EXCLUDE_SUBJECT_PATCH_MARKER) != 0)
		email_create_opts.subject_prefix = "";

	error = git3_email__append_from_diff(&email, diff, opts->patch_no,
		opts->total_patches, opts->id, opts->summary, opts->body,
		opts->author, &email_create_opts);

	if (error < 0)
		goto done;

	error = git3_buf_fromstr(out, &email);

done:
	git3_str_dispose(&email);
	return error;
}

int git3_diff_commit_as_email(
	git3_buf *out,
	git3_repository *repo,
	git3_commit *commit,
	size_t patch_no,
	size_t total_patches,
	uint32_t flags,
	const git3_diff_options *diff_opts)
{
	git3_diff *diff = NULL;
	git3_email_create_options opts = GIT3_EMAIL_CREATE_OPTIONS_INIT;
	const git3_oid *commit_id;
	const char *summary, *body;
	const git3_signature *author;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(commit);

	commit_id = git3_commit_id(commit);
	summary = git3_commit_summary(commit);
	body = git3_commit_body(commit);
	author = git3_commit_author(commit);

	if ((flags & GIT3_DIFF_FORMAT_EMAIL_EXCLUDE_SUBJECT_PATCH_MARKER) != 0)
		opts.subject_prefix = "";

	if ((error = git3_diff__commit(&diff, repo, commit, diff_opts)) < 0)
		return error;

	error = git3_email_create_from_diff(out, diff, patch_no, total_patches, commit_id, summary, body, author, &opts);

	git3_diff_free(diff);
	return error;
}

int git3_diff_init_options(git3_diff_options *opts, unsigned int version)
{
	return git3_diff_options_init(opts, version);
}

int git3_diff_find_init_options(
	git3_diff_find_options *opts, unsigned int version)
{
	return git3_diff_find_options_init(opts, version);
}

int git3_diff_format_email_options_init(
	git3_diff_format_email_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_diff_format_email_options,
		GIT3_DIFF_FORMAT_EMAIL_OPTIONS_INIT);
	return 0;
}

int git3_diff_format_email_init_options(
	git3_diff_format_email_options *opts, unsigned int version)
{
	return git3_diff_format_email_options_init(opts, version);
}

#endif

int git3_diff_options_init(git3_diff_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_diff_options, GIT3_DIFF_OPTIONS_INIT);
	return 0;
}

int git3_diff_find_options_init(
	git3_diff_find_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_diff_find_options, GIT3_DIFF_FIND_OPTIONS_INIT);
	return 0;
}

static int flush_hunk(git3_oid *result, struct patch_id_args *args)
{
	git3_hash_ctx *ctx = &args->ctx;
	git3_oid hash;
	unsigned short carry = 0;
	size_t i;
	int error;

	if ((error = git3_hash_final(hash.id, ctx)) < 0 ||
	    (error = git3_hash_init(ctx)) < 0)
		return error;

	for (i = 0; i < git3_oid_size(args->oid_type); i++) {
		carry += result->id[i] + hash.id[i];
		result->id[i] = (unsigned char)carry;
		carry >>= 8;
	}

	return 0;
}

static void strip_spaces(git3_str *buf)
{
	char *src = buf->ptr, *dst = buf->ptr;
	char c;
	size_t len = 0;

	while ((c = *src++) != '\0') {
		if (!git3__isspace(c)) {
			*dst++ = c;
			len++;
		}
	}

	git3_str_truncate(buf, len);
}

static int diff_patchid_print_callback_to_buf(
	const git3_diff_delta *delta,
	const git3_diff_hunk *hunk,
	const git3_diff_line *line,
	void *payload)
{
	struct patch_id_args *args = (struct patch_id_args *) payload;
	git3_str buf = GIT3_STR_INIT;
	int error = 0;

	if (line->origin == GIT3_DIFF_LINE_CONTEXT_EOFNL ||
	    line->origin == GIT3_DIFF_LINE_ADD_EOFNL ||
	    line->origin == GIT3_DIFF_LINE_DEL_EOFNL)
		goto out;

	if ((error = git3_diff_print_callback__to_buf(delta, hunk,
						     line, &buf)) < 0)
		goto out;

	strip_spaces(&buf);

	if (line->origin == GIT3_DIFF_LINE_FILE_HDR &&
	    !args->first_file &&
	    (error = flush_hunk(&args->result, args) < 0))
			goto out;

	if ((error = git3_hash_update(&args->ctx, buf.ptr, buf.size)) < 0)
		goto out;

	if (line->origin == GIT3_DIFF_LINE_FILE_HDR && args->first_file)
		args->first_file = 0;

out:
	git3_str_dispose(&buf);
	return error;
}

int git3_diff_patchid_options_init(git3_diff_patchid_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_diff_patchid_options, GIT3_DIFF_PATCHID_OPTIONS_INIT);
	return 0;
}

int git3_diff_patchid(git3_oid *out, git3_diff *diff, git3_diff_patchid_options *opts)
{
	struct patch_id_args args;
	git3_hash_algorithm_t algorithm;
	int error;

	GIT3_ERROR_CHECK_VERSION(
		opts, GIT3_DIFF_PATCHID_OPTIONS_VERSION, "git3_diff_patchid_options");

	algorithm = git3_oid_algorithm(diff->opts.oid_type);

	memset(&args, 0, sizeof(args));
	args.diff = diff;
	args.first_file = 1;
	args.oid_type = diff->opts.oid_type;
	if ((error = git3_hash_ctx_init(&args.ctx, algorithm)) < 0)
		goto out;

	if ((error = git3_diff_print(diff,
				    GIT3_DIFF_FORMAT_PATCH_ID,
				    diff_patchid_print_callback_to_buf,
				    &args)) < 0)
		goto out;

	if ((error = (flush_hunk(&args.result, &args))) < 0)
		goto out;

#ifdef GIT3_EXPERIMENTAL_SHA256
	args.result.type = diff->opts.oid_type;
#endif

	git3_oid_cpy(out, &args.result);

out:
	git3_hash_ctx_cleanup(&args.ctx);
	return error;
}
