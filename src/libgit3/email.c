/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "email.h"

#include "common.h"
#include "buf.h"
#include "diff_generate.h"
#include "diff_stats.h"
#include "patch.h"
#include "date.h"

#include "git3/email.h"
#include "git3/patch.h"
#include "git3/sys/email.h"
#include "git3/version.h"

/*
 * Git uses a "magic" timestamp to indicate that an email message
 * is from `git format-patch` (or our equivalent).
 */
#define EMAIL_TIMESTAMP "Mon Sep 17 00:00:00 2001"

GIT3_INLINE(int) include_prefix(
	size_t patch_count,
	git3_email_create_options *opts)
{
	return ((!opts->subject_prefix || *opts->subject_prefix) ||
	        (opts->flags & GIT3_EMAIL_CREATE_ALWAYS_NUMBER) != 0 ||
	        opts->reroll_number ||
		(patch_count > 1 && !(opts->flags & GIT3_EMAIL_CREATE_OMIT_NUMBERS)));
}

static int append_prefix(
	git3_str *out,
	size_t patch_idx,
	size_t patch_count,
	git3_email_create_options *opts)
{
	const char *subject_prefix = opts->subject_prefix ?
		opts->subject_prefix : "PATCH";

	git3_str_putc(out, '[');

	if (*subject_prefix)
		git3_str_puts(out, subject_prefix);

	if (opts->reroll_number) {
		if (*subject_prefix)
			git3_str_putc(out, ' ');

		git3_str_printf(out, "v%" PRIuZ, opts->reroll_number);
	}

	if ((opts->flags & GIT3_EMAIL_CREATE_ALWAYS_NUMBER) != 0 ||
	    (patch_count > 1 && !(opts->flags & GIT3_EMAIL_CREATE_OMIT_NUMBERS))) {
		size_t start_number = opts->start_number ?
			opts->start_number : 1;

		if (*subject_prefix || opts->reroll_number)
			git3_str_putc(out, ' ');

		git3_str_printf(out, "%" PRIuZ "/%" PRIuZ,
		               patch_idx + (start_number - 1),
		               patch_count + (start_number - 1));
	}

	git3_str_puts(out, "]");

	return git3_str_oom(out) ? -1 : 0;
}

static int append_date(
	git3_str *out,
	const git3_time *date)
{
	int error;

	if ((error = git3_str_printf(out, "Date: ")) == 0 &&
	    (error = git3_date_rfc2822_fmt(out, date->time, date->offset)) == 0)
	    error = git3_str_putc(out, '\n');

	return error;
}

static int append_subject(
	git3_str *out,
	size_t patch_idx,
	size_t patch_count,
	const char *summary,
	git3_email_create_options *opts)
{
	bool prefix = include_prefix(patch_count, opts);
	size_t summary_len = summary ? strlen(summary) : 0;
	int error;

	if (summary_len) {
		const char *nl = strchr(summary, '\n');

		if (nl)
			summary_len = (nl - summary);
	}

	if ((error = git3_str_puts(out, "Subject: ")) < 0)
		return error;

	if (prefix &&
	    (error = append_prefix(out, patch_idx, patch_count, opts)) < 0)
		return error;

	if (prefix && summary_len && (error = git3_str_putc(out, ' ')) < 0)
		return error;

	if (summary_len &&
	    (error = git3_str_put(out, summary, summary_len)) < 0)
		return error;

	return git3_str_putc(out, '\n');
}

static int append_header(
	git3_str *out,
	size_t patch_idx,
	size_t patch_count,
	const git3_oid *commit_id,
	const char *summary,
	const git3_signature *author,
	git3_email_create_options *opts)
{
	char id[GIT3_OID_MAX_HEXSIZE + 1];
	int error;

	git3_oid_tostr(id, GIT3_OID_MAX_HEXSIZE + 1, commit_id);

	if ((error = git3_str_printf(out, "From %s %s\n", id, EMAIL_TIMESTAMP)) < 0 ||
	    (error = git3_str_printf(out, "From: %s <%s>\n", author->name, author->email)) < 0 ||
	    (error = append_date(out, &author->when)) < 0 ||
	    (error = append_subject(out, patch_idx, patch_count, summary, opts)) < 0)
		return error;

	if ((error = git3_str_putc(out, '\n')) < 0)
		return error;

	return 0;
}

static int append_body(git3_str *out, const char *body)
{
	size_t body_len;
	int error;

	if (!body)
		return 0;

	body_len = strlen(body);

	if ((error = git3_str_puts(out, body)) < 0)
		return error;

	if (body_len && body[body_len - 1] != '\n')
		error = git3_str_putc(out, '\n');

	return error;
}

static int append_diffstat(git3_str *out, git3_diff *diff)
{
	git3_diff_stats *stats = NULL;
	unsigned int format_flags;
	int error;

	format_flags = GIT3_DIFF_STATS_FULL | GIT3_DIFF_STATS_INCLUDE_SUMMARY;

	if ((error = git3_diff_get_stats(&stats, diff)) == 0 &&
	    (error = git3_diff__stats_to_buf(out, stats, format_flags, 0)) == 0)
		error = git3_str_putc(out, '\n');

	git3_diff_stats_free(stats);
	return error;
}

static int append_patches(git3_str *out, git3_diff *diff)
{
	size_t i, deltas;
	int error = 0;

	deltas = git3_diff_num_deltas(diff);

	for (i = 0; i < deltas; ++i) {
		git3_patch *patch = NULL;

		if ((error = git3_patch_from_diff(&patch, diff, i)) >= 0)
			error = git3_patch__to_buf(out, patch);

		git3_patch_free(patch);

		if (error < 0)
			break;
	}

	return error;
}

int git3_email__append_from_diff(
	git3_str *out,
	git3_diff *diff,
	size_t patch_idx,
	size_t patch_count,
	const git3_oid *commit_id,
	const char *summary,
	const char *body,
	const git3_signature *author,
	const git3_email_create_options *given_opts)
{
	git3_email_create_options opts = GIT3_EMAIL_CREATE_OPTIONS_INIT;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(diff);
	GIT3_ASSERT_ARG(!patch_idx || patch_idx <= patch_count);
	GIT3_ASSERT_ARG(commit_id);
	GIT3_ASSERT_ARG(author);

	GIT3_ERROR_CHECK_VERSION(given_opts,
		GIT3_EMAIL_CREATE_OPTIONS_VERSION,
		"git3_email_create_options");

	if (given_opts)
		memcpy(&opts, given_opts, sizeof(git3_email_create_options));

	if ((error = append_header(out, patch_idx, patch_count, commit_id, summary, author, &opts)) == 0 &&
	    (error = append_body(out, body)) == 0 &&
	    (error = git3_str_puts(out, "---\n")) == 0 &&
	    (error = append_diffstat(out, diff)) == 0 &&
	    (error = append_patches(out, diff)) == 0)
		error = git3_str_puts(out, "--\nlibgit3 " LIBGIT3_VERSION "\n\n");

	return error;
}

int git3_email_create_from_diff(
	git3_buf *out,
	git3_diff *diff,
	size_t patch_idx,
	size_t patch_count,
	const git3_oid *commit_id,
	const char *summary,
	const char *body,
	const git3_signature *author,
	const git3_email_create_options *given_opts)
{
	git3_str email = GIT3_STR_INIT;
	int error;

	git3_buf_tostr(&email, out);

	error = git3_email__append_from_diff(&email, diff, patch_idx,
		patch_count, commit_id, summary, body, author,
		given_opts);

	if (error == 0)
		error = git3_buf_fromstr(out, &email);

	git3_str_dispose(&email);
	return error;
}

int git3_email_create_from_commit(
	git3_buf *out,
	git3_commit *commit,
	const git3_email_create_options *given_opts)
{
	git3_email_create_options opts = GIT3_EMAIL_CREATE_OPTIONS_INIT;
	git3_diff *diff = NULL;
	git3_repository *repo;
	git3_diff_options *diff_opts;
	git3_diff_find_options *find_opts;
	const git3_signature *author;
	const char *summary, *body;
	const git3_oid *commit_id;
	int error = -1;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(commit);

	GIT3_ERROR_CHECK_VERSION(given_opts,
		GIT3_EMAIL_CREATE_OPTIONS_VERSION,
		"git3_email_create_options");

	if (given_opts)
		memcpy(&opts, given_opts, sizeof(git3_email_create_options));

	repo = git3_commit_owner(commit);
	author = git3_commit_author(commit);
	summary = git3_commit_summary(commit);
	body = git3_commit_body(commit);
	commit_id = git3_commit_id(commit);
	diff_opts = &opts.diff_opts;
	find_opts = &opts.diff_find_opts;

	if ((error = git3_diff__commit(&diff, repo, commit, diff_opts)) < 0)
		goto done;

	if ((opts.flags & GIT3_EMAIL_CREATE_NO_RENAMES) == 0 &&
	    (error = git3_diff_find_similar(diff, find_opts)) < 0)
		goto done;

	error = git3_email_create_from_diff(out, diff, 1, 1, commit_id, summary, body, author, &opts);

done:
	git3_diff_free(diff);
	return error;
}
