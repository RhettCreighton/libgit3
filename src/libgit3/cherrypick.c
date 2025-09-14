/*
* Copyright (C) the libgit3 contributors. All rights reserved.
*
* This file is part of libgit3, distributed under the GNU GPL v2 with
* a Linking Exception. For full terms see the included COPYING file.
*/

#include "common.h"

#include "repository.h"
#include "filebuf.h"
#include "merge.h"
#include "vector.h"
#include "index.h"

#include "git3/types.h"
#include "git3/merge.h"
#include "git3/cherrypick.h"
#include "git3/commit.h"
#include "git3/sys/commit.h"

#define GIT3_CHERRYPICK_FILE_MODE		0666

static int write_cherrypick_head(
	git3_repository *repo,
	const char *commit_oidstr)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	int error = 0;

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_CHERRYPICK_HEAD_FILE)) >= 0 &&
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_CREATE_LEADING_DIRS, GIT3_CHERRYPICK_FILE_MODE)) >= 0 &&
		(error = git3_filebuf_printf(&file, "%s\n", commit_oidstr)) >= 0)
		error = git3_filebuf_commit(&file);

	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	return error;
}

static int write_merge_msg(
	git3_repository *repo,
	const char *commit_msg)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	int error = 0;

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_MERGE_MSG_FILE)) < 0 ||
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_CREATE_LEADING_DIRS, GIT3_CHERRYPICK_FILE_MODE)) < 0 ||
		(error = git3_filebuf_printf(&file, "%s", commit_msg)) < 0)
		goto cleanup;

	error = git3_filebuf_commit(&file);

cleanup:
	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	return error;
}

static int cherrypick_normalize_opts(
	git3_repository *repo,
	git3_cherrypick_options *opts,
	const git3_cherrypick_options *given,
	const char *their_label)
{
	int error = 0;
	unsigned int default_checkout_strategy = GIT3_CHECKOUT_ALLOW_CONFLICTS;

	GIT3_UNUSED(repo);

	if (given != NULL)
		memcpy(opts, given, sizeof(git3_cherrypick_options));
	else {
		git3_cherrypick_options default_opts = GIT3_CHERRYPICK_OPTIONS_INIT;
		memcpy(opts, &default_opts, sizeof(git3_cherrypick_options));
	}

	if (!opts->checkout_opts.checkout_strategy)
		opts->checkout_opts.checkout_strategy = default_checkout_strategy;

	if (!opts->checkout_opts.our_label)
		opts->checkout_opts.our_label = "HEAD";

	if (!opts->checkout_opts.their_label)
		opts->checkout_opts.their_label = their_label;

	return error;
}

static int cherrypick_state_cleanup(git3_repository *repo)
{
	const char *state_files[] = { GIT3_CHERRYPICK_HEAD_FILE, GIT3_MERGE_MSG_FILE };

	return git3_repository__cleanup_files(repo, state_files, ARRAY_SIZE(state_files));
}

static int cherrypick_seterr(git3_commit *commit, const char *fmt)
{
	char commit_oidstr[GIT3_OID_MAX_HEXSIZE + 1];

	git3_error_set(GIT3_ERROR_CHERRYPICK, fmt,
		git3_oid_tostr(commit_oidstr, GIT3_OID_MAX_HEXSIZE + 1, git3_commit_id(commit)));

	return -1;
}

int git3_cherrypick_commit(
	git3_index **out,
	git3_repository *repo,
	git3_commit *cherrypick_commit,
	git3_commit *our_commit,
	unsigned int mainline,
	const git3_merge_options *merge_opts)
{
	git3_commit *parent_commit = NULL;
	git3_tree *parent_tree = NULL, *our_tree = NULL, *cherrypick_tree = NULL;
	int parent = 0, error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(cherrypick_commit);
	GIT3_ASSERT_ARG(our_commit);

	if (git3_commit_parentcount(cherrypick_commit) > 1) {
		if (!mainline)
			return cherrypick_seterr(cherrypick_commit,
				"mainline branch is not specified but %s is a merge commit");

		parent = mainline;
	} else {
		if (mainline)
			return cherrypick_seterr(cherrypick_commit,
				"mainline branch specified but %s is not a merge commit");

		parent = git3_commit_parentcount(cherrypick_commit);
	}

	if (parent &&
		((error = git3_commit_parent(&parent_commit, cherrypick_commit, (parent - 1))) < 0 ||
		(error = git3_commit_tree(&parent_tree, parent_commit)) < 0))
		goto done;

	if ((error = git3_commit_tree(&cherrypick_tree, cherrypick_commit)) < 0 ||
		(error = git3_commit_tree(&our_tree, our_commit)) < 0)
		goto done;

	error = git3_merge_trees(out, repo, parent_tree, our_tree, cherrypick_tree, merge_opts);

done:
	git3_tree_free(parent_tree);
	git3_tree_free(our_tree);
	git3_tree_free(cherrypick_tree);
	git3_commit_free(parent_commit);

	return error;
}

int git3_cherrypick(
	git3_repository *repo,
	git3_commit *commit,
	const git3_cherrypick_options *given_opts)
{
	git3_cherrypick_options opts;
	git3_reference *our_ref = NULL;
	git3_commit *our_commit = NULL;
	char commit_oidstr[GIT3_OID_MAX_HEXSIZE + 1];
	const char *commit_msg, *commit_summary;
	git3_str their_label = GIT3_STR_INIT;
	git3_index *index = NULL;
	git3_indexwriter indexwriter = GIT3_INDEXWRITER_INIT;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(commit);

	GIT3_ERROR_CHECK_VERSION(given_opts, GIT3_CHERRYPICK_OPTIONS_VERSION, "git3_cherrypick_options");

	if ((error = git3_repository__ensure_not_bare(repo, "cherry-pick")) < 0)
		return error;

	if ((commit_msg = git3_commit_message(commit)) == NULL ||
		(commit_summary = git3_commit_summary(commit)) == NULL) {
		error = -1;
		goto on_error;
	}

	git3_oid_nfmt(commit_oidstr, sizeof(commit_oidstr), git3_commit_id(commit));

	if ((error = write_merge_msg(repo, commit_msg)) < 0 ||
		(error = git3_str_printf(&their_label, "%.7s... %s", commit_oidstr, commit_summary)) < 0 ||
		(error = cherrypick_normalize_opts(repo, &opts, given_opts, git3_str_cstr(&their_label))) < 0 ||
		(error = git3_indexwriter_init_for_operation(&indexwriter, repo, &opts.checkout_opts.checkout_strategy)) < 0 ||
		(error = write_cherrypick_head(repo, commit_oidstr)) < 0 ||
		(error = git3_repository_head(&our_ref, repo)) < 0 ||
		(error = git3_reference_peel((git3_object **)&our_commit, our_ref, GIT3_OBJECT_COMMIT)) < 0 ||
		(error = git3_cherrypick_commit(&index, repo, commit, our_commit, opts.mainline, &opts.merge_opts)) < 0 ||
		(error = git3_merge__check_result(repo, index)) < 0 ||
		(error = git3_merge__append_conflicts_to_merge_msg(repo, index)) < 0 ||
		(error = git3_checkout_index(repo, index, &opts.checkout_opts)) < 0 ||
		(error = git3_indexwriter_commit(&indexwriter)) < 0)
		goto on_error;

	goto done;

on_error:
	cherrypick_state_cleanup(repo);

done:
	git3_indexwriter_cleanup(&indexwriter);
	git3_index_free(index);
	git3_commit_free(our_commit);
	git3_reference_free(our_ref);
	git3_str_dispose(&their_label);

	return error;
}

int git3_cherrypick_options_init(
	git3_cherrypick_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_cherrypick_options, GIT3_CHERRYPICK_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_cherrypick_init_options(
	git3_cherrypick_options *opts, unsigned int version)
{
	return git3_cherrypick_options_init(opts, version);
}
#endif
