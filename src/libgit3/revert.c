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
#include "index.h"

#include "git3/types.h"
#include "git3/merge.h"
#include "git3/revert.h"
#include "git3/commit.h"
#include "git3/sys/commit.h"

#define GIT3_REVERT_FILE_MODE		0666

static int write_revert_head(
	git3_repository *repo,
	const char *commit_oidstr)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	int error = 0;

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_REVERT_HEAD_FILE)) >= 0 &&
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_CREATE_LEADING_DIRS, GIT3_REVERT_FILE_MODE)) >= 0 &&
		(error = git3_filebuf_printf(&file, "%s\n", commit_oidstr)) >= 0)
		error = git3_filebuf_commit(&file);

	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	return error;
}

static int write_merge_msg(
	git3_repository *repo,
	const char *commit_oidstr,
	const char *commit_msgline)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	int error = 0;

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_MERGE_MSG_FILE)) < 0 ||
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_CREATE_LEADING_DIRS, GIT3_REVERT_FILE_MODE)) < 0 ||
		(error = git3_filebuf_printf(&file, "Revert \"%s\"\n\nThis reverts commit %s.\n",
		commit_msgline, commit_oidstr)) < 0)
		goto cleanup;

	error = git3_filebuf_commit(&file);

cleanup:
	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	return error;
}

static int revert_normalize_opts(
	git3_repository *repo,
	git3_revert_options *opts,
	const git3_revert_options *given,
	const char *their_label)
{
	int error = 0;
	unsigned int default_checkout_strategy = GIT3_CHECKOUT_ALLOW_CONFLICTS;

	GIT3_UNUSED(repo);

	if (given != NULL)
		memcpy(opts, given, sizeof(git3_revert_options));
	else {
		git3_revert_options default_opts = GIT3_REVERT_OPTIONS_INIT;
		memcpy(opts, &default_opts, sizeof(git3_revert_options));
	}

	if (!opts->checkout_opts.checkout_strategy)
		opts->checkout_opts.checkout_strategy = default_checkout_strategy;

	if (!opts->checkout_opts.our_label)
		opts->checkout_opts.our_label = "HEAD";

	if (!opts->checkout_opts.their_label)
		opts->checkout_opts.their_label = their_label;

	return error;
}

static int revert_state_cleanup(git3_repository *repo)
{
	const char *state_files[] = { GIT3_REVERT_HEAD_FILE, GIT3_MERGE_MSG_FILE };

	return git3_repository__cleanup_files(repo, state_files, ARRAY_SIZE(state_files));
}

static int revert_seterr(git3_commit *commit, const char *fmt)
{
	char commit_id[GIT3_OID_MAX_HEXSIZE + 1];

	git3_oid_tostr(commit_id, GIT3_OID_MAX_HEXSIZE + 1, git3_commit_id(commit));
	git3_error_set(GIT3_ERROR_REVERT, fmt, commit_id);

	return -1;
}

int git3_revert_commit(
	git3_index **out,
	git3_repository *repo,
	git3_commit *revert_commit,
	git3_commit *our_commit,
	unsigned int mainline,
	const git3_merge_options *merge_opts)
{
	git3_commit *parent_commit = NULL;
	git3_tree *parent_tree = NULL, *our_tree = NULL, *revert_tree = NULL;
	int parent = 0, error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(revert_commit);
	GIT3_ASSERT_ARG(our_commit);

	if (git3_commit_parentcount(revert_commit) > 1) {
		if (!mainline)
			return revert_seterr(revert_commit,
				"mainline branch is not specified but %s is a merge commit");

		parent = mainline;
	} else {
		if (mainline)
			return revert_seterr(revert_commit,
				"mainline branch specified but %s is not a merge commit");

		parent = git3_commit_parentcount(revert_commit);
	}

	if (parent &&
		((error = git3_commit_parent(&parent_commit, revert_commit, (parent - 1))) < 0 ||
		(error = git3_commit_tree(&parent_tree, parent_commit)) < 0))
		goto done;

	if ((error = git3_commit_tree(&revert_tree, revert_commit)) < 0 ||
		(error = git3_commit_tree(&our_tree, our_commit)) < 0)
		goto done;

	error = git3_merge_trees(out, repo, revert_tree, our_tree, parent_tree, merge_opts);

done:
	git3_tree_free(parent_tree);
	git3_tree_free(our_tree);
	git3_tree_free(revert_tree);
	git3_commit_free(parent_commit);

	return error;
}

int git3_revert(
	git3_repository *repo,
	git3_commit *commit,
	const git3_revert_options *given_opts)
{
	git3_revert_options opts;
	git3_reference *our_ref = NULL;
	git3_commit *our_commit = NULL;
	char commit_id[GIT3_OID_MAX_HEXSIZE + 1];
	const char *commit_msg;
	git3_str their_label = GIT3_STR_INIT;
	git3_index *index = NULL;
	git3_indexwriter indexwriter = GIT3_INDEXWRITER_INIT;
	int error;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(commit);

	GIT3_ERROR_CHECK_VERSION(given_opts, GIT3_REVERT_OPTIONS_VERSION, "git3_revert_options");

	if ((error = git3_repository__ensure_not_bare(repo, "revert")) < 0)
		return error;

	git3_oid_tostr(commit_id, GIT3_OID_MAX_HEXSIZE + 1, git3_commit_id(commit));

	if ((commit_msg = git3_commit_summary(commit)) == NULL) {
		error = -1;
		goto on_error;
	}

	if ((error = git3_str_printf(&their_label, "parent of %.7s... %s", commit_id, commit_msg)) < 0 ||
		(error = revert_normalize_opts(repo, &opts, given_opts, git3_str_cstr(&their_label))) < 0 ||
		(error = git3_indexwriter_init_for_operation(&indexwriter, repo, &opts.checkout_opts.checkout_strategy)) < 0 ||
		(error = write_revert_head(repo, commit_id)) < 0 ||
		(error = write_merge_msg(repo, commit_id, commit_msg)) < 0 ||
		(error = git3_repository_head(&our_ref, repo)) < 0 ||
		(error = git3_reference_peel((git3_object **)&our_commit, our_ref, GIT3_OBJECT_COMMIT)) < 0 ||
		(error = git3_revert_commit(&index, repo, commit, our_commit, opts.mainline, &opts.merge_opts)) < 0 ||
		(error = git3_merge__check_result(repo, index)) < 0 ||
		(error = git3_merge__append_conflicts_to_merge_msg(repo, index)) < 0 ||
		(error = git3_checkout_index(repo, index, &opts.checkout_opts)) < 0 ||
		(error = git3_indexwriter_commit(&indexwriter)) < 0)
		goto on_error;

	goto done;

on_error:
	revert_state_cleanup(repo);

done:
	git3_indexwriter_cleanup(&indexwriter);
	git3_index_free(index);
	git3_commit_free(our_commit);
	git3_reference_free(our_ref);
	git3_str_dispose(&their_label);

	return error;
}

int git3_revert_options_init(git3_revert_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_revert_options, GIT3_REVERT_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_revert_init_options(git3_revert_options *opts, unsigned int version)
{
	return git3_revert_options_init(opts, version);
}
#endif
