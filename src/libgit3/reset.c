/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "commit.h"
#include "tag.h"
#include "merge.h"
#include "diff.h"
#include "annotated_commit.h"
#include "git3/reset.h"
#include "git3/checkout.h"
#include "git3/merge.h"
#include "git3/refs.h"

#define ERROR_MSG "Cannot perform reset"

int git3_reset_default(
	git3_repository *repo,
	const git3_object *target,
	const git3_strarray *pathspecs)
{
	git3_object *commit = NULL;
	git3_tree *tree = NULL;
	git3_diff *diff = NULL;
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	size_t i, max_i;
	git3_index_entry entry;
	int error;
	git3_index *index = NULL;

	GIT3_ASSERT_ARG(pathspecs && pathspecs->count > 0);

	memset(&entry, 0, sizeof(git3_index_entry));

	if ((error = git3_repository_index(&index, repo)) < 0)
		goto cleanup;

	if (target) {
		if (git3_object_owner(target) != repo) {
			git3_error_set(GIT3_ERROR_OBJECT,
				"%s_default - The given target does not belong to this repository.", ERROR_MSG);
			return -1;
		}

		if ((error = git3_object_peel(&commit, target, GIT3_OBJECT_COMMIT)) < 0 ||
			(error = git3_commit_tree(&tree, (git3_commit *)commit)) < 0)
			goto cleanup;
	}

	opts.pathspec = *pathspecs;
	opts.flags = GIT3_DIFF_REVERSE;

	if ((error = git3_diff_tree_to_index(
		&diff, repo, tree, index, &opts)) < 0)
			goto cleanup;

	for (i = 0, max_i = git3_diff_num_deltas(diff); i < max_i; ++i) {
		const git3_diff_delta *delta = git3_diff_get_delta(diff, i);

		GIT3_ASSERT(delta->status == GIT3_DELTA_ADDED ||
		           delta->status == GIT3_DELTA_MODIFIED ||
		           delta->status == GIT3_DELTA_CONFLICTED ||
		           delta->status == GIT3_DELTA_DELETED);

		error = git3_index_conflict_remove(index, delta->old_file.path);
		if (error < 0) {
			if (delta->status == GIT3_DELTA_ADDED && error == GIT3_ENOTFOUND)
				git3_error_clear();
			else
				goto cleanup;
		}

		if (delta->status == GIT3_DELTA_DELETED) {
			if ((error = git3_index_remove(index, delta->old_file.path, 0)) < 0)
				goto cleanup;
		} else {
			entry.mode = delta->new_file.mode;
			git3_oid_cpy(&entry.id, &delta->new_file.id);
			entry.path = (char *)delta->new_file.path;

			if ((error = git3_index_add(index, &entry)) < 0)
				goto cleanup;
		}
	}

	error = git3_index_write(index);

cleanup:
	git3_object_free(commit);
	git3_tree_free(tree);
	git3_index_free(index);
	git3_diff_free(diff);

	return error;
}

static int reset(
	git3_repository *repo,
	const git3_object *target,
	const char *to,
	git3_reset_t reset_type,
	const git3_checkout_options *checkout_opts)
{
	git3_object *commit = NULL;
	git3_index *index = NULL;
	git3_tree *tree = NULL;
	int error = 0;
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;
	git3_str log_message = GIT3_STR_INIT;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(target);

	if (checkout_opts)
		opts = *checkout_opts;

	if (git3_object_owner(target) != repo) {
		git3_error_set(GIT3_ERROR_OBJECT,
			"%s - The given target does not belong to this repository.", ERROR_MSG);
		return -1;
	}

	if (reset_type != GIT3_RESET_SOFT &&
		(error = git3_repository__ensure_not_bare(repo,
			reset_type == GIT3_RESET_MIXED ? "reset mixed" : "reset hard")) < 0)
		return error;

	if ((error = git3_object_peel(&commit, target, GIT3_OBJECT_COMMIT)) < 0 ||
		(error = git3_repository_index(&index, repo)) < 0 ||
		(error = git3_commit_tree(&tree, (git3_commit *)commit)) < 0)
		goto cleanup;

	if (reset_type == GIT3_RESET_SOFT &&
		(git3_repository_state(repo) == GIT3_REPOSITORY_STATE_MERGE ||
		 git3_index_has_conflicts(index)))
	{
		git3_error_set(GIT3_ERROR_OBJECT, "%s (soft) in the middle of a merge", ERROR_MSG);
		error = GIT3_EUNMERGED;
		goto cleanup;
	}

	if ((error = git3_str_printf(&log_message, "reset: moving to %s", to)) < 0)
		return error;

	if (reset_type == GIT3_RESET_HARD) {
		/* overwrite working directory with the new tree */
		opts.checkout_strategy = GIT3_CHECKOUT_FORCE;

		if ((error = git3_checkout_tree(repo, (git3_object *)tree, &opts)) < 0)
			goto cleanup;
	}

	/* move HEAD to the new target */
	if ((error = git3_reference__update_terminal(repo, GIT3_HEAD_FILE,
		git3_object_id(commit), NULL, git3_str_cstr(&log_message))) < 0)
		goto cleanup;

	if (reset_type > GIT3_RESET_SOFT) {
		/* reset index to the target content */

		if ((error = git3_index_read_tree(index, tree)) < 0 ||
			(error = git3_index_write(index)) < 0)
			goto cleanup;

		if ((error = git3_repository_state_cleanup(repo)) < 0) {
			git3_error_set(GIT3_ERROR_INDEX, "%s - failed to clean up merge data", ERROR_MSG);
			goto cleanup;
		}
	}

cleanup:
	git3_object_free(commit);
	git3_index_free(index);
	git3_tree_free(tree);
	git3_str_dispose(&log_message);

	return error;
}

int git3_reset(
	git3_repository *repo,
	const git3_object *target,
	git3_reset_t reset_type,
	const git3_checkout_options *checkout_opts)
{
	char to[GIT3_OID_MAX_HEXSIZE + 1];

	git3_oid_tostr(to, GIT3_OID_MAX_HEXSIZE + 1, git3_object_id(target));
	return reset(repo, target, to, reset_type, checkout_opts);
}

int git3_reset_from_annotated(
	git3_repository *repo,
	const git3_annotated_commit *commit,
	git3_reset_t reset_type,
	const git3_checkout_options *checkout_opts)
{
	return reset(repo, (git3_object *) commit->commit, commit->description, reset_type, checkout_opts);
}
