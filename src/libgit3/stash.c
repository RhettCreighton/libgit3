/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "repository.h"
#include "commit.h"
#include "tree.h"
#include "reflog.h"
#include "blob.h"
#include "git3/diff.h"
#include "git3/stash.h"
#include "git3/status.h"
#include "git3/checkout.h"
#include "git3/index.h"
#include "git3/transaction.h"
#include "git3/merge.h"
#include "index.h"
#include "signature.h"
#include "iterator.h"
#include "merge.h"
#include "diff.h"
#include "diff_generate.h"
#include "strarray.h"

static int create_error(int error, const char *msg)
{
	git3_error_set(GIT3_ERROR_STASH, "cannot stash changes - %s", msg);
	return error;
}

static int retrieve_head(git3_reference **out, git3_repository *repo)
{
	int error = git3_repository_head(out, repo);

	if (error == GIT3_EUNBORNBRANCH)
		return create_error(error, "you do not have the initial commit yet.");

	return error;
}

static int append_abbreviated_oid(git3_str *out, const git3_oid *b_commit)
{
	char *formatted_oid;

	formatted_oid = git3_oid_allocfmt(b_commit);
	GIT3_ERROR_CHECK_ALLOC(formatted_oid);

	git3_str_put(out, formatted_oid, 7);
	git3__free(formatted_oid);

	return git3_str_oom(out) ? -1 : 0;
}

static int append_commit_description(git3_str *out, git3_commit *commit)
{
	const char *summary = git3_commit_summary(commit);
	GIT3_ERROR_CHECK_ALLOC(summary);

	if (append_abbreviated_oid(out, git3_commit_id(commit)) < 0)
		return -1;

	git3_str_putc(out, ' ');
	git3_str_puts(out, summary);
	git3_str_putc(out, '\n');

	return git3_str_oom(out) ? -1 : 0;
}

static int retrieve_base_commit_and_message(
	git3_commit **b_commit,
	git3_str *stash_message,
	git3_repository *repo)
{
	git3_reference *head = NULL;
	int error;

	if ((error = retrieve_head(&head, repo)) < 0)
		return error;

	if (strcmp("HEAD", git3_reference_name(head)) == 0)
		error = git3_str_puts(stash_message, "(no branch): ");
	else
		error = git3_str_printf(
			stash_message,
			"%s: ",
			git3_reference_name(head) + strlen(GIT3_REFS_HEADS_DIR));
	if (error < 0)
		goto cleanup;

	if ((error = git3_commit_lookup(
			 b_commit, repo, git3_reference_target(head))) < 0)
		goto cleanup;

	if ((error = append_commit_description(stash_message, *b_commit)) < 0)
		goto cleanup;

cleanup:
	git3_reference_free(head);
	return error;
}

static int build_tree_from_index(
	git3_tree **out,
	git3_repository *repo,
	git3_index *index)
{
	int error;
	git3_oid i_tree_oid;

	if ((error = git3_index_write_tree_to(&i_tree_oid, index, repo)) < 0)
		return error;

	return git3_tree_lookup(out, repo, &i_tree_oid);
}

static int commit_index(
	git3_commit **i_commit,
	git3_repository *repo,
	git3_index *index,
	const git3_signature *stasher,
	const char *message,
	const git3_commit *parent)
{
	git3_tree *i_tree = NULL;
	git3_oid i_commit_oid;
	git3_str msg = GIT3_STR_INIT;
	int error;

	if ((error = build_tree_from_index(&i_tree, repo, index)) < 0)
		goto cleanup;

	if ((error = git3_str_printf(&msg, "index on %s\n", message)) < 0)
		goto cleanup;

	if ((error = git3_commit_create(
		&i_commit_oid,
		git3_index_owner(index),
		NULL,
		stasher,
		stasher,
		NULL,
		git3_str_cstr(&msg),
		i_tree,
		1,
		&parent)) < 0)
		goto cleanup;

	error = git3_commit_lookup(i_commit, git3_index_owner(index), &i_commit_oid);

cleanup:
	git3_tree_free(i_tree);
	git3_str_dispose(&msg);
	return error;
}

struct stash_update_rules {
	bool include_changed;
	bool include_untracked;
	bool include_ignored;
};

/*
 * Similar to git3_index_add_bypath but able to operate on any
 * index without making assumptions about the repository's index
 */
static int stash_to_index(
	git3_repository *repo,
	git3_index *index,
	const char *path)
{
	git3_index *repo_index = NULL;
	git3_index_entry entry = {{0}};
	struct stat st;
	int error;

	if (!git3_repository_is_bare(repo) &&
	    (error = git3_repository_index__weakptr(&repo_index, repo)) < 0)
		return error;

	if ((error = git3_blob__create_from_paths(
	    &entry.id, &st, repo, NULL, path, 0, true)) < 0)
		return error;

	git3_index_entry__init_from_stat(&entry, &st,
		(repo_index == NULL || !repo_index->distrust_filemode));

	entry.path = path;

	return git3_index_add(index, &entry);
}

static int stash_update_index_from_paths(
	git3_repository *repo,
	git3_index *index,
	const git3_strarray *paths)
{
	unsigned int status_flags;
	size_t i;
	int error = 0;

	for (i = 0; i < paths->count; i++) {
		git3_status_file(&status_flags, repo, paths->strings[i]);

		if (status_flags & (GIT3_STATUS_WT_DELETED | GIT3_STATUS_INDEX_DELETED)) {
			if ((error = git3_index_remove(index, paths->strings[i], 0)) < 0)
				return error;
		} else {
			if ((error = stash_to_index(repo, index, paths->strings[i])) < 0)
				return error;
		}
	}

	return error;
}

static int stash_update_index_from_diff(
	git3_repository *repo,
	git3_index *index,
	const git3_diff *diff,
	struct stash_update_rules *data)
{
	int error = 0;
	size_t d, max_d = git3_diff_num_deltas(diff);

	for (d = 0; !error && d < max_d; ++d) {
		const char *add_path = NULL;
		const git3_diff_delta *delta = git3_diff_get_delta(diff, d);

		switch (delta->status) {
		case GIT3_DELTA_IGNORED:
			if (data->include_ignored)
				add_path = delta->new_file.path;
			break;

		case GIT3_DELTA_UNTRACKED:
			if (data->include_untracked &&
				delta->new_file.mode != GIT3_FILEMODE_TREE)
				add_path = delta->new_file.path;
			break;

		case GIT3_DELTA_ADDED:
		case GIT3_DELTA_MODIFIED:
			if (data->include_changed)
				add_path = delta->new_file.path;
			break;

		case GIT3_DELTA_DELETED:
			if (data->include_changed &&
				!git3_index_find(NULL, index, delta->old_file.path))
				error = git3_index_remove(index, delta->old_file.path, 0);
			break;

		default:
			/* Unimplemented */
			git3_error_set(
				GIT3_ERROR_INVALID,
				"cannot update index. Unimplemented status (%d)",
				delta->status);
			return -1;
		}

		if (add_path != NULL)
			error = stash_to_index(repo, index, add_path);
	}

	return error;
}

static int build_untracked_tree(
	git3_tree **tree_out,
	git3_repository *repo,
	git3_commit *i_commit,
	uint32_t flags)
{
	git3_index *i_index = NULL;
	git3_tree *i_tree = NULL;
	git3_diff *diff = NULL;
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_FOR_REPO(repo);
	struct stash_update_rules data = {0};
	int error;

	if ((error = git3_index_new_ext(&i_index, &index_opts)) < 0)
		goto cleanup;

	if (flags & GIT3_STASH_INCLUDE_UNTRACKED) {
		opts.flags |= GIT3_DIFF_INCLUDE_UNTRACKED |
			GIT3_DIFF_RECURSE_UNTRACKED_DIRS;
		data.include_untracked = true;
	}

	if (flags & GIT3_STASH_INCLUDE_IGNORED) {
		opts.flags |= GIT3_DIFF_INCLUDE_IGNORED |
			GIT3_DIFF_RECURSE_IGNORED_DIRS;
		data.include_ignored = true;
	}

	if ((error = git3_commit_tree(&i_tree, i_commit)) < 0)
		goto cleanup;

	if ((error = git3_diff_tree_to_workdir(&diff, repo, i_tree, &opts)) < 0)
		goto cleanup;

	if ((error = stash_update_index_from_diff(repo, i_index, diff, &data)) < 0)
		goto cleanup;

	error = build_tree_from_index(tree_out, repo, i_index);

cleanup:
	git3_diff_free(diff);
	git3_tree_free(i_tree);
	git3_index_free(i_index);
	return error;
}

static int commit_untracked(
	git3_commit **u_commit,
	git3_repository *repo,
	const git3_signature *stasher,
	const char *message,
	git3_commit *i_commit,
	uint32_t flags)
{
	git3_tree *u_tree = NULL;
	git3_oid u_commit_oid;
	git3_str msg = GIT3_STR_INIT;
	int error;

	if ((error = build_untracked_tree(&u_tree, repo, i_commit, flags)) < 0)
		goto cleanup;

	if ((error = git3_str_printf(&msg, "untracked files on %s\n", message)) < 0)
		goto cleanup;

	if ((error = git3_commit_create(
		&u_commit_oid,
		repo,
		NULL,
		stasher,
		stasher,
		NULL,
		git3_str_cstr(&msg),
		u_tree,
		0,
		NULL)) < 0)
		goto cleanup;

	error = git3_commit_lookup(u_commit, repo, &u_commit_oid);

cleanup:
	git3_tree_free(u_tree);
	git3_str_dispose(&msg);
	return error;
}

static git3_diff_delta *stash_delta_merge(
	const git3_diff_delta *a,
	const git3_diff_delta *b,
	git3_pool *pool)
{
	/* Special case for stash: if a file is deleted in the index, but exists
	 * in the working tree, we need to stash the workdir copy for the workdir.
	 */
	if (a->status == GIT3_DELTA_DELETED && b->status == GIT3_DELTA_UNTRACKED) {
		git3_diff_delta *dup = git3_diff__delta_dup(b, pool);

		if (dup)
			dup->status = GIT3_DELTA_MODIFIED;
		return dup;
	}

	return git3_diff__merge_like_cgit(a, b, pool);
}

static int build_workdir_tree(
	git3_tree **tree_out,
	git3_repository *repo,
	git3_index *i_index,
	git3_commit *b_commit)
{
	git3_tree *b_tree = NULL;
	git3_diff *diff = NULL, *idx_to_wd = NULL;
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	struct stash_update_rules data = {0};
	int error;

	opts.flags = GIT3_DIFF_IGNORE_SUBMODULES | GIT3_DIFF_INCLUDE_UNTRACKED;

	if ((error = git3_commit_tree(&b_tree, b_commit)) < 0)
		goto cleanup;

	if ((error = git3_diff_tree_to_index(&diff, repo, b_tree, i_index, &opts)) < 0 ||
		(error = git3_diff_index_to_workdir(&idx_to_wd, repo, i_index, &opts)) < 0 ||
		(error = git3_diff__merge(diff, idx_to_wd, stash_delta_merge)) < 0)
		goto cleanup;

	data.include_changed = true;

	if ((error = stash_update_index_from_diff(repo, i_index, diff, &data)) < 0)
		goto cleanup;

	error = build_tree_from_index(tree_out, repo, i_index);

cleanup:
	git3_diff_free(idx_to_wd);
	git3_diff_free(diff);
	git3_tree_free(b_tree);

	return error;
}

static int build_stash_commit_from_tree(
	git3_oid *w_commit_oid,
	git3_repository *repo,
	const git3_signature *stasher,
	const char *message,
	git3_commit *i_commit,
	git3_commit *b_commit,
	git3_commit *u_commit,
	const git3_tree *tree)
{
	const git3_commit *parents[] = {	NULL, NULL, NULL };

	parents[0] = b_commit;
	parents[1] = i_commit;
	parents[2] = u_commit;

	return git3_commit_create(
		w_commit_oid,
		repo,
		NULL,
		stasher,
		stasher,
		NULL,
		message,
		tree,
		u_commit ? 3 : 2,
		parents);
}

static int build_stash_commit_from_index(
	git3_oid *w_commit_oid,
	git3_repository *repo,
	const git3_signature *stasher,
	const char *message,
	git3_commit *i_commit,
	git3_commit *b_commit,
	git3_commit *u_commit,
	git3_index *index)
{
	git3_tree *tree;
	int error;

	if ((error = build_tree_from_index(&tree, repo, index)) < 0)
		goto cleanup;

	error = build_stash_commit_from_tree(
		w_commit_oid,
		repo,
		stasher,
		message,
		i_commit,
		b_commit,
		u_commit,
		tree);

cleanup:
	git3_tree_free(tree);
	return error;
}

static int commit_worktree(
	git3_oid *w_commit_oid,
	git3_repository *repo,
	const git3_signature *stasher,
	const char *message,
	git3_commit *i_commit,
	git3_commit *b_commit,
	git3_commit *u_commit)
{
	git3_index *i_index = NULL, *r_index = NULL;
	git3_tree *w_tree = NULL;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_FOR_REPO(repo);
	int error = 0, ignorecase;

	if ((error = git3_repository_index(&r_index, repo) < 0) ||
	    (error = git3_index_new_ext(&i_index, &index_opts)) < 0 ||
	    (error = git3_index__fill(i_index, &r_index->entries) < 0) ||
	    (error = git3_repository__configmap_lookup(&ignorecase, repo, GIT3_CONFIGMAP_IGNORECASE)) < 0)
		goto cleanup;

	git3_index__set_ignore_case(i_index, ignorecase);

	if ((error = build_workdir_tree(&w_tree, repo, i_index, b_commit)) < 0)
		goto cleanup;

	error = build_stash_commit_from_tree(
		w_commit_oid,
		repo,
		stasher,
		message,
		i_commit,
		b_commit,
		u_commit,
		w_tree
	);

cleanup:
	git3_tree_free(w_tree);
	git3_index_free(i_index);
	git3_index_free(r_index);
	return error;
}

static int prepare_worktree_commit_message(git3_str *out, const char *user_message)
{
	git3_str buf = GIT3_STR_INIT;
	int error = 0;

	if (!user_message) {
		git3_str_printf(&buf, "WIP on %s", git3_str_cstr(out));
	} else {
		const char *colon;

		if ((colon = strchr(git3_str_cstr(out), ':')) == NULL)
			goto cleanup;

		git3_str_puts(&buf, "On ");
		git3_str_put(&buf, git3_str_cstr(out), colon - out->ptr);
		git3_str_printf(&buf, ": %s\n", user_message);
	}

	if (git3_str_oom(&buf)) {
		error = -1;
		goto cleanup;
	}

	git3_str_swap(out, &buf);

cleanup:
	git3_str_dispose(&buf);
	return error;
}

static int update_reflog(
	git3_oid *w_commit_oid,
	git3_repository *repo,
	const char *message)
{
	git3_reference *stash;
	int error;

	if ((error = git3_reference_ensure_log(repo, GIT3_REFS_STASH_FILE)) < 0)
		return error;

	error = git3_reference_create(&stash, repo, GIT3_REFS_STASH_FILE, w_commit_oid, 1, message);

	git3_reference_free(stash);

	return error;
}

static int is_dirty_cb(const char *path, unsigned int status, void *payload)
{
	GIT3_UNUSED(path);
	GIT3_UNUSED(status);
	GIT3_UNUSED(payload);

	return GIT3_PASSTHROUGH;
}

static int ensure_there_are_changes_to_stash(git3_repository *repo, uint32_t flags)
{
	int error;
	git3_status_options opts = GIT3_STATUS_OPTIONS_INIT;

	opts.show  = GIT3_STATUS_SHOW_INDEX_AND_WORKDIR;
	opts.flags = GIT3_STATUS_OPT_EXCLUDE_SUBMODULES;

	if (flags & GIT3_STASH_INCLUDE_UNTRACKED)
		opts.flags |= GIT3_STATUS_OPT_INCLUDE_UNTRACKED |
			GIT3_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

	if (flags & GIT3_STASH_INCLUDE_IGNORED)
		opts.flags |= GIT3_STATUS_OPT_INCLUDE_IGNORED |
			GIT3_STATUS_OPT_RECURSE_IGNORED_DIRS;

	error = git3_status_foreach_ext(repo, &opts, is_dirty_cb, NULL);

	if (error == GIT3_PASSTHROUGH)
		return 0;

	if (!error)
		return create_error(GIT3_ENOTFOUND, "there is nothing to stash.");

	return error;
}

static int has_changes_cb(
	const char *path,
	unsigned int status,
	void *payload)
{
	GIT3_UNUSED(path);
	GIT3_UNUSED(status);
	GIT3_UNUSED(payload);

	if (status == GIT3_STATUS_CURRENT)
		return GIT3_ENOTFOUND;

	return 0;
}

static int ensure_there_are_changes_to_stash_paths(
	git3_repository *repo,
	uint32_t flags,
	const git3_strarray *paths)
{
	int error;
	git3_status_options opts = GIT3_STATUS_OPTIONS_INIT;

	opts.show  = GIT3_STATUS_SHOW_INDEX_AND_WORKDIR;
	opts.flags = GIT3_STATUS_OPT_EXCLUDE_SUBMODULES |
	             GIT3_STATUS_OPT_INCLUDE_UNMODIFIED |
		     GIT3_STATUS_OPT_DISABLE_PATHSPEC_MATCH;

	if (flags & GIT3_STASH_INCLUDE_UNTRACKED)
		opts.flags |= GIT3_STATUS_OPT_INCLUDE_UNTRACKED |
			GIT3_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

	if (flags & GIT3_STASH_INCLUDE_IGNORED)
		opts.flags |= GIT3_STATUS_OPT_INCLUDE_IGNORED |
			GIT3_STATUS_OPT_RECURSE_IGNORED_DIRS;

	git3_strarray_copy(&opts.pathspec, paths);

	error = git3_status_foreach_ext(repo, &opts, has_changes_cb, NULL);

	git3_strarray_dispose(&opts.pathspec);

	if (error == GIT3_ENOTFOUND)
		return create_error(GIT3_ENOTFOUND, "one of the files does not have any changes to stash.");

	return error;
}

static int reset_index_and_workdir(git3_repository *repo, git3_commit *commit, uint32_t flags)
{
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;

	opts.checkout_strategy = GIT3_CHECKOUT_FORCE;
	if (flags & GIT3_STASH_INCLUDE_UNTRACKED)
		opts.checkout_strategy |= GIT3_CHECKOUT_REMOVE_UNTRACKED;
	if (flags & GIT3_STASH_INCLUDE_IGNORED)
		opts.checkout_strategy |= GIT3_CHECKOUT_REMOVE_IGNORED;

	return git3_checkout_tree(repo, (git3_object *)commit, &opts);
}

int git3_stash_save(
	git3_oid *out,
	git3_repository *repo,
	const git3_signature *stasher,
	const char *message,
	uint32_t flags)
{
	git3_stash_save_options opts = GIT3_STASH_SAVE_OPTIONS_INIT;

	GIT3_ASSERT_ARG(stasher);

	opts.stasher = stasher;
	opts.message = message;
	opts.flags = flags;

	return git3_stash_save_with_opts(out, repo, &opts);
}

int git3_stash_save_with_opts(
	git3_oid *out,
	git3_repository *repo,
	const git3_stash_save_options *opts)
{
	git3_index *index = NULL, *paths_index = NULL;
	git3_commit *b_commit = NULL, *i_commit = NULL, *u_commit = NULL;
	git3_str msg = GIT3_STR_INIT;
	git3_tree *tree = NULL;
	git3_reference *head = NULL;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_FOR_REPO(repo);
	bool has_paths = false;

	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(opts && opts->stasher);

	has_paths = opts->paths.count > 0;

	if ((error = git3_repository__ensure_not_bare(repo, "stash save")) < 0)
		return error;

	if ((error = retrieve_base_commit_and_message(&b_commit, &msg, repo)) < 0)
		goto cleanup;

	if (!has_paths &&
		  (error = ensure_there_are_changes_to_stash(repo, opts->flags)) < 0)
		goto cleanup;
	else if (has_paths &&
		  (error = ensure_there_are_changes_to_stash_paths(
			  repo, opts->flags, &opts->paths)) < 0)
		goto cleanup;

	if ((error = git3_repository_index(&index, repo)) < 0)
		goto cleanup;

	if ((error = commit_index(&i_commit, repo, index, opts->stasher,
				  git3_str_cstr(&msg), b_commit)) < 0)
		goto cleanup;

	if ((opts->flags & (GIT3_STASH_INCLUDE_UNTRACKED | GIT3_STASH_INCLUDE_IGNORED)) &&
	    (error = commit_untracked(&u_commit, repo, opts->stasher,
			  git3_str_cstr(&msg), i_commit, opts->flags)) < 0)
		goto cleanup;

	if ((error = prepare_worktree_commit_message(&msg, opts->message)) < 0)
		goto cleanup;

	if (!has_paths) {
		if ((error = commit_worktree(out, repo, opts->stasher, git3_str_cstr(&msg),
					     i_commit, b_commit, u_commit)) < 0)
			goto cleanup;
	} else {
		if ((error = git3_index_new_ext(&paths_index, &index_opts)) < 0 ||
		    (error = retrieve_head(&head, repo)) < 0 ||
		    (error = git3_reference_peel((git3_object**)&tree, head, GIT3_OBJECT_TREE)) < 0 ||
		    (error = git3_index_read_tree(paths_index, tree)) < 0 ||
		    (error = stash_update_index_from_paths(repo, paths_index, &opts->paths)) < 0 ||
		    (error = build_stash_commit_from_index(out, repo, opts->stasher, git3_str_cstr(&msg),
				  i_commit, b_commit, u_commit, paths_index)) < 0)
			goto cleanup;
	}

	git3_str_rtrim(&msg);

	if ((error = update_reflog(out, repo, git3_str_cstr(&msg))) < 0)
		goto cleanup;

	if (!(opts->flags & GIT3_STASH_KEEP_ALL) &&
	    (error = reset_index_and_workdir(repo,
		  (opts->flags & GIT3_STASH_KEEP_INDEX) ? i_commit : b_commit,opts->flags)) < 0)
		goto cleanup;

cleanup:
	git3_str_dispose(&msg);
	git3_commit_free(i_commit);
	git3_commit_free(b_commit);
	git3_commit_free(u_commit);
	git3_tree_free(tree);
	git3_reference_free(head);
	git3_index_free(index);
	git3_index_free(paths_index);

	return error;
}

static int retrieve_stash_commit(
	git3_commit **commit,
	git3_repository *repo,
	size_t index)
{
	git3_reference *stash = NULL;
	git3_reflog *reflog = NULL;
	int error;
	size_t max;
	const git3_reflog_entry *entry;

	if ((error = git3_reference_lookup(&stash, repo, GIT3_REFS_STASH_FILE)) < 0)
		goto cleanup;

	if ((error = git3_reflog_read(&reflog, repo, GIT3_REFS_STASH_FILE)) < 0)
		goto cleanup;

	max = git3_reflog_entrycount(reflog);
	if (!max || index > max - 1) {
		error = GIT3_ENOTFOUND;
		git3_error_set(GIT3_ERROR_STASH, "no stashed state at position %" PRIuZ, index);
		goto cleanup;
	}

	entry = git3_reflog_entry_byindex(reflog, index);
	if ((error = git3_commit_lookup(commit, repo, git3_reflog_entry_id_new(entry))) < 0)
		goto cleanup;

cleanup:
	git3_reference_free(stash);
	git3_reflog_free(reflog);
	return error;
}

static int retrieve_stash_trees(
	git3_tree **out_stash_tree,
	git3_tree **out_base_tree,
	git3_tree **out_index_tree,
	git3_tree **out_index_parent_tree,
	git3_tree **out_untracked_tree,
	git3_commit *stash_commit)
{
	git3_tree *stash_tree = NULL;
	git3_commit *base_commit = NULL;
	git3_tree *base_tree = NULL;
	git3_commit *index_commit = NULL;
	git3_tree *index_tree = NULL;
	git3_commit *index_parent_commit = NULL;
	git3_tree *index_parent_tree = NULL;
	git3_commit *untracked_commit = NULL;
	git3_tree *untracked_tree = NULL;
	int error;

	if ((error = git3_commit_tree(&stash_tree, stash_commit)) < 0)
		goto cleanup;

	if ((error = git3_commit_parent(&base_commit, stash_commit, 0)) < 0)
		goto cleanup;
	if ((error = git3_commit_tree(&base_tree, base_commit)) < 0)
		goto cleanup;

	if ((error = git3_commit_parent(&index_commit, stash_commit, 1)) < 0)
		goto cleanup;
	if ((error = git3_commit_tree(&index_tree, index_commit)) < 0)
		goto cleanup;

	if ((error = git3_commit_parent(&index_parent_commit, index_commit, 0)) < 0)
		goto cleanup;
	if ((error = git3_commit_tree(&index_parent_tree, index_parent_commit)) < 0)
		goto cleanup;

	if (git3_commit_parentcount(stash_commit) == 3) {
		if ((error = git3_commit_parent(&untracked_commit, stash_commit, 2)) < 0)
			goto cleanup;
		if ((error = git3_commit_tree(&untracked_tree, untracked_commit)) < 0)
			goto cleanup;
	}

	*out_stash_tree = stash_tree;
	*out_base_tree = base_tree;
	*out_index_tree = index_tree;
	*out_index_parent_tree = index_parent_tree;
	*out_untracked_tree = untracked_tree;

cleanup:
	git3_commit_free(untracked_commit);
	git3_commit_free(index_parent_commit);
	git3_commit_free(index_commit);
	git3_commit_free(base_commit);
	if (error < 0) {
		git3_tree_free(stash_tree);
		git3_tree_free(base_tree);
		git3_tree_free(index_tree);
		git3_tree_free(index_parent_tree);
		git3_tree_free(untracked_tree);
	}
	return error;
}

static int merge_indexes(
	git3_index **out,
	git3_repository *repo,
	git3_tree *ancestor_tree,
	git3_index *ours_index,
	git3_index *theirs_index)
{
	git3_iterator *ancestor = NULL, *ours = NULL, *theirs = NULL;
	git3_iterator_options iter_opts = GIT3_ITERATOR_OPTIONS_INIT;
	int error;

	iter_opts.flags = GIT3_ITERATOR_DONT_IGNORE_CASE;

	if ((error = git3_iterator_for_tree(&ancestor, ancestor_tree, &iter_opts)) < 0 ||
		(error = git3_iterator_for_index(&ours, repo, ours_index, &iter_opts)) < 0 ||
		(error = git3_iterator_for_index(&theirs, repo, theirs_index, &iter_opts)) < 0)
		goto done;

	error = git3_merge__iterators(out, repo, ancestor, ours, theirs, NULL);

done:
	git3_iterator_free(ancestor);
	git3_iterator_free(ours);
	git3_iterator_free(theirs);
	return error;
}

static int merge_index_and_tree(
	git3_index **out,
	git3_repository *repo,
	git3_tree *ancestor_tree,
	git3_index *ours_index,
	git3_tree *theirs_tree)
{
	git3_iterator *ancestor = NULL, *ours = NULL, *theirs = NULL;
	git3_iterator_options iter_opts = GIT3_ITERATOR_OPTIONS_INIT;
	int error;

	iter_opts.flags = GIT3_ITERATOR_DONT_IGNORE_CASE;

	if ((error = git3_iterator_for_tree(&ancestor, ancestor_tree, &iter_opts)) < 0 ||
		(error = git3_iterator_for_index(&ours, repo, ours_index, &iter_opts)) < 0 ||
		(error = git3_iterator_for_tree(&theirs, theirs_tree, &iter_opts)) < 0)
		goto done;

	error = git3_merge__iterators(out, repo, ancestor, ours, theirs, NULL);

done:
	git3_iterator_free(ancestor);
	git3_iterator_free(ours);
	git3_iterator_free(theirs);
	return error;
}

static void normalize_apply_options(
	git3_stash_apply_options *opts,
	const git3_stash_apply_options *given_apply_opts)
{
	if (given_apply_opts != NULL) {
		memcpy(opts, given_apply_opts, sizeof(git3_stash_apply_options));
	} else {
		git3_stash_apply_options default_apply_opts = GIT3_STASH_APPLY_OPTIONS_INIT;
		memcpy(opts, &default_apply_opts, sizeof(git3_stash_apply_options));
	}

	opts->checkout_options.checkout_strategy |= GIT3_CHECKOUT_NO_REFRESH;

	if (!opts->checkout_options.our_label)
		opts->checkout_options.our_label = "Updated upstream";

	if (!opts->checkout_options.their_label)
		opts->checkout_options.their_label = "Stashed changes";
}

int git3_stash_apply_options_init(git3_stash_apply_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_stash_apply_options, GIT3_STASH_APPLY_OPTIONS_INIT);
	return 0;
}

int git3_stash_save_options_init(git3_stash_save_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_stash_save_options, GIT3_STASH_SAVE_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_stash_apply_init_options(git3_stash_apply_options *opts, unsigned int version)
{
	return git3_stash_apply_options_init(opts, version);
}
#endif

#define NOTIFY_PROGRESS(opts, progress_type)				\
	do {								\
		if ((opts).progress_cb &&				\
		    (error = (opts).progress_cb((progress_type), (opts).progress_payload))) { \
			error = (error < 0) ? error : -1;		\
			goto cleanup;					\
		}							\
	} while(false);

static int ensure_clean_index(git3_repository *repo, git3_index *index)
{
	git3_tree *head_tree = NULL;
	git3_diff *index_diff = NULL;
	int error = 0;

	if ((error = git3_repository_head_tree(&head_tree, repo)) < 0 ||
		(error = git3_diff_tree_to_index(
			&index_diff, repo, head_tree, index, NULL)) < 0)
		goto done;

	if (git3_diff_num_deltas(index_diff) > 0) {
		git3_error_set(GIT3_ERROR_STASH, "%" PRIuZ " uncommitted changes exist in the index",
			git3_diff_num_deltas(index_diff));
		error = GIT3_EUNCOMMITTED;
	}

done:
	git3_diff_free(index_diff);
	git3_tree_free(head_tree);
	return error;
}

static int stage_new_file(const git3_index_entry **entries, void *data)
{
	git3_index *index = data;

	if(entries[0] == NULL)
		return git3_index_add(index, entries[1]);
	else
		return git3_index_add(index, entries[0]);
}

static int stage_new_files(
	git3_index **out,
	git3_repository *repo,
	git3_tree *parent_tree,
	git3_tree *tree)
{
	git3_iterator *iterators[2] = { NULL, NULL };
	git3_iterator_options iterator_options = GIT3_ITERATOR_OPTIONS_INIT;
	git3_index *index = NULL;
	git3_index_options index_opts = GIT3_INDEX_OPTIONS_FOR_REPO(repo);
	int error;

	if ((error = git3_index_new_ext(&index, &index_opts)) < 0 ||
		(error = git3_iterator_for_tree(
			&iterators[0], parent_tree, &iterator_options)) < 0 ||
		(error = git3_iterator_for_tree(
			&iterators[1], tree, &iterator_options)) < 0)
		goto done;

	error = git3_iterator_walk(iterators, 2, stage_new_file, index);

done:
	if (error < 0)
		git3_index_free(index);
	else
		*out = index;

	git3_iterator_free(iterators[0]);
	git3_iterator_free(iterators[1]);

	return error;
}

int git3_stash_apply(
	git3_repository *repo,
	size_t index,
	const git3_stash_apply_options *given_opts)
{
	git3_stash_apply_options opts;
	unsigned int checkout_strategy;
	git3_commit *stash_commit = NULL;
	git3_tree *stash_tree = NULL;
	git3_tree *stash_parent_tree = NULL;
	git3_tree *index_tree = NULL;
	git3_tree *index_parent_tree = NULL;
	git3_tree *untracked_tree = NULL;
	git3_index *stash_adds = NULL;
	git3_index *repo_index = NULL;
	git3_index *unstashed_index = NULL;
	git3_index *modified_index = NULL;
	git3_index *untracked_index = NULL;
	int error;

	GIT3_ERROR_CHECK_VERSION(given_opts, GIT3_STASH_APPLY_OPTIONS_VERSION, "git3_stash_apply_options");

	normalize_apply_options(&opts, given_opts);
	checkout_strategy = opts.checkout_options.checkout_strategy;

	NOTIFY_PROGRESS(opts, GIT3_STASH_APPLY_PROGRESS_LOADING_STASH);

	/* Retrieve commit corresponding to the given stash */
	if ((error = retrieve_stash_commit(&stash_commit, repo, index)) < 0)
		goto cleanup;

	/* Retrieve all trees in the stash */
	if ((error = retrieve_stash_trees(
			&stash_tree, &stash_parent_tree, &index_tree,
			&index_parent_tree, &untracked_tree, stash_commit)) < 0)
		goto cleanup;

	/* Load repo index */
	if ((error = git3_repository_index(&repo_index, repo)) < 0)
		goto cleanup;

	NOTIFY_PROGRESS(opts, GIT3_STASH_APPLY_PROGRESS_ANALYZE_INDEX);

	if ((error = ensure_clean_index(repo, repo_index)) < 0)
		goto cleanup;

	/* Restore index if required */
	if ((opts.flags & GIT3_STASH_APPLY_REINSTATE_INDEX) &&
		git3_oid_cmp(git3_tree_id(stash_parent_tree), git3_tree_id(index_tree))) {

		if ((error = merge_index_and_tree(
				&unstashed_index, repo, index_parent_tree, repo_index, index_tree)) < 0)
			goto cleanup;

		if (git3_index_has_conflicts(unstashed_index)) {
			error = GIT3_ECONFLICT;
			goto cleanup;
		}

	/* Otherwise, stage any new files in the stash tree.  (Note: their
	 * previously unstaged contents are staged, not the previously staged.)
	 */
	} else if ((opts.flags & GIT3_STASH_APPLY_REINSTATE_INDEX) == 0) {
		if ((error = stage_new_files(&stash_adds, repo,
				stash_parent_tree, stash_tree)) < 0 ||
		    (error = merge_indexes(&unstashed_index, repo,
				stash_parent_tree, repo_index, stash_adds)) < 0)
			goto cleanup;
	}

	NOTIFY_PROGRESS(opts, GIT3_STASH_APPLY_PROGRESS_ANALYZE_MODIFIED);

	/* Restore modified files in workdir */
	if ((error = merge_index_and_tree(
			&modified_index, repo, stash_parent_tree, repo_index, stash_tree)) < 0)
		goto cleanup;

	/* If applicable, restore untracked / ignored files in workdir */
	if (untracked_tree) {
		NOTIFY_PROGRESS(opts, GIT3_STASH_APPLY_PROGRESS_ANALYZE_UNTRACKED);

		if ((error = merge_index_and_tree(&untracked_index, repo, NULL, repo_index, untracked_tree)) < 0)
			goto cleanup;
	}

	if (untracked_index) {
		opts.checkout_options.checkout_strategy |= GIT3_CHECKOUT_DONT_UPDATE_INDEX;

		NOTIFY_PROGRESS(opts, GIT3_STASH_APPLY_PROGRESS_CHECKOUT_UNTRACKED);

		if ((error = git3_checkout_index(repo, untracked_index, &opts.checkout_options)) < 0)
			goto cleanup;

		opts.checkout_options.checkout_strategy = checkout_strategy;
	}


	/* If there are conflicts in the modified index, then we need to actually
	 * check that out as the repo's index.  Otherwise, we don't update the
	 * index.
	 */

	if (!git3_index_has_conflicts(modified_index))
		opts.checkout_options.checkout_strategy |= GIT3_CHECKOUT_DONT_UPDATE_INDEX;

	/* Check out the modified index using the existing repo index as baseline,
	 * so that existing modifications in the index can be rewritten even when
	 * checking out safely.
	 */
	opts.checkout_options.baseline_index = repo_index;

	NOTIFY_PROGRESS(opts, GIT3_STASH_APPLY_PROGRESS_CHECKOUT_MODIFIED);

	if ((error = git3_checkout_index(repo, modified_index, &opts.checkout_options)) < 0)
		goto cleanup;

	if (unstashed_index && !git3_index_has_conflicts(modified_index)) {
		if ((error = git3_index_read_index(repo_index, unstashed_index)) < 0)
			goto cleanup;
	}

	NOTIFY_PROGRESS(opts, GIT3_STASH_APPLY_PROGRESS_DONE);

	error = git3_index_write(repo_index);

cleanup:
	git3_index_free(untracked_index);
	git3_index_free(modified_index);
	git3_index_free(unstashed_index);
	git3_index_free(stash_adds);
	git3_index_free(repo_index);
	git3_tree_free(untracked_tree);
	git3_tree_free(index_parent_tree);
	git3_tree_free(index_tree);
	git3_tree_free(stash_parent_tree);
	git3_tree_free(stash_tree);
	git3_commit_free(stash_commit);
	return error;
}

int git3_stash_foreach(
	git3_repository *repo,
	git3_stash_cb callback,
	void *payload)
{
	git3_reference *stash;
	git3_reflog *reflog = NULL;
	int error;
	size_t i, max;
	const git3_reflog_entry *entry;

	error = git3_reference_lookup(&stash, repo, GIT3_REFS_STASH_FILE);
	if (error == GIT3_ENOTFOUND) {
		git3_error_clear();
		return 0;
	}
	if (error < 0)
		goto cleanup;

	if ((error = git3_reflog_read(&reflog, repo, GIT3_REFS_STASH_FILE)) < 0)
		goto cleanup;

	max = git3_reflog_entrycount(reflog);
	for (i = 0; i < max; i++) {
		entry = git3_reflog_entry_byindex(reflog, i);

		error = callback(i,
			git3_reflog_entry_message(entry),
			git3_reflog_entry_id_new(entry),
			payload);

		if (error) {
			git3_error_set_after_callback(error);
			break;
		}
	}

cleanup:
	git3_reference_free(stash);
	git3_reflog_free(reflog);
	return error;
}

int git3_stash_drop(
	git3_repository *repo,
	size_t index)
{
	git3_transaction *tx;
	git3_reference *stash = NULL;
	git3_reflog *reflog = NULL;
	size_t max;
	int error;

	if ((error = git3_transaction_new(&tx, repo)) < 0)
		return error;

	if ((error = git3_transaction_lock_ref(tx, GIT3_REFS_STASH_FILE)) < 0)
		goto cleanup;

	if ((error = git3_reference_lookup(&stash, repo, GIT3_REFS_STASH_FILE)) < 0)
		goto cleanup;

	if ((error = git3_reflog_read(&reflog, repo, GIT3_REFS_STASH_FILE)) < 0)
		goto cleanup;

	max = git3_reflog_entrycount(reflog);

	if (!max || index > max - 1) {
		error = GIT3_ENOTFOUND;
		git3_error_set(GIT3_ERROR_STASH, "no stashed state at position %" PRIuZ, index);
		goto cleanup;
	}

	if ((error = git3_reflog_drop(reflog, index, true)) < 0)
		goto cleanup;

	if ((error = git3_transaction_set_reflog(tx, GIT3_REFS_STASH_FILE, reflog)) < 0)
		goto cleanup;

	if (max == 1) {
		if ((error = git3_transaction_remove(tx, GIT3_REFS_STASH_FILE)) < 0)
			goto cleanup;
	} else if (index == 0) {
		const git3_reflog_entry *entry;

		entry = git3_reflog_entry_byindex(reflog, 0);
		if ((error = git3_transaction_set_target(tx, GIT3_REFS_STASH_FILE, &entry->oid_cur, NULL, NULL)) < 0)
			goto cleanup;
	}

	error = git3_transaction_commit(tx);

cleanup:
	git3_reference_free(stash);
	git3_transaction_free(tx);
	git3_reflog_free(reflog);
	return error;
}

int git3_stash_pop(
	git3_repository *repo,
	size_t index,
	const git3_stash_apply_options *options)
{
	int error;

	if ((error = git3_stash_apply(repo, index, options)) < 0)
		return error;

	return git3_stash_drop(repo, index);
}
