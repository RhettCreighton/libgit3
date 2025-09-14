/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "worktree.h"

#include "buf.h"
#include "repository.h"
#include "path.h"

#include "git3/branch.h"
#include "git3/commit.h"
#include "git3/worktree.h"

static bool is_worktree_dir(const char *dir)
{
	git3_str buf = GIT3_STR_INIT;
	int error;

	if (git3_str_sets(&buf, dir) < 0)
		return -1;

	error = git3_fs_path_contains_file(&buf, "commondir")
		&& git3_fs_path_contains_file(&buf, "gitdir")
		&& git3_fs_path_contains_file(&buf, "HEAD");

	git3_str_dispose(&buf);
	return error;
}

int git3_worktree_list(git3_strarray *wts, git3_repository *repo)
{
	git3_vector worktrees = GIT3_VECTOR_INIT;
	git3_str path = GIT3_STR_INIT;
	char *worktree;
	size_t i, len;
	int error;

	GIT3_ASSERT_ARG(wts);
	GIT3_ASSERT_ARG(repo);

	wts->count = 0;
	wts->strings = NULL;

	if ((error = git3_str_joinpath(&path, repo->commondir, "worktrees/")) < 0)
		goto exit;
	if (!git3_fs_path_exists(path.ptr) || git3_fs_path_is_empty_dir(path.ptr))
		goto exit;
	if ((error = git3_fs_path_dirload(&worktrees, path.ptr, path.size, 0x0)) < 0)
		goto exit;

	len = path.size;

	git3_vector_foreach(&worktrees, i, worktree) {
		git3_str_truncate(&path, len);
		git3_str_puts(&path, worktree);

		if (!is_worktree_dir(path.ptr)) {
			git3_vector_remove(&worktrees, i);
			git3__free(worktree);
		}
	}

	wts->strings = (char **)git3_vector_detach(&wts->count, NULL, &worktrees);

exit:
	git3_str_dispose(&path);

	return error;
}

char *git3_worktree__read_link(const char *base, const char *file)
{
	git3_str path = GIT3_STR_INIT, buf = GIT3_STR_INIT;

	GIT3_ASSERT_ARG_WITH_RETVAL(base, NULL);
	GIT3_ASSERT_ARG_WITH_RETVAL(file, NULL);

	if (git3_str_joinpath(&path, base, file) < 0)
		goto err;
	if (git3_futils_readbuffer(&buf, path.ptr) < 0)
		goto err;
	git3_str_dispose(&path);

	git3_str_rtrim(&buf);

	if (!git3_fs_path_is_relative(buf.ptr))
		return git3_str_detach(&buf);

	if (git3_str_sets(&path, base) < 0)
		goto err;
	if (git3_fs_path_apply_relative(&path, buf.ptr) < 0)
		goto err;
	git3_str_dispose(&buf);

	return git3_str_detach(&path);

err:
	git3_str_dispose(&buf);
	git3_str_dispose(&path);

	return NULL;
}

static int write_wtfile(const char *base, const char *file, const git3_str *buf)
{
	git3_str path = GIT3_STR_INIT;
	int err;

	GIT3_ASSERT_ARG(base);
	GIT3_ASSERT_ARG(file);
	GIT3_ASSERT_ARG(buf);

	if ((err = git3_str_joinpath(&path, base, file)) < 0)
		goto out;

	if ((err = git3_futils_writebuffer(buf, path.ptr, O_CREAT|O_EXCL|O_WRONLY, 0644)) < 0)
		goto out;

out:
	git3_str_dispose(&path);

	return err;
}

static int open_worktree_dir(git3_worktree **out, const char *parent, const char *dir, const char *name)
{
	git3_str gitdir = GIT3_STR_INIT;
	git3_worktree *wt = NULL;
	int error = 0;

	if (!is_worktree_dir(dir)) {
		error = -1;
		goto out;
	}

	if ((error = git3_path_validate_length(NULL, dir)) < 0)
		goto out;

	if ((wt = git3__calloc(1, sizeof(*wt))) == NULL) {
		error = -1;
		goto out;
	}

	if ((wt->name = git3__strdup(name)) == NULL ||
	    (wt->commondir_path = git3_worktree__read_link(dir, "commondir")) == NULL ||
	    (wt->gitlink_path = git3_worktree__read_link(dir, "gitdir")) == NULL ||
	    (parent && (wt->parent_path = git3__strdup(parent)) == NULL) ||
	    (wt->worktree_path = git3_fs_path_dirname(wt->gitlink_path)) == NULL) {
		error = -1;
		goto out;
	}

	if ((error = git3_fs_path_prettify_dir(&gitdir, dir, NULL)) < 0)
		goto out;
	wt->gitdir_path = git3_str_detach(&gitdir);

	if ((error = git3_worktree_is_locked(NULL, wt)) < 0)
		goto out;
	wt->locked = !!error;
	error = 0;

	*out = wt;

out:
	if (error)
		git3_worktree_free(wt);
	git3_str_dispose(&gitdir);

	return error;
}

int git3_worktree_lookup(git3_worktree **out, git3_repository *repo, const char *name)
{
	git3_str path = GIT3_STR_INIT;
	git3_worktree *wt = NULL;
	int error;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(name);

	*out = NULL;

	if ((error = git3_str_join3(&path, '/', repo->commondir, "worktrees", name)) < 0)
		goto out;

	if (!git3_fs_path_isdir(path.ptr)) {
		error = GIT3_ENOTFOUND;
		goto out;
	}

	if ((error = (open_worktree_dir(out, git3_repository_workdir(repo), path.ptr, name))) < 0)
		goto out;

out:
	git3_str_dispose(&path);

	if (error)
		git3_worktree_free(wt);

	return error;
}

int git3_worktree_open_from_repository(git3_worktree **out, git3_repository *repo)
{
	git3_str parent = GIT3_STR_INIT;
	const char *gitdir, *commondir;
	char *name = NULL;
	int error = 0;

	if (!git3_repository_is_worktree(repo)) {
		git3_error_set(GIT3_ERROR_WORKTREE, "cannot open worktree of a non-worktree repo");
		error = -1;
		goto out;
	}

	gitdir = git3_repository_path(repo);
	commondir = git3_repository_commondir(repo);

	if ((error = git3_fs_path_prettify_dir(&parent, "..", commondir)) < 0)
		goto out;

	/* The name is defined by the last component in '.git/worktree/%s' */
	name = git3_fs_path_basename(gitdir);

	if ((error = open_worktree_dir(out, parent.ptr, gitdir, name)) < 0)
		goto out;

out:
	git3__free(name);
	git3_str_dispose(&parent);

	return error;
}

void git3_worktree_free(git3_worktree *wt)
{
	if (!wt)
		return;

	git3__free(wt->commondir_path);
	git3__free(wt->worktree_path);
	git3__free(wt->gitlink_path);
	git3__free(wt->gitdir_path);
	git3__free(wt->parent_path);
	git3__free(wt->name);
	git3__free(wt);
}

int git3_worktree_validate(const git3_worktree *wt)
{
	GIT3_ASSERT_ARG(wt);

	if (!is_worktree_dir(wt->gitdir_path)) {
		git3_error_set(GIT3_ERROR_WORKTREE,
			"worktree gitdir ('%s') is not valid",
			wt->gitlink_path);
		return GIT3_ERROR;
	}

	if (wt->parent_path && !git3_fs_path_exists(wt->parent_path)) {
		git3_error_set(GIT3_ERROR_WORKTREE,
			"worktree parent directory ('%s') does not exist ",
			wt->parent_path);
		return GIT3_ERROR;
	}

	if (!git3_fs_path_exists(wt->commondir_path)) {
		git3_error_set(GIT3_ERROR_WORKTREE,
			"worktree common directory ('%s') does not exist ",
			wt->commondir_path);
		return GIT3_ERROR;
	}

	if (!git3_fs_path_exists(wt->worktree_path)) {
		git3_error_set(GIT3_ERROR_WORKTREE,
			"worktree directory '%s' does not exist",
			wt->worktree_path);
		return GIT3_ERROR;
	}

	return 0;
}

int git3_worktree_add_options_init(git3_worktree_add_options *opts,
	unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(opts, version,
		git3_worktree_add_options, GIT3_WORKTREE_ADD_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_worktree_add_init_options(git3_worktree_add_options *opts,
	unsigned int version)
{
	return git3_worktree_add_options_init(opts, version);
}
#endif

int git3_worktree_add(git3_worktree **out, git3_repository *repo,
	const char *name, const char *worktree,
	const git3_worktree_add_options *opts)
{
	git3_str gitdir = GIT3_STR_INIT, wddir = GIT3_STR_INIT, buf = GIT3_STR_INIT;
	git3_reference *ref = NULL, *head = NULL;
	git3_commit *commit = NULL;
	git3_repository *wt = NULL;
	git3_checkout_options coopts;
	git3_worktree_add_options wtopts = GIT3_WORKTREE_ADD_OPTIONS_INIT;
	int err;

	GIT3_ERROR_CHECK_VERSION(
		opts, GIT3_WORKTREE_ADD_OPTIONS_VERSION, "git3_worktree_add_options");

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(name);
	GIT3_ASSERT_ARG(worktree);

	*out = NULL;

	if (opts)
		memcpy(&wtopts, opts, sizeof(wtopts));

	memcpy(&coopts, &wtopts.checkout_options, sizeof(coopts));

	if (wtopts.ref) {
		if (!git3_reference_is_branch(wtopts.ref)) {
			git3_error_set(GIT3_ERROR_WORKTREE, "reference is not a branch");
			err = -1;
			goto out;
		}

		if ((err = git3_reference_dup(&ref, wtopts.ref)) < 0)
			goto out;
	} else if (wtopts.checkout_existing && git3_branch_lookup(&ref, repo, name, GIT3_BRANCH_LOCAL) == 0) {
		/* Do nothing */
	} else if ((err = git3_repository_head(&head, repo)) < 0 ||
		   (err = git3_commit_lookup(&commit, repo, &head->target.oid)) < 0 ||
		   (err = git3_branch_create(&ref, repo, name, commit, false)) < 0) {
			goto out;
	}

	if (git3_branch_is_checked_out(ref)) {
		git3_error_set(GIT3_ERROR_WORKTREE, "reference %s is already checked out",
			      git3_reference_name(ref));
		err = -1;
		goto out;
	}

	/* Create gitdir directory ".git/worktrees/<name>" */
	if ((err = git3_str_joinpath(&gitdir, repo->commondir, "worktrees")) < 0)
		goto out;
	if (!git3_fs_path_exists(gitdir.ptr))
		if ((err = git3_futils_mkdir(gitdir.ptr, 0755, GIT3_MKDIR_EXCL)) < 0)
			goto out;
	if ((err = git3_str_joinpath(&gitdir, gitdir.ptr, name)) < 0)
		goto out;
	if ((err = git3_futils_mkdir(gitdir.ptr, 0755, GIT3_MKDIR_EXCL)) < 0)
		goto out;
	if ((err = git3_fs_path_prettify_dir(&gitdir, gitdir.ptr, NULL)) < 0)
		goto out;

	/* Create worktree work dir */
	if ((err = git3_futils_mkdir(worktree, 0755, GIT3_MKDIR_EXCL)) < 0)
		goto out;
	if ((err = git3_fs_path_prettify_dir(&wddir, worktree, NULL)) < 0)
		goto out;

	if (wtopts.lock) {
		int fd;

		if ((err = git3_str_joinpath(&buf, gitdir.ptr, "locked")) < 0)
			goto out;

		if ((fd = p_creat(buf.ptr, 0644)) < 0) {
			err = fd;
			goto out;
		}

		p_close(fd);
		git3_str_clear(&buf);
	}

	/* Create worktree .git file */
	if ((err = git3_str_printf(&buf, "gitdir: %s\n", gitdir.ptr)) < 0)
		goto out;
	if ((err = write_wtfile(wddir.ptr, ".git", &buf)) < 0)
		goto out;

	/* Create gitdir files */
	if ((err = git3_fs_path_prettify_dir(&buf, repo->commondir, NULL) < 0)
	    || (err = git3_str_putc(&buf, '\n')) < 0
	    || (err = write_wtfile(gitdir.ptr, "commondir", &buf)) < 0)
		goto out;
	if ((err = git3_str_joinpath(&buf, wddir.ptr, ".git")) < 0
	    || (err = git3_str_putc(&buf, '\n')) < 0
	    || (err = write_wtfile(gitdir.ptr, "gitdir", &buf)) < 0)
		goto out;

	/* Set worktree's HEAD */
	if ((err = git3_repository_create_head(gitdir.ptr, git3_reference_name(ref))) < 0)
		goto out;
	if ((err = git3_repository_open(&wt, wddir.ptr)) < 0)
		goto out;

	/* Checkout worktree's HEAD */
	if ((err = git3_checkout_head(wt, &coopts)) < 0)
		goto out;

	/* Load result */
	if ((err = git3_worktree_lookup(out, repo, name)) < 0)
		goto out;

out:
	git3_str_dispose(&gitdir);
	git3_str_dispose(&wddir);
	git3_str_dispose(&buf);
	git3_reference_free(ref);
	git3_reference_free(head);
	git3_commit_free(commit);
	git3_repository_free(wt);

	return err;
}

int git3_worktree_lock(git3_worktree *wt, const char *reason)
{
	git3_str buf = GIT3_STR_INIT, path = GIT3_STR_INIT;
	int error;

	GIT3_ASSERT_ARG(wt);

	if ((error = git3_worktree_is_locked(NULL, wt)) < 0)
		goto out;
	if (error) {
		error = GIT3_ELOCKED;
		goto out;
	}

	if ((error = git3_str_joinpath(&path, wt->gitdir_path, "locked")) < 0)
		goto out;

	if (reason)
		git3_str_attach_notowned(&buf, reason, strlen(reason));

	if ((error = git3_futils_writebuffer(&buf, path.ptr, O_CREAT|O_EXCL|O_WRONLY, 0644)) < 0)
		goto out;

	wt->locked = 1;

out:
	git3_str_dispose(&path);

	return error;
}

int git3_worktree_unlock(git3_worktree *wt)
{
	git3_str path = GIT3_STR_INIT;
	int error;

	GIT3_ASSERT_ARG(wt);

	if ((error = git3_worktree_is_locked(NULL, wt)) < 0)
		return error;
	if (!error)
		return 1;

	if (git3_str_joinpath(&path, wt->gitdir_path, "locked") < 0)
		return -1;

	if (p_unlink(path.ptr) != 0) {
		git3_str_dispose(&path);
		return -1;
	}

	wt->locked = 0;

	git3_str_dispose(&path);

	return 0;
}

static int git3_worktree__is_locked(git3_str *reason, const git3_worktree *wt)
{
	git3_str path = GIT3_STR_INIT;
	int error, locked;

	GIT3_ASSERT_ARG(wt);

	if (reason)
		git3_str_clear(reason);

	if ((error = git3_str_joinpath(&path, wt->gitdir_path, "locked")) < 0)
		goto out;
	locked = git3_fs_path_exists(path.ptr);
	if (locked && reason &&
	    (error = git3_futils_readbuffer(reason, path.ptr)) < 0)
		goto out;

	error = locked;
out:
	git3_str_dispose(&path);

	return error;
}

int git3_worktree_is_locked(git3_buf *reason, const git3_worktree *wt)
{
	git3_str str = GIT3_STR_INIT;
	int error = 0;

	if (reason && (error = git3_buf_tostr(&str, reason)) < 0)
		return error;

	error = git3_worktree__is_locked(reason ? &str : NULL, wt);

	if (error >= 0 && reason) {
		if (git3_buf_fromstr(reason, &str) < 0)
			error = -1;
	}

	git3_str_dispose(&str);
	return error;
}

const char *git3_worktree_name(const git3_worktree *wt)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(wt, NULL);
	return wt->name;
}

const char *git3_worktree_path(const git3_worktree *wt)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(wt, NULL);
	return wt->worktree_path;
}

int git3_worktree_prune_options_init(
	git3_worktree_prune_options *opts,
	unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(opts, version,
		git3_worktree_prune_options, GIT3_WORKTREE_PRUNE_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_worktree_prune_init_options(git3_worktree_prune_options *opts,
	unsigned int version)
{
	return git3_worktree_prune_options_init(opts, version);
}
#endif

int git3_worktree_is_prunable(git3_worktree *wt,
	git3_worktree_prune_options *opts)
{
	git3_worktree_prune_options popts = GIT3_WORKTREE_PRUNE_OPTIONS_INIT;
	git3_str path = GIT3_STR_INIT;
	int ret = 0;

	GIT3_ERROR_CHECK_VERSION(
		opts, GIT3_WORKTREE_PRUNE_OPTIONS_VERSION,
		"git3_worktree_prune_options");

	if (opts)
		memcpy(&popts, opts, sizeof(popts));

	if ((popts.flags & GIT3_WORKTREE_PRUNE_LOCKED) == 0) {
		git3_str reason = GIT3_STR_INIT;

		if ((ret = git3_worktree__is_locked(&reason, wt)) < 0)
			goto out;

		if (ret) {
			git3_error_set(GIT3_ERROR_WORKTREE,
				"not pruning locked working tree: '%s'",
				reason.size ?  reason.ptr : "is locked");

			git3_str_dispose(&reason);
			ret = 0;
			goto out;
		}
	}

	if ((popts.flags & GIT3_WORKTREE_PRUNE_VALID) == 0 &&
	    git3_worktree_validate(wt) == 0) {
		git3_error_set(GIT3_ERROR_WORKTREE, "not pruning valid working tree");
		goto out;
	}

	if ((ret = git3_str_printf(&path, "%s/worktrees/%s", wt->commondir_path, wt->name) < 0))
		goto out;

	if (!git3_fs_path_exists(path.ptr)) {
		git3_error_set(GIT3_ERROR_WORKTREE, "worktree gitdir ('%s') does not exist", path.ptr);
		goto out;
	}

	ret = 1;

out:
	git3_str_dispose(&path);
	return ret;
}

int git3_worktree_prune(git3_worktree *wt,
	git3_worktree_prune_options *opts)
{
	git3_worktree_prune_options popts = GIT3_WORKTREE_PRUNE_OPTIONS_INIT;
	git3_str path = GIT3_STR_INIT;
	char *wtpath;
	int err;

	GIT3_ERROR_CHECK_VERSION(
		opts, GIT3_WORKTREE_PRUNE_OPTIONS_VERSION,
		"git3_worktree_prune_options");

	if (opts)
		memcpy(&popts, opts, sizeof(popts));

	if (!git3_worktree_is_prunable(wt, &popts)) {
		err = -1;
		goto out;
	}

	/* Delete gitdir in parent repository */
	if ((err = git3_str_join3(&path, '/', wt->commondir_path, "worktrees", wt->name)) < 0)
		goto out;
	if (!git3_fs_path_exists(path.ptr))
	{
		git3_error_set(GIT3_ERROR_WORKTREE, "worktree gitdir '%s' does not exist", path.ptr);
		err = -1;
		goto out;
	}
	if ((err = git3_futils_rmdir_r(path.ptr, NULL, GIT3_RMDIR_REMOVE_FILES)) < 0)
		goto out;

	/* Skip deletion of the actual working tree if it does
	 * not exist or deletion was not requested */
	if ((popts.flags & GIT3_WORKTREE_PRUNE_WORKING_TREE) == 0 ||
		!git3_fs_path_exists(wt->gitlink_path))
	{
		goto out;
	}

	if ((wtpath = git3_fs_path_dirname(wt->gitlink_path)) == NULL)
		goto out;
	git3_str_attach(&path, wtpath, 0);
	if (!git3_fs_path_exists(path.ptr))
	{
		git3_error_set(GIT3_ERROR_WORKTREE, "working tree '%s' does not exist", path.ptr);
		err = -1;
		goto out;
	}
	if ((err = git3_futils_rmdir_r(path.ptr, NULL, GIT3_RMDIR_REMOVE_FILES)) < 0)
		goto out;

out:
	git3_str_dispose(&path);

	return err;
}
