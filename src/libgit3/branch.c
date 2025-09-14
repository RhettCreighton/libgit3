/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "branch.h"

#include "buf.h"
#include "commit.h"
#include "tag.h"
#include "config.h"
#include "refspec.h"
#include "refs.h"
#include "remote.h"
#include "annotated_commit.h"
#include "worktree.h"

#include "git3/branch.h"

static int retrieve_branch_reference(
	git3_reference **branch_reference_out,
	git3_repository *repo,
	const char *branch_name,
	bool is_remote)
{
	git3_reference *branch = NULL;
	int error = 0;
	char *prefix;
	git3_str ref_name = GIT3_STR_INIT;

	prefix = is_remote ? GIT3_REFS_REMOTES_DIR : GIT3_REFS_HEADS_DIR;

	if ((error = git3_str_joinpath(&ref_name, prefix, branch_name)) < 0)
		/* OOM */;
	else if ((error = git3_reference_lookup(&branch, repo, ref_name.ptr)) < 0)
		git3_error_set(
			GIT3_ERROR_REFERENCE, "cannot locate %s branch '%s'",
			is_remote ? "remote-tracking" : "local", branch_name);

	*branch_reference_out = branch; /* will be NULL on error */

	git3_str_dispose(&ref_name);
	return error;
}

static int not_a_local_branch(const char *reference_name)
{
	git3_error_set(
		GIT3_ERROR_INVALID,
		"reference '%s' is not a local branch.", reference_name);
	return -1;
}

static bool branch_name_is_valid(const char *branch_name)
{
	/*
	 * Discourage branch name starting with dash,
	 * https://github.com/git/git/commit/6348624010888b
	 * and discourage HEAD as branch name,
	 * https://github.com/git/git/commit/a625b092cc5994
	 */
	return branch_name[0] != '-' && git3__strcmp(branch_name, "HEAD");
}

static int create_branch(
	git3_reference **ref_out,
	git3_repository *repository,
	const char *branch_name,
	const git3_commit *commit,
	const char *from,
	int force)
{
	int is_unmovable_head = 0;
	git3_reference *branch = NULL;
	git3_str canonical_branch_name = GIT3_STR_INIT,
			  log_message = GIT3_STR_INIT;
	int error = -1;
	int bare = git3_repository_is_bare(repository);

	GIT3_ASSERT_ARG(branch_name);
	GIT3_ASSERT_ARG(commit);
	GIT3_ASSERT_ARG(ref_out);
	GIT3_ASSERT_ARG(git3_commit_owner(commit) == repository);

	if (!branch_name_is_valid(branch_name)) {
		git3_error_set(GIT3_ERROR_REFERENCE, "'%s' is not a valid branch name", branch_name);
		error = -1;
		goto cleanup;
	}

	if (force && !bare && git3_branch_lookup(&branch, repository, branch_name, GIT3_BRANCH_LOCAL) == 0) {
		error = git3_branch_is_head(branch);
		git3_reference_free(branch);
		branch = NULL;

		if (error < 0)
			goto cleanup;

		is_unmovable_head = error;
	}

	if (is_unmovable_head && force) {
		git3_error_set(GIT3_ERROR_REFERENCE, "cannot force update branch '%s' as it is "
			"the current HEAD of the repository.", branch_name);
		error = -1;
		goto cleanup;
	}

	if (git3_str_joinpath(&canonical_branch_name, GIT3_REFS_HEADS_DIR, branch_name) < 0)
		goto cleanup;

	if (git3_str_printf(&log_message, "branch: Created from %s", from) < 0)
		goto cleanup;

	error = git3_reference_create(&branch, repository,
		git3_str_cstr(&canonical_branch_name), git3_commit_id(commit), force,
		git3_str_cstr(&log_message));

	if (!error)
		*ref_out = branch;

cleanup:
	git3_str_dispose(&canonical_branch_name);
	git3_str_dispose(&log_message);
	return error;
}

int git3_branch_create(
	git3_reference **ref_out,
	git3_repository *repository,
	const char *branch_name,
	const git3_commit *commit,
	int force)
{
	char commit_id[GIT3_OID_MAX_HEXSIZE + 1];

	git3_oid_tostr(commit_id, GIT3_OID_MAX_HEXSIZE + 1, git3_commit_id(commit));
	return create_branch(ref_out, repository, branch_name, commit, commit_id, force);
}

int git3_branch_create_from_annotated(
	git3_reference **ref_out,
	git3_repository *repository,
	const char *branch_name,
	const git3_annotated_commit *commit,
	int force)
{
	return create_branch(ref_out,
		repository, branch_name, commit->commit, commit->description, force);
}

static int branch_is_checked_out(git3_repository *worktree, void *payload)
{
	git3_reference *branch = (git3_reference *) payload;
	git3_reference *head = NULL;
	int error;

	if (git3_repository_is_bare(worktree))
		return 0;

	if ((error = git3_reference_lookup(&head, worktree, GIT3_HEAD_FILE)) < 0) {
		if (error == GIT3_ENOTFOUND)
			error = 0;
		goto out;
	}

	if (git3_reference_type(head) != GIT3_REFERENCE_SYMBOLIC)
		goto out;

	error = !git3__strcmp(head->target.symbolic, branch->name);

out:
	git3_reference_free(head);
	return error;
}

int git3_branch_is_checked_out(const git3_reference *branch)
{
	GIT3_ASSERT_ARG(branch);

	if (!git3_reference_is_branch(branch))
		return 0;
	return git3_repository_foreach_worktree(git3_reference_owner(branch),
					       branch_is_checked_out, (void *)branch) == 1;
}

int git3_branch_delete(git3_reference *branch)
{
	int is_head;
	git3_str config_section = GIT3_STR_INIT;
	int error = -1;

	GIT3_ASSERT_ARG(branch);

	if (!git3_reference_is_branch(branch) && !git3_reference_is_remote(branch)) {
		git3_error_set(GIT3_ERROR_INVALID, "reference '%s' is not a valid branch.",
			git3_reference_name(branch));
		return GIT3_ENOTFOUND;
	}

	if ((is_head = git3_branch_is_head(branch)) < 0)
		return is_head;

	if (is_head) {
		git3_error_set(GIT3_ERROR_REFERENCE, "cannot delete branch '%s' as it is "
			"the current HEAD of the repository.", git3_reference_name(branch));
		return -1;
	}

	if (git3_reference_is_branch(branch) && git3_branch_is_checked_out(branch)) {
		git3_error_set(GIT3_ERROR_REFERENCE, "Cannot delete branch '%s' as it is "
			"the current HEAD of a linked repository.", git3_reference_name(branch));
		return -1;
	}

	if (git3_str_join(&config_section, '.', "branch",
			git3_reference_name(branch) + strlen(GIT3_REFS_HEADS_DIR)) < 0)
		goto on_error;

	if (git3_config_rename_section(
		git3_reference_owner(branch), git3_str_cstr(&config_section), NULL) < 0)
		goto on_error;

	error = git3_reference_delete(branch);

on_error:
	git3_str_dispose(&config_section);
	return error;
}

typedef struct {
	git3_reference_iterator *iter;
	unsigned int flags;
} branch_iter;

int git3_branch_next(git3_reference **out, git3_branch_t *out_type, git3_branch_iterator *_iter)
{
	branch_iter *iter = (branch_iter *) _iter;
	git3_reference *ref;
	int error;

	while ((error = git3_reference_next(&ref, iter->iter)) == 0) {
		if ((iter->flags & GIT3_BRANCH_LOCAL) &&
		    !git3__prefixcmp(ref->name, GIT3_REFS_HEADS_DIR)) {
			*out = ref;
			*out_type = GIT3_BRANCH_LOCAL;

			return 0;
		} else  if ((iter->flags & GIT3_BRANCH_REMOTE) &&
			    !git3__prefixcmp(ref->name, GIT3_REFS_REMOTES_DIR)) {
			*out = ref;
			*out_type = GIT3_BRANCH_REMOTE;

			return 0;
		} else {
			git3_reference_free(ref);
		}
	}

	return error;
}

int git3_branch_iterator_new(
	git3_branch_iterator **out,
	git3_repository *repo,
	git3_branch_t list_flags)
{
	branch_iter *iter;

	iter = git3__calloc(1, sizeof(branch_iter));
	GIT3_ERROR_CHECK_ALLOC(iter);

	iter->flags = list_flags;

	if (git3_reference_iterator_new(&iter->iter, repo) < 0) {
		git3__free(iter);
		return -1;
	}

	*out = (git3_branch_iterator *) iter;

	return 0;
}

void git3_branch_iterator_free(git3_branch_iterator *_iter)
{
	branch_iter *iter = (branch_iter *) _iter;

	if (iter == NULL)
		return;

	git3_reference_iterator_free(iter->iter);
	git3__free(iter);
}

int git3_branch_move(
	git3_reference **out,
	git3_reference *branch,
	const char *new_branch_name,
	int force)
{
	git3_str new_reference_name = GIT3_STR_INIT,
	        old_config_section = GIT3_STR_INIT,
	        new_config_section = GIT3_STR_INIT,
	        log_message = GIT3_STR_INIT;
	int error;

	GIT3_ASSERT_ARG(branch);
	GIT3_ASSERT_ARG(new_branch_name);

	if (!git3_reference_is_branch(branch))
		return not_a_local_branch(git3_reference_name(branch));

	if ((error = git3_str_joinpath(&new_reference_name, GIT3_REFS_HEADS_DIR, new_branch_name)) < 0)
		goto done;

	if ((error = git3_str_printf(&log_message, "branch: renamed %s to %s",
				    git3_reference_name(branch), git3_str_cstr(&new_reference_name))) < 0)
			goto done;

	/* first update ref then config so failure won't trash config */

	error = git3_reference_rename(
		out, branch, git3_str_cstr(&new_reference_name), force,
		git3_str_cstr(&log_message));
	if (error < 0)
		goto done;

	git3_str_join(&old_config_section, '.', "branch",
		git3_reference_name(branch) + strlen(GIT3_REFS_HEADS_DIR));
	git3_str_join(&new_config_section, '.', "branch", new_branch_name);

	error = git3_config_rename_section(
		git3_reference_owner(branch),
		git3_str_cstr(&old_config_section),
		git3_str_cstr(&new_config_section));

done:
	git3_str_dispose(&new_reference_name);
	git3_str_dispose(&old_config_section);
	git3_str_dispose(&new_config_section);
	git3_str_dispose(&log_message);

	return error;
}

int git3_branch_lookup(
	git3_reference **ref_out,
	git3_repository *repo,
	const char *branch_name,
	git3_branch_t branch_type)
{
	int error = -1;

	GIT3_ASSERT_ARG(ref_out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(branch_name);

	switch (branch_type) {
	case GIT3_BRANCH_LOCAL:
	case GIT3_BRANCH_REMOTE:
		error = retrieve_branch_reference(ref_out, repo, branch_name, branch_type == GIT3_BRANCH_REMOTE);
		break;
	case GIT3_BRANCH_ALL:
		error = retrieve_branch_reference(ref_out, repo, branch_name, false);
		if (error == GIT3_ENOTFOUND)
			error = retrieve_branch_reference(ref_out, repo, branch_name, true);
		break;
	default:
		GIT3_ASSERT(false);
	}
	return error;
}

int git3_branch_name(
	const char **out,
	const git3_reference *ref)
{
	const char *branch_name;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(ref);

	branch_name = ref->name;

	if (git3_reference_is_branch(ref)) {
		branch_name += strlen(GIT3_REFS_HEADS_DIR);
	} else if (git3_reference_is_remote(ref)) {
		branch_name += strlen(GIT3_REFS_REMOTES_DIR);
	} else {
		git3_error_set(GIT3_ERROR_INVALID,
				"reference '%s' is neither a local nor a remote branch.", ref->name);
		return -1;
	}
	*out = branch_name;
	return 0;
}

static int retrieve_upstream_configuration(
	git3_str *out,
	const git3_config *config,
	const char *canonical_branch_name,
	const char *format)
{
	git3_str buf = GIT3_STR_INIT;
	int error;

	if (git3_str_printf(&buf, format,
		canonical_branch_name + strlen(GIT3_REFS_HEADS_DIR)) < 0)
			return -1;

	error = git3_config__get_string_buf(out, config, git3_str_cstr(&buf));
	git3_str_dispose(&buf);
	return error;
}

int git3_branch_upstream_name(
	git3_buf *out,
	git3_repository *repo,
	const char *refname)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_branch__upstream_name, repo, refname);
}

int git3_branch__upstream_name(
	git3_str *out,
	git3_repository *repo,
	const char *refname)
{
	git3_str remote_name = GIT3_STR_INIT;
	git3_str merge_name = GIT3_STR_INIT;
	git3_str buf = GIT3_STR_INIT;
	int error = -1;
	git3_remote *remote = NULL;
	const git3_refspec *refspec;
	git3_config *config;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(refname);

	if (!git3_reference__is_branch(refname))
		return not_a_local_branch(refname);

	if ((error = git3_repository_config_snapshot(&config, repo)) < 0)
		return error;

	if ((error = retrieve_upstream_configuration(
		&remote_name, config, refname, "branch.%s.remote")) < 0)
			goto cleanup;

	if ((error = retrieve_upstream_configuration(
		&merge_name, config, refname, "branch.%s.merge")) < 0)
			goto cleanup;

	if (git3_str_len(&remote_name) == 0 || git3_str_len(&merge_name) == 0) {
		git3_error_set(GIT3_ERROR_REFERENCE,
			"branch '%s' does not have an upstream", refname);
		error = GIT3_ENOTFOUND;
		goto cleanup;
	}

	if (strcmp(".", git3_str_cstr(&remote_name)) != 0) {
		if ((error = git3_remote_lookup(&remote, repo, git3_str_cstr(&remote_name))) < 0)
			goto cleanup;

		refspec = git3_remote__matching_refspec(remote, git3_str_cstr(&merge_name));
		if (!refspec) {
			error = GIT3_ENOTFOUND;
			goto cleanup;
		}

		if (git3_refspec__transform(&buf, refspec, git3_str_cstr(&merge_name)) < 0)
			goto cleanup;
	} else
		if (git3_str_set(&buf, git3_str_cstr(&merge_name), git3_str_len(&merge_name)) < 0)
			goto cleanup;

	git3_str_swap(out, &buf);

cleanup:
	git3_config_free(config);
	git3_remote_free(remote);
	git3_str_dispose(&remote_name);
	git3_str_dispose(&merge_name);
	git3_str_dispose(&buf);
	return error;
}

static int git3_branch_upstream_with_format(
	git3_str *out,
	git3_repository *repo,
	const char *refname,
	const char *format,
	const char *format_name)
{
	git3_config *cfg;
	int error;

	if (!git3_reference__is_branch(refname))
		return not_a_local_branch(refname);

	if ((error = git3_repository_config__weakptr(&cfg, repo)) < 0 ||
	    (error = retrieve_upstream_configuration(out, cfg, refname, format)) < 0)
		return error;

	if (git3_str_len(out) == 0) {
		git3_error_set(GIT3_ERROR_REFERENCE, "branch '%s' does not have an upstream %s", refname, format_name);
		error = GIT3_ENOTFOUND;
	}

	return error;
}

int git3_branch_upstream_remote(
	git3_buf *out,
	git3_repository *repo,
	const char *refname)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_branch__upstream_remote, repo, refname);
}

int git3_branch__upstream_remote(
	git3_str *out,
	git3_repository *repo,
	const char *refname)
{
	return git3_branch_upstream_with_format(out, repo, refname, "branch.%s.remote", "remote");
}

int git3_branch_upstream_merge(
	git3_buf *out,
	git3_repository *repo,
	const char *refname)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_branch__upstream_merge, repo, refname);
}

int git3_branch__upstream_merge(
	git3_str *out,
	git3_repository *repo,
	const char *refname)
{
	return git3_branch_upstream_with_format(out, repo, refname, "branch.%s.merge", "merge");
}

int git3_branch_remote_name(
	git3_buf *out,
	git3_repository *repo,
	const char *refname)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_branch__remote_name, repo, refname);
}

int git3_branch__remote_name(
	git3_str *out,
	git3_repository *repo,
	const char *refname)
{
	git3_strarray remote_list = {0};
	size_t i;
	git3_remote *remote;
	const git3_refspec *fetchspec;
	int error = 0;
	char *remote_name = NULL;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(refname);

	/* Verify that this is a remote branch */
	if (!git3_reference__is_remote(refname)) {
		git3_error_set(GIT3_ERROR_INVALID, "reference '%s' is not a remote branch.",
			refname);
		error = GIT3_ERROR;
		goto cleanup;
	}

	/* Get the remotes */
	if ((error = git3_remote_list(&remote_list, repo)) < 0)
		goto cleanup;

	/* Find matching remotes */
	for (i = 0; i < remote_list.count; i++) {
		if ((error = git3_remote_lookup(&remote, repo, remote_list.strings[i])) < 0)
			continue;

		fetchspec = git3_remote__matching_dst_refspec(remote, refname);
		if (fetchspec) {
			/* If we have not already set out yet, then set
			 * it to the matching remote name. Otherwise
			 * multiple remotes match this reference, and it
			 * is ambiguous. */
			if (!remote_name) {
				remote_name = remote_list.strings[i];
			} else {
				git3_remote_free(remote);

				git3_error_set(GIT3_ERROR_REFERENCE,
					"reference '%s' is ambiguous", refname);
				error = GIT3_EAMBIGUOUS;
				goto cleanup;
			}
		}

		git3_remote_free(remote);
	}

	if (remote_name) {
		git3_str_clear(out);
		error = git3_str_puts(out, remote_name);
	} else {
		git3_error_set(GIT3_ERROR_REFERENCE,
			"could not determine remote for '%s'", refname);
		error = GIT3_ENOTFOUND;
	}

cleanup:
	if (error < 0)
		git3_str_dispose(out);

	git3_strarray_dispose(&remote_list);
	return error;
}

int git3_branch_upstream(
	git3_reference **tracking_out,
	const git3_reference *branch)
{
	int error;
	git3_str tracking_name = GIT3_STR_INIT;

	if ((error = git3_branch__upstream_name(&tracking_name,
		git3_reference_owner(branch), git3_reference_name(branch))) < 0)
			return error;

	error = git3_reference_lookup(
		tracking_out,
		git3_reference_owner(branch),
		git3_str_cstr(&tracking_name));

	git3_str_dispose(&tracking_name);
	return error;
}

static int unset_upstream(git3_config *config, const char *shortname)
{
	git3_str buf = GIT3_STR_INIT;

	if (git3_str_printf(&buf, "branch.%s.remote", shortname) < 0)
		return -1;

	if (git3_config_delete_entry(config, git3_str_cstr(&buf)) < 0)
		goto on_error;

	git3_str_clear(&buf);
	if (git3_str_printf(&buf, "branch.%s.merge", shortname) < 0)
		goto on_error;

	if (git3_config_delete_entry(config, git3_str_cstr(&buf)) < 0)
		goto on_error;

	git3_str_dispose(&buf);
	return 0;

on_error:
	git3_str_dispose(&buf);
	return -1;
}

int git3_branch_set_upstream(git3_reference *branch, const char *branch_name)
{
	git3_str key = GIT3_STR_INIT, remote_name = GIT3_STR_INIT, merge_refspec = GIT3_STR_INIT;
	git3_reference *upstream;
	git3_repository *repo;
	git3_remote *remote = NULL;
	git3_config *config;
	const char *refname, *shortname;
	int local, error;
	const git3_refspec *fetchspec;

	refname = git3_reference_name(branch);
	if (!git3_reference__is_branch(refname))
		return not_a_local_branch(refname);

	if (git3_repository_config__weakptr(&config, git3_reference_owner(branch)) < 0)
		return -1;

	shortname = refname + strlen(GIT3_REFS_HEADS_DIR);

	/* We're unsetting, delegate and bail-out */
	if (branch_name == NULL)
		return unset_upstream(config, shortname);

	repo = git3_reference_owner(branch);

	/* First we need to resolve name to a branch */
	if (git3_branch_lookup(&upstream, repo, branch_name, GIT3_BRANCH_LOCAL) == 0)
		local = 1;
	else if (git3_branch_lookup(&upstream, repo, branch_name, GIT3_BRANCH_REMOTE) == 0)
		local = 0;
	else {
		git3_error_set(GIT3_ERROR_REFERENCE,
			"cannot set upstream for branch '%s'", shortname);
		return GIT3_ENOTFOUND;
	}

	/*
	 * If it's a local-tracking branch, its remote is "." (as "the local
	 * repository"), and the branch name is simply the refname.
	 * Otherwise we need to figure out what the remote-tracking branch's
	 * name on the remote is and use that.
	 */
	if (local)
		error = git3_str_puts(&remote_name, ".");
	else
		error = git3_branch__remote_name(&remote_name, repo, git3_reference_name(upstream));

	if (error < 0)
		goto on_error;

	/* Update the upstream branch config with the new name */
	if (git3_str_printf(&key, "branch.%s.remote", shortname) < 0)
		goto on_error;

	if (git3_config_set_string(config, git3_str_cstr(&key), git3_str_cstr(&remote_name)) < 0)
		goto on_error;

	if (local) {
		/* A local branch uses the upstream refname directly */
		if (git3_str_puts(&merge_refspec, git3_reference_name(upstream)) < 0)
			goto on_error;
	} else {
		/* We transform the upstream branch name according to the remote's refspecs */
		if (git3_remote_lookup(&remote, repo, git3_str_cstr(&remote_name)) < 0)
			goto on_error;

		fetchspec = git3_remote__matching_dst_refspec(remote, git3_reference_name(upstream));
		if (!fetchspec || git3_refspec__rtransform(&merge_refspec, fetchspec, git3_reference_name(upstream)) < 0)
			goto on_error;

		git3_remote_free(remote);
		remote = NULL;
	}

	/* Update the merge branch config with the refspec */
	git3_str_clear(&key);
	if (git3_str_printf(&key, "branch.%s.merge", shortname) < 0)
		goto on_error;

	if (git3_config_set_string(config, git3_str_cstr(&key), git3_str_cstr(&merge_refspec)) < 0)
		goto on_error;

	git3_reference_free(upstream);
	git3_str_dispose(&key);
	git3_str_dispose(&remote_name);
	git3_str_dispose(&merge_refspec);

	return 0;

on_error:
	git3_reference_free(upstream);
	git3_str_dispose(&key);
	git3_str_dispose(&remote_name);
	git3_str_dispose(&merge_refspec);
	git3_remote_free(remote);

	return -1;
}

int git3_branch_is_head(
		const git3_reference *branch)
{
	git3_reference *head;
	bool is_same = false;
	int error;

	GIT3_ASSERT_ARG(branch);

	if (!git3_reference_is_branch(branch))
		return false;

	error = git3_repository_head(&head, git3_reference_owner(branch));

	if (error == GIT3_EUNBORNBRANCH || error == GIT3_ENOTFOUND)
		return false;

	if (error < 0)
		return -1;

	is_same = strcmp(
		git3_reference_name(branch),
		git3_reference_name(head)) == 0;

	git3_reference_free(head);

	return is_same;
}

int git3_branch_name_is_valid(int *valid, const char *name)
{
	git3_str ref_name = GIT3_STR_INIT;
	int error = 0;

	GIT3_ASSERT(valid);

	*valid = 0;

	if (!name || !branch_name_is_valid(name))
		goto done;

	if ((error = git3_str_puts(&ref_name, GIT3_REFS_HEADS_DIR)) < 0 ||
	    (error = git3_str_puts(&ref_name, name)) < 0)
		goto done;

	error = git3_reference_name_is_valid(valid, ref_name.ptr);

done:
	git3_str_dispose(&ref_name);
	return error;
}
