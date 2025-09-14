/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "ignore.h"

#include "git3/ignore.h"
#include "common.h"
#include "attrcache.h"
#include "fs_path.h"
#include "config.h"
#include "wildmatch.h"
#include "path.h"

#define GIT3_IGNORE_INTERNAL		"[internal]exclude"

#define GIT3_IGNORE_DEFAULT_RULES ".\n..\n.git\n"

/**
 * A negative ignore pattern can negate a positive one without
 * wildcards if it is a basename only and equals the basename of
 * the positive pattern. Thus
 *
 * foo/bar
 * !bar
 *
 * would result in foo/bar being unignored again while
 *
 * moo/foo/bar
 * !foo/bar
 *
 * would do nothing. The reverse also holds true: a positive
 * basename pattern can be negated by unignoring the basename in
 * subdirectories. Thus
 *
 * bar
 * !foo/bar
 *
 * would result in foo/bar being unignored again. As with the
 * first case,
 *
 * foo/bar
 * !moo/foo/bar
 *
 * would do nothing, again.
 */
static int does_negate_pattern(git3_attr_fnmatch *rule, git3_attr_fnmatch *neg)
{
	int (*cmp)(const char *, const char *, size_t);
	git3_attr_fnmatch *longer, *shorter;
	char *p;

	if ((rule->flags & GIT3_ATTR_FNMATCH_NEGATIVE) != 0
	    || (neg->flags & GIT3_ATTR_FNMATCH_NEGATIVE) == 0)
		return false;

	if (neg->flags & GIT3_ATTR_FNMATCH_ICASE)
		cmp = git3__strncasecmp;
	else
		cmp = git3__strncmp;

	/* If lengths match we need to have an exact match */
	if (rule->length == neg->length) {
		return cmp(rule->pattern, neg->pattern, rule->length) == 0;
	} else if (rule->length < neg->length) {
		shorter = rule;
		longer = neg;
	} else {
		shorter = neg;
		longer = rule;
	}

	/* Otherwise, we need to check if the shorter
	 * rule is a basename only (that is, it contains
	 * no path separator) and, if so, if it
	 * matches the tail of the longer rule */
	p = longer->pattern + longer->length - shorter->length;

	if (p[-1] != '/')
		return false;
	if (memchr(shorter->pattern, '/', shorter->length) != NULL)
		return false;

	return cmp(p, shorter->pattern, shorter->length) == 0;
}

/**
 * A negative ignore can only unignore a file which is given explicitly before, thus
 *
 *    foo
 *    !foo/bar
 *
 * does not unignore 'foo/bar' as it's not in the list. However
 *
 *    foo/<star>
 *    !foo/bar
 *
 * does unignore 'foo/bar', as it is contained within the 'foo/<star>' rule.
 */
static int does_negate_rule(int *out, git3_vector *rules, git3_attr_fnmatch *match)
{
	int error = 0, wildmatch_flags, effective_flags;
	size_t i;
	git3_attr_fnmatch *rule;
	char *path;
	git3_str buf = GIT3_STR_INIT;

	*out = 0;

	wildmatch_flags = WM_PATHNAME;
	if (match->flags & GIT3_ATTR_FNMATCH_ICASE)
		wildmatch_flags |= WM_CASEFOLD;

	/* path of the file relative to the workdir, so we match the rules in subdirs */
	if (match->containing_dir) {
		git3_str_puts(&buf, match->containing_dir);
	}
	if (git3_str_puts(&buf, match->pattern) < 0)
		return -1;

	path = git3_str_detach(&buf);

	git3_vector_foreach(rules, i, rule) {
		if (!(rule->flags & GIT3_ATTR_FNMATCH_HASWILD)) {
			if (does_negate_pattern(rule, match)) {
				error = 0;
				*out = 1;
				goto out;
			}
			else
				continue;
		}

		git3_str_clear(&buf);
		if (rule->containing_dir)
			git3_str_puts(&buf, rule->containing_dir);
		git3_str_puts(&buf, rule->pattern);

		if (git3_str_oom(&buf))
			goto out;

		/*
		 * if rule isn't for full path we match without PATHNAME flag
		 * as lines like *.txt should match something like dir/test.txt
		 * requiring * to also match /
		 */
		effective_flags = wildmatch_flags;
		if (!(rule->flags & GIT3_ATTR_FNMATCH_FULLPATH))
			effective_flags &= ~WM_PATHNAME;

		/* if we found a match, we want to keep this rule */
		if ((wildmatch(git3_str_cstr(&buf), path, effective_flags)) == WM_MATCH) {
			*out = 1;
			error = 0;
			goto out;
		}
	}

	error = 0;

out:
	git3__free(path);
	git3_str_dispose(&buf);
	return error;
}

static int parse_ignore_file(
	git3_repository *repo, git3_attr_file *attrs, const char *data, bool allow_macros)
{
	int error = 0;
	int ignore_case = false;
	const char *scan = data, *context = NULL;
	git3_attr_fnmatch *match = NULL;

	GIT3_UNUSED(allow_macros);

	if (git3_repository__configmap_lookup(&ignore_case, repo, GIT3_CONFIGMAP_IGNORECASE) < 0)
		git3_error_clear();

	/* if subdir file path, convert context for file paths */
	if (attrs->entry &&
		git3_fs_path_root(attrs->entry->path) < 0 &&
		!git3__suffixcmp(attrs->entry->path, "/" GIT3_IGNORE_FILE))
		context = attrs->entry->path;

	if (git3_mutex_lock(&attrs->lock) < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to lock ignore file");
		return -1;
	}

	while (!error && *scan) {
		int valid_rule = 1;

		if (!match && !(match = git3__calloc(1, sizeof(*match)))) {
			error = -1;
			break;
		}

		match->flags =
		    GIT3_ATTR_FNMATCH_ALLOWSPACE | GIT3_ATTR_FNMATCH_ALLOWNEG;

		if (!(error = git3_attr_fnmatch__parse(
			match, &attrs->pool, context, &scan)))
		{
			match->flags |= GIT3_ATTR_FNMATCH_IGNORE;

			if (ignore_case)
				match->flags |= GIT3_ATTR_FNMATCH_ICASE;

			scan = git3__next_line(scan);

			/*
			 * If a negative match doesn't actually do anything,
			 * throw it away. As we cannot always verify whether a
			 * rule containing wildcards negates another rule, we
			 * do not optimize away these rules, though.
			 * */
			if (match->flags & GIT3_ATTR_FNMATCH_NEGATIVE
			    && !(match->flags & GIT3_ATTR_FNMATCH_HASWILD))
				error = does_negate_rule(&valid_rule, &attrs->rules, match);

			if (!error && valid_rule)
				error = git3_vector_insert(&attrs->rules, match);
		}

		if (error != 0 || !valid_rule) {
			match->pattern = NULL;

			if (error == GIT3_ENOTFOUND)
				error = 0;
		} else {
			match = NULL; /* vector now "owns" the match */
		}
	}

	git3_mutex_unlock(&attrs->lock);
	git3__free(match);

	return error;
}

static int push_ignore_file(
	git3_ignores *ignores,
	git3_vector *which_list,
	const char *base,
	const char *filename)
{
	git3_attr_file_source source = { GIT3_ATTR_FILE_SOURCE_FILE, base, filename };
	git3_attr_file *file = NULL;
	int error = 0;

	error = git3_attr_cache__get(&file, ignores->repo, NULL, &source, parse_ignore_file, false);

	if (error < 0)
		return error;

	if (file != NULL) {
		if ((error = git3_vector_insert(which_list, file)) < 0)
			git3_attr_file__free(file);
	}

	return error;
}

static int push_one_ignore(void *payload, const char *path)
{
	git3_ignores *ign = payload;
	ign->depth++;
	return push_ignore_file(ign, &ign->ign_path, path, GIT3_IGNORE_FILE);
}

static int get_internal_ignores(git3_attr_file **out, git3_repository *repo)
{
	git3_attr_file_source source = { GIT3_ATTR_FILE_SOURCE_MEMORY, NULL, GIT3_IGNORE_INTERNAL };
	int error;

	if ((error = git3_attr_cache__init(repo)) < 0)
		return error;

	error = git3_attr_cache__get(out, repo, NULL, &source, NULL, false);

	/* if internal rules list is empty, insert default rules */
	if (!error && !(*out)->rules.length)
		error = parse_ignore_file(repo, *out, GIT3_IGNORE_DEFAULT_RULES, false);

	return error;
}

int git3_ignore__for_path(
	git3_repository *repo,
	const char *path,
	git3_ignores *ignores)
{
	int error = 0;
	const char *workdir = git3_repository_workdir(repo);
	git3_attr_cache *attrcache;
	const char *excludes_file = NULL;
	git3_str infopath = GIT3_STR_INIT;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(ignores);
	GIT3_ASSERT_ARG(path);

	memset(ignores, 0, sizeof(*ignores));
	ignores->repo = repo;

	/* Read the ignore_case flag */
	if ((error = git3_repository__configmap_lookup(
			&ignores->ignore_case, repo, GIT3_CONFIGMAP_IGNORECASE)) < 0)
		goto cleanup;

	if ((error = git3_attr_cache__init(repo)) < 0)
		goto cleanup;

	/* given a unrooted path in a non-bare repo, resolve it */
	if (workdir && git3_fs_path_root(path) < 0) {
		git3_str local = GIT3_STR_INIT;

		if ((error = git3_fs_path_dirname_r(&local, path)) < 0 ||
		    (error = git3_fs_path_resolve_relative(&local, 0)) < 0 ||
		    (error = git3_fs_path_to_dir(&local)) < 0 ||
		    (error = git3_str_joinpath(&ignores->dir, workdir, local.ptr)) < 0 ||
		    (error = git3_path_validate_str_length(repo, &ignores->dir)) < 0) {
			/* Nothing, we just want to stop on the first error */
		}

		git3_str_dispose(&local);
	} else {
		if (!(error = git3_str_joinpath(&ignores->dir, path, "")))
		    error = git3_path_validate_str_length(NULL, &ignores->dir);
	}

	if (error < 0)
		goto cleanup;

	if (workdir && !git3__prefixcmp(ignores->dir.ptr, workdir))
		ignores->dir_root = strlen(workdir);

	/* set up internals */
	if ((error = get_internal_ignores(&ignores->ign_internal, repo)) < 0)
		goto cleanup;

	/* load .gitignore up the path */
	if (workdir != NULL) {
		error = git3_fs_path_walk_up(
			&ignores->dir, workdir, push_one_ignore, ignores);
		if (error < 0)
			goto cleanup;
	}

	/* load .git/info/exclude if possible */
	if ((error = git3_repository__item_path(&infopath, repo, GIT3_REPOSITORY_ITEM_INFO)) < 0 ||
		(error = push_ignore_file(ignores, &ignores->ign_global, infopath.ptr, GIT3_IGNORE_FILE_INREPO)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto cleanup;
		error = 0;
	}

	/* load core.excludesfile */
	attrcache = git3_repository_attr_cache(repo);
	excludes_file = git3_attr_cache_excludesfile(attrcache);

	if (excludes_file != NULL)
		error = push_ignore_file(
			ignores, &ignores->ign_global, NULL, excludes_file);

cleanup:
	git3_str_dispose(&infopath);
	if (error < 0)
		git3_ignore__free(ignores);

	return error;
}

int git3_ignore__push_dir(git3_ignores *ign, const char *dir)
{
	if (git3_str_joinpath(&ign->dir, ign->dir.ptr, dir) < 0)
		return -1;

	ign->depth++;

	return push_ignore_file(
		ign, &ign->ign_path, ign->dir.ptr, GIT3_IGNORE_FILE);
}

int git3_ignore__pop_dir(git3_ignores *ign)
{
	if (ign->ign_path.length > 0) {
		git3_attr_file *file = git3_vector_last(&ign->ign_path);
		const char *start = file->entry->path, *end;

		/* - ign->dir looks something like "/home/user/a/b/" (or "a/b/c/d/")
		 * - file->path looks something like "a/b/.gitignore
		 *
		 * We are popping the last directory off ign->dir.  We also want
		 * to remove the file from the vector if the popped directory
		 * matches the ignore path.  We need to test if the "a/b" part of
		 * the file key matches the path we are about to pop.
		 */

		if ((end = strrchr(start, '/')) != NULL) {
			size_t dirlen = (end - start) + 1;
			const char *relpath = ign->dir.ptr + ign->dir_root;
			size_t pathlen = ign->dir.size - ign->dir_root;

			if (pathlen == dirlen && !memcmp(relpath, start, dirlen)) {
				git3_vector_pop(&ign->ign_path);
				git3_attr_file__free(file);
			}
		}
	}

	if (--ign->depth > 0) {
		git3_str_rtruncate_at_char(&ign->dir, '/');
		git3_fs_path_to_dir(&ign->dir);
	}

	return 0;
}

void git3_ignore__free(git3_ignores *ignores)
{
	unsigned int i;
	git3_attr_file *file;

	git3_attr_file__free(ignores->ign_internal);

	git3_vector_foreach(&ignores->ign_path, i, file) {
		git3_attr_file__free(file);
		ignores->ign_path.contents[i] = NULL;
	}
	git3_vector_dispose(&ignores->ign_path);

	git3_vector_foreach(&ignores->ign_global, i, file) {
		git3_attr_file__free(file);
		ignores->ign_global.contents[i] = NULL;
	}
	git3_vector_dispose(&ignores->ign_global);

	git3_str_dispose(&ignores->dir);
}

static bool ignore_lookup_in_rules(
	int *ignored, git3_attr_file *file, git3_attr_path *path)
{
	size_t j;
	git3_attr_fnmatch *match;

	git3_vector_rforeach(&file->rules, j, match) {
		if (match->flags & GIT3_ATTR_FNMATCH_DIRECTORY &&
		    path->is_dir == GIT3_DIR_FLAG_FALSE)
			continue;
		if (git3_attr_fnmatch__match(match, path)) {
			*ignored = ((match->flags & GIT3_ATTR_FNMATCH_NEGATIVE) == 0) ?
				GIT3_IGNORE_TRUE : GIT3_IGNORE_FALSE;
			return true;
		}
	}

	return false;
}

int git3_ignore__lookup(
	int *out, git3_ignores *ignores, const char *pathname, git3_dir_flag dir_flag)
{
	size_t i;
	git3_attr_file *file;
	git3_attr_path path;

	*out = GIT3_IGNORE_NOTFOUND;

	if (git3_attr_path__init(
		&path, pathname, git3_repository_workdir(ignores->repo), dir_flag) < 0)
		return -1;

	/* first process builtins - success means path was found */
	if (ignore_lookup_in_rules(out, ignores->ign_internal, &path))
		goto cleanup;

	/* next process files in the path.
	 * this process has to process ignores in reverse order
	 * to ensure correct prioritization of rules
	 */
	git3_vector_rforeach(&ignores->ign_path, i, file) {
		if (ignore_lookup_in_rules(out, file, &path))
			goto cleanup;
	}

	/* last process global ignores */
	git3_vector_foreach(&ignores->ign_global, i, file) {
		if (ignore_lookup_in_rules(out, file, &path))
			goto cleanup;
	}

cleanup:
	git3_attr_path__free(&path);
	return 0;
}

int git3_ignore_add_rule(git3_repository *repo, const char *rules)
{
	int error;
	git3_attr_file *ign_internal = NULL;

	if ((error = get_internal_ignores(&ign_internal, repo)) < 0)
		return error;

	error = parse_ignore_file(repo, ign_internal, rules, false);
	git3_attr_file__free(ign_internal);

	return error;
}

int git3_ignore_clear_internal_rules(git3_repository *repo)
{
	int error;
	git3_attr_file *ign_internal;

	if ((error = get_internal_ignores(&ign_internal, repo)) < 0)
		return error;

	if (!(error = git3_attr_file__clear_rules(ign_internal, true)))
		error = parse_ignore_file(
				repo, ign_internal, GIT3_IGNORE_DEFAULT_RULES, false);

	git3_attr_file__free(ign_internal);
	return error;
}

int git3_ignore_path_is_ignored(
	int *ignored,
	git3_repository *repo,
	const char *pathname)
{
	int error;
	const char *workdir;
	git3_attr_path path;
	git3_ignores ignores;
	unsigned int i;
	git3_attr_file *file;
	git3_dir_flag dir_flag = GIT3_DIR_FLAG_UNKNOWN;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(ignored);
	GIT3_ASSERT_ARG(pathname);

	workdir = git3_repository_workdir(repo);

	memset(&path, 0, sizeof(path));
	memset(&ignores, 0, sizeof(ignores));

	if (!git3__suffixcmp(pathname, "/"))
		dir_flag = GIT3_DIR_FLAG_TRUE;
	else if (git3_repository_is_bare(repo))
		dir_flag = GIT3_DIR_FLAG_FALSE;

	if ((error = git3_attr_path__init(&path, pathname, workdir, dir_flag)) < 0 ||
		(error = git3_ignore__for_path(repo, path.path, &ignores)) < 0)
		goto cleanup;

	while (1) {
		/* first process builtins - success means path was found */
		if (ignore_lookup_in_rules(ignored, ignores.ign_internal, &path))
			goto cleanup;

		/* next process files in the path */
		git3_vector_foreach(&ignores.ign_path, i, file) {
			if (ignore_lookup_in_rules(ignored, file, &path))
				goto cleanup;
		}

		/* last process global ignores */
		git3_vector_foreach(&ignores.ign_global, i, file) {
			if (ignore_lookup_in_rules(ignored, file, &path))
				goto cleanup;
		}

		/* move up one directory */
		if (path.basename == path.path)
			break;
		path.basename[-1] = '\0';
		while (path.basename > path.path && *path.basename != '/')
			path.basename--;
		if (path.basename > path.path)
			path.basename++;
		path.is_dir = 1;

		if ((error = git3_ignore__pop_dir(&ignores)) < 0)
			break;
	}

	*ignored = 0;

cleanup:
	git3_attr_path__free(&path);
	git3_ignore__free(&ignores);
	return error;
}

int git3_ignore__check_pathspec_for_exact_ignores(
	git3_repository *repo,
	git3_vector *vspec,
	bool no_fnmatch)
{
	int error = 0;
	size_t i;
	git3_attr_fnmatch *match;
	int ignored;
	git3_str path = GIT3_STR_INIT;
	const char *filename;
	git3_index *idx;

	if ((error = git3_repository__ensure_not_bare(
			repo, "validate pathspec")) < 0 ||
		(error = git3_repository_index(&idx, repo)) < 0)
		return error;

	git3_vector_foreach(vspec, i, match) {
		/* skip wildcard matches (if they are being used) */
		if ((match->flags & GIT3_ATTR_FNMATCH_HASWILD) != 0 &&
			!no_fnmatch)
			continue;

		filename = match->pattern;

		/* if file is already in the index, it's fine */
		if (git3_index_get_bypath(idx, filename, 0) != NULL)
			continue;

		if ((error = git3_repository_workdir_path(&path, repo, filename)) < 0)
			break;

		/* is there a file on disk that matches this exactly? */
		if (!git3_fs_path_isfile(path.ptr))
			continue;

		/* is that file ignored? */
		if ((error = git3_ignore_path_is_ignored(&ignored, repo, filename)) < 0)
			break;

		if (ignored) {
			git3_error_set(GIT3_ERROR_INVALID, "pathspec contains ignored file '%s'",
				filename);
			error = GIT3_EINVALIDSPEC;
			break;
		}
	}

	git3_index_free(idx);
	git3_str_dispose(&path);

	return error;
}
