/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "attr.h"

#include "repository.h"
#include "sysdir.h"
#include "config.h"
#include "attr_file.h"
#include "ignore.h"
#include "git3/oid.h"
#include "hashmap_str.h"
#include <ctype.h>

const char *git3_attr__true  = "[internal]__TRUE__";
const char *git3_attr__false = "[internal]__FALSE__";
const char *git3_attr__unset = "[internal]__UNSET__";

git3_attr_value_t git3_attr_value(const char *attr)
{
	if (attr == NULL || attr == git3_attr__unset)
		return GIT3_ATTR_VALUE_UNSPECIFIED;

	if (attr == git3_attr__true)
		return GIT3_ATTR_VALUE_TRUE;

	if (attr == git3_attr__false)
		return GIT3_ATTR_VALUE_FALSE;

	return GIT3_ATTR_VALUE_STRING;
}

static int collect_attr_files(
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_attr_options *opts,
	const char *path,
	git3_vector *files);

static void release_attr_files(git3_vector *files);

int git3_attr_get_ext(
	const char **value,
	git3_repository *repo,
	git3_attr_options *opts,
	const char *pathname,
	const char *name)
{
	int error;
	git3_attr_path path;
	git3_vector files = GIT3_VECTOR_INIT;
	size_t i, j;
	git3_attr_file *file;
	git3_attr_name attr;
	git3_attr_rule *rule;
	git3_dir_flag dir_flag = GIT3_DIR_FLAG_UNKNOWN;

	GIT3_ASSERT_ARG(value);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(name);
	GIT3_ERROR_CHECK_VERSION(opts, GIT3_ATTR_OPTIONS_VERSION, "git3_attr_options");

	*value = NULL;

	if (git3_repository_is_bare(repo))
		dir_flag = GIT3_DIR_FLAG_FALSE;

	if (git3_attr_path__init(&path, pathname, git3_repository_workdir(repo), dir_flag) < 0)
		return -1;

	if ((error = collect_attr_files(repo, NULL, opts, pathname, &files)) < 0)
		goto cleanup;

	memset(&attr, 0, sizeof(attr));
	attr.name = name;
	attr.name_hash = git3_attr_file__name_hash(name);

	git3_vector_foreach(&files, i, file) {

		git3_attr_file__foreach_matching_rule(file, &path, j, rule) {
			size_t pos;

			if (!git3_vector_bsearch(&pos, &rule->assigns, &attr)) {
				*value = ((git3_attr_assignment *)git3_vector_get(
							  &rule->assigns, pos))->value;
				goto cleanup;
			}
		}
	}

cleanup:
	release_attr_files(&files);
	git3_attr_path__free(&path);

	return error;
}

int git3_attr_get(
	const char **value,
	git3_repository *repo,
	uint32_t flags,
	const char *pathname,
	const char *name)
{
	git3_attr_options opts = GIT3_ATTR_OPTIONS_INIT;

	opts.flags = flags;

	return git3_attr_get_ext(value, repo, &opts, pathname, name);
}


typedef struct {
	git3_attr_name name;
	git3_attr_assignment *found;
} attr_get_many_info;

int git3_attr_get_many_with_session(
	const char **values,
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_attr_options *opts,
	const char *pathname,
	size_t num_attr,
	const char **names)
{
	int error;
	git3_attr_path path;
	git3_vector files = GIT3_VECTOR_INIT;
	size_t i, j, k;
	git3_attr_file *file;
	git3_attr_rule *rule;
	attr_get_many_info *info = NULL;
	size_t num_found = 0;
	git3_dir_flag dir_flag = GIT3_DIR_FLAG_UNKNOWN;

	if (!num_attr)
		return 0;

	GIT3_ASSERT_ARG(values);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(pathname);
	GIT3_ASSERT_ARG(names);
	GIT3_ERROR_CHECK_VERSION(opts, GIT3_ATTR_OPTIONS_VERSION, "git3_attr_options");

	if (git3_repository_is_bare(repo))
		dir_flag = GIT3_DIR_FLAG_FALSE;

	if (git3_attr_path__init(&path, pathname, git3_repository_workdir(repo), dir_flag) < 0)
		return -1;

	if ((error = collect_attr_files(repo, attr_session, opts, pathname, &files)) < 0)
		goto cleanup;

	info = git3__calloc(num_attr, sizeof(attr_get_many_info));
	GIT3_ERROR_CHECK_ALLOC(info);

	git3_vector_foreach(&files, i, file) {

		git3_attr_file__foreach_matching_rule(file, &path, j, rule) {

			for (k = 0; k < num_attr; k++) {
				size_t pos;

				if (info[k].found != NULL) /* already found assignment */
					continue;

				if (!info[k].name.name) {
					info[k].name.name = names[k];
					info[k].name.name_hash = git3_attr_file__name_hash(names[k]);
				}

				if (!git3_vector_bsearch(&pos, &rule->assigns, &info[k].name)) {
					info[k].found = (git3_attr_assignment *)
						git3_vector_get(&rule->assigns, pos);
					values[k] = info[k].found->value;

					if (++num_found == num_attr)
						goto cleanup;
				}
			}
		}
	}

	for (k = 0; k < num_attr; k++) {
		if (!info[k].found)
			values[k] = NULL;
	}

cleanup:
	release_attr_files(&files);
	git3_attr_path__free(&path);
	git3__free(info);

	return error;
}

int git3_attr_get_many(
	const char **values,
	git3_repository *repo,
	uint32_t flags,
	const char *pathname,
	size_t num_attr,
	const char **names)
{
	git3_attr_options opts = GIT3_ATTR_OPTIONS_INIT;

	opts.flags = flags;

	return git3_attr_get_many_with_session(
		values, repo, NULL, &opts, pathname, num_attr, names);
}

int git3_attr_get_many_ext(
	const char **values,
	git3_repository *repo,
	git3_attr_options *opts,
	const char *pathname,
	size_t num_attr,
	const char **names)
{
	return git3_attr_get_many_with_session(
		values, repo, NULL, opts, pathname, num_attr, names);
}

int git3_attr_foreach(
	git3_repository *repo,
	uint32_t flags,
	const char *pathname,
	int (*callback)(const char *name, const char *value, void *payload),
	void *payload)
{
	git3_attr_options opts = GIT3_ATTR_OPTIONS_INIT;

	opts.flags = flags;

	return git3_attr_foreach_ext(repo, &opts, pathname, callback, payload);
}

int git3_attr_foreach_ext(
	git3_repository *repo,
	git3_attr_options *opts,
	const char *pathname,
	int (*callback)(const char *name, const char *value, void *payload),
	void *payload)
{
	int error;
	git3_attr_path path;
	git3_vector files = GIT3_VECTOR_INIT;
	size_t i, j, k;
	git3_attr_file *file;
	git3_attr_rule *rule;
	git3_attr_assignment *assign;
	git3_hashset_str seen = GIT3_HASHSET_INIT;
	git3_dir_flag dir_flag = GIT3_DIR_FLAG_UNKNOWN;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(callback);
	GIT3_ERROR_CHECK_VERSION(opts, GIT3_ATTR_OPTIONS_VERSION, "git3_attr_options");

	if (git3_repository_is_bare(repo))
		dir_flag = GIT3_DIR_FLAG_FALSE;

	if (git3_attr_path__init(&path, pathname, git3_repository_workdir(repo), dir_flag) < 0)
		return -1;

	if ((error = collect_attr_files(repo, NULL, opts, pathname, &files)) < 0)
		goto cleanup;

	git3_vector_foreach(&files, i, file) {

		git3_attr_file__foreach_matching_rule(file, &path, j, rule) {

			git3_vector_foreach(&rule->assigns, k, assign) {
				/* skip if higher priority assignment was already seen */
				if (git3_hashset_str_contains(&seen, assign->name))
					continue;

				if ((error = git3_hashset_str_add(&seen, assign->name)) < 0)
					goto cleanup;

				error = callback(assign->name, assign->value, payload);
				if (error) {
					git3_error_set_after_callback(error);
					goto cleanup;
				}
			}
		}
	}

cleanup:
	git3_hashset_str_dispose(&seen);
	release_attr_files(&files);
	git3_attr_path__free(&path);

	return error;
}

static int preload_attr_source(
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_attr_file_source *source)
{
	int error;
	git3_attr_file *preload = NULL;

	if (!source)
		return 0;

	error = git3_attr_cache__get(&preload, repo, attr_session, source,
	                            git3_attr_file__parse_buffer, true);

	if (!error)
		git3_attr_file__free(preload);

	return error;
}

GIT3_INLINE(int) preload_attr_file(
	git3_repository *repo,
	git3_attr_session *attr_session,
	const char *base,
	const char *filename)
{
	git3_attr_file_source source = { GIT3_ATTR_FILE_SOURCE_FILE };

	if (!filename)
		return 0;

	source.base = base;
	source.filename = filename;

	return preload_attr_source(repo, attr_session, &source);
}

static int system_attr_file(
	git3_str *out,
	git3_attr_session *attr_session)
{
	int error;

	if (!attr_session) {
		error = git3_sysdir_find_system_file(out, GIT3_ATTR_FILE_SYSTEM);

		if (error == GIT3_ENOTFOUND)
			git3_error_clear();

		return error;
	}

	if (!attr_session->init_sysdir) {
		error = git3_sysdir_find_system_file(&attr_session->sysdir, GIT3_ATTR_FILE_SYSTEM);

		if (error == GIT3_ENOTFOUND)
			git3_error_clear();
		else if (error)
			return error;

		attr_session->init_sysdir = 1;
	}

	if (attr_session->sysdir.size == 0)
		return GIT3_ENOTFOUND;

	/* We can safely provide a git3_str with no allocation (asize == 0) to
	 * a consumer. This allows them to treat this as a regular `git3_str`,
	 * but their call to `git3_str_dispose` will not attempt to free it.
	 */
	git3_str_attach_notowned(
		out, attr_session->sysdir.ptr, attr_session->sysdir.size);
	return 0;
}

static int attr_setup(
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_attr_options *opts)
{
	git3_str system = GIT3_STR_INIT, info = GIT3_STR_INIT;
	git3_attr_file_source index_source = { GIT3_ATTR_FILE_SOURCE_INDEX, NULL, GIT3_ATTR_FILE, NULL };
	git3_attr_file_source head_source = { GIT3_ATTR_FILE_SOURCE_HEAD, NULL, GIT3_ATTR_FILE, NULL };
	git3_attr_file_source commit_source = { GIT3_ATTR_FILE_SOURCE_COMMIT, NULL, GIT3_ATTR_FILE, NULL };
	git3_attr_cache *attrcache;
	const char *attr_cfg_file = NULL;
	git3_index *idx = NULL;
	const char *workdir;
	int error = 0;

	if (attr_session && attr_session->init_setup)
		return 0;

	if ((error = git3_attr_cache__init(repo)) < 0)
		return error;

	/*
	 * Preload attribute files that could contain macros so the
	 * definitions will be available for later file parsing.
	 */

	if ((error = system_attr_file(&system, attr_session)) < 0 ||
	    (error = preload_attr_file(repo, attr_session, NULL, system.ptr)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto out;

		error = 0;
	}

	if ((attrcache = git3_repository_attr_cache(repo)) != NULL)
		attr_cfg_file = git3_attr_cache_attributesfile(attrcache);

	if ((error = preload_attr_file(repo, attr_session, NULL, attr_cfg_file)) < 0)
		goto out;

	if ((error = git3_repository__item_path(&info, repo, GIT3_REPOSITORY_ITEM_INFO)) < 0 ||
	    (error = preload_attr_file(repo, attr_session, info.ptr, GIT3_ATTR_FILE_INREPO)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto out;

		error = 0;
	}

	if ((workdir = git3_repository_workdir(repo)) != NULL &&
	    (error = preload_attr_file(repo, attr_session, workdir, GIT3_ATTR_FILE)) < 0)
			goto out;

	if ((error = git3_repository_index__weakptr(&idx, repo)) < 0 ||
	    (error = preload_attr_source(repo, attr_session, &index_source)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto out;

		error = 0;
	}

	if ((opts && (opts->flags & GIT3_ATTR_CHECK_INCLUDE_HEAD) != 0) &&
	    (error = preload_attr_source(repo, attr_session, &head_source)) < 0)
		goto out;

	if ((opts && (opts->flags & GIT3_ATTR_CHECK_INCLUDE_COMMIT) != 0)) {
#ifndef GIT3_DEPRECATE_HARD
		if (opts->commit_id)
			commit_source.commit_id = opts->commit_id;
		else
#endif
		commit_source.commit_id = &opts->attr_commit_id;

		if ((error = preload_attr_source(repo, attr_session, &commit_source)) < 0)
			goto out;
	}

	if (attr_session)
		attr_session->init_setup = 1;

out:
	git3_str_dispose(&system);
	git3_str_dispose(&info);

	return error;
}

int git3_attr_add_macro(
	git3_repository *repo,
	const char *name,
	const char *values)
{
	int error;
	git3_attr_rule *macro = NULL;
	git3_attr_cache *attrcache;
	git3_pool *pool;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(name);

	if ((error = git3_attr_cache__init(repo)) < 0)
		return error;

	macro = git3__calloc(1, sizeof(git3_attr_rule));
	GIT3_ERROR_CHECK_ALLOC(macro);

	attrcache = git3_repository_attr_cache(repo);
	pool = git3_attr_cache_pool(attrcache);

	macro->match.pattern = git3_pool_strdup(pool, name);
	GIT3_ERROR_CHECK_ALLOC(macro->match.pattern);

	macro->match.length = strlen(macro->match.pattern);
	macro->match.flags = GIT3_ATTR_FNMATCH_MACRO;

	error = git3_attr_assignment__parse(repo, pool, &macro->assigns, &values);

	if (!error)
		error = git3_attr_cache__insert_macro(repo, macro);

	if (error < 0)
		git3_attr_rule__free(macro);

	return error;
}

typedef struct {
	git3_repository *repo;
	git3_attr_session *attr_session;
	git3_attr_options *opts;
	const char *workdir;
	git3_index *index;
	git3_vector *files;
} attr_walk_up_info;

static int attr_decide_sources(
	uint32_t flags,
	bool has_wd,
	bool has_index,
	git3_attr_file_source_t *srcs)
{
	int count = 0;

	switch (flags & 0x03) {
	case GIT3_ATTR_CHECK_FILE_THEN_INDEX:
		if (has_wd)
			srcs[count++] = GIT3_ATTR_FILE_SOURCE_FILE;
		if (has_index)
			srcs[count++] = GIT3_ATTR_FILE_SOURCE_INDEX;
		break;
	case GIT3_ATTR_CHECK_INDEX_THEN_FILE:
		if (has_index)
			srcs[count++] = GIT3_ATTR_FILE_SOURCE_INDEX;
		if (has_wd)
			srcs[count++] = GIT3_ATTR_FILE_SOURCE_FILE;
		break;
	case GIT3_ATTR_CHECK_INDEX_ONLY:
		if (has_index)
			srcs[count++] = GIT3_ATTR_FILE_SOURCE_INDEX;
		break;
	}

	if ((flags & GIT3_ATTR_CHECK_INCLUDE_HEAD) != 0)
		srcs[count++] = GIT3_ATTR_FILE_SOURCE_HEAD;

	if ((flags & GIT3_ATTR_CHECK_INCLUDE_COMMIT) != 0)
		srcs[count++] = GIT3_ATTR_FILE_SOURCE_COMMIT;

	return count;
}

static int push_attr_source(
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_vector *list,
	git3_attr_file_source *source,
	bool allow_macros)
{
	int error = 0;
	git3_attr_file *file = NULL;

	error = git3_attr_cache__get(&file, repo, attr_session,
	                            source,
	                            git3_attr_file__parse_buffer,
	                            allow_macros);

	if (error < 0)
		return error;

	if (file != NULL) {
		if ((error = git3_vector_insert(list, file)) < 0)
			git3_attr_file__free(file);
	}

	return error;
}

GIT3_INLINE(int) push_attr_file(
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_vector *list,
	const char *base,
	const char *filename)
{
	git3_attr_file_source source = { GIT3_ATTR_FILE_SOURCE_FILE, base, filename };
	return push_attr_source(repo, attr_session, list, &source, true);
}

static int push_one_attr(void *ref, const char *path)
{
	attr_walk_up_info *info = (attr_walk_up_info *)ref;
	git3_attr_file_source_t src[GIT3_ATTR_FILE_NUM_SOURCES];
	int error = 0, n_src, i;
	bool allow_macros;

	n_src = attr_decide_sources(info->opts ? info->opts->flags : 0,
	                            info->workdir != NULL,
	                            info->index != NULL,
	                            src);

	allow_macros = info->workdir ? !strcmp(info->workdir, path) : false;

	for (i = 0; !error && i < n_src; ++i) {
		git3_attr_file_source source = { src[i], path, GIT3_ATTR_FILE };

		if (src[i] == GIT3_ATTR_FILE_SOURCE_COMMIT && info->opts) {
#ifndef GIT3_DEPRECATE_HARD
			if (info->opts->commit_id)
				source.commit_id = info->opts->commit_id;
			else
#endif
			source.commit_id = &info->opts->attr_commit_id;
		}

		error = push_attr_source(info->repo, info->attr_session, info->files,
		                       &source, allow_macros);
	}

	return error;
}

static void release_attr_files(git3_vector *files)
{
	size_t i;
	git3_attr_file *file;

	git3_vector_foreach(files, i, file) {
		git3_attr_file__free(file);
		files->contents[i] = NULL;
	}
	git3_vector_dispose(files);
}

static int collect_attr_files(
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_attr_options *opts,
	const char *path,
	git3_vector *files)
{
	int error = 0;
	git3_str dir = GIT3_STR_INIT, attrfile = GIT3_STR_INIT;
	const char *workdir = git3_repository_workdir(repo);
	git3_attr_cache *attrcache;
	const char *attr_cfg_file = NULL;
	attr_walk_up_info info = { NULL };

	GIT3_ASSERT(!git3_fs_path_is_absolute(path));

	if ((error = attr_setup(repo, attr_session, opts)) < 0)
		return error;

	/* Resolve path in a non-bare repo */
	if (workdir != NULL) {
		if (!(error = git3_repository_workdir_path(&dir, repo, path)))
			error = git3_fs_path_find_dir(&dir);
	}
	else {
		error = git3_fs_path_dirname_r(&dir, path);
	}

	if (error < 0)
		goto cleanup;

	/* in precedence order highest to lowest:
	 * - $GIT3_DIR/info/attributes
	 * - path components with .gitattributes
	 * - config core.attributesfile
	 * - $GIT3_PREFIX/etc/gitattributes
	 */

	if ((error = git3_repository__item_path(&attrfile, repo, GIT3_REPOSITORY_ITEM_INFO)) < 0 ||
	    (error = push_attr_file(repo, attr_session, files, attrfile.ptr, GIT3_ATTR_FILE_INREPO)) < 0) {
		if (error != GIT3_ENOTFOUND)
			goto cleanup;
	}

	info.repo = repo;
	info.attr_session = attr_session;
	info.opts = opts;
	info.workdir = workdir;
	if (git3_repository_index__weakptr(&info.index, repo) < 0)
		git3_error_clear(); /* no error even if there is no index */
	info.files = files;

	if (!strcmp(dir.ptr, "."))
		error = push_one_attr(&info, "");
	else
		error = git3_fs_path_walk_up(&dir, workdir, push_one_attr, &info);

	if (error < 0)
		goto cleanup;

	if ((attrcache = git3_repository_attr_cache(repo)) != NULL)
		attr_cfg_file = git3_attr_cache_attributesfile(attrcache);


	if (attr_cfg_file) {
		error = push_attr_file(repo, attr_session, files, NULL, attr_cfg_file);

		if (error < 0)
			goto cleanup;
	}

	if (!opts || (opts->flags & GIT3_ATTR_CHECK_NO_SYSTEM) == 0) {
		error = system_attr_file(&dir, attr_session);

		if (!error)
			error = push_attr_file(repo, attr_session, files, NULL, dir.ptr);
		else if (error == GIT3_ENOTFOUND)
			error = 0;
	}

 cleanup:
	if (error < 0)
		release_attr_files(files);
	git3_str_dispose(&attrfile);
	git3_str_dispose(&dir);

	return error;
}
