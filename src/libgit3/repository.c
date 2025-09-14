/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "repository.h"

#include <ctype.h>

#include "git3/object.h"
#include "git3/sys/repository.h"

#include "buf.h"
#include "common.h"
#include "commit.h"
#include "grafts.h"
#include "tag.h"
#include "blob.h"
#include "futils.h"
#include "sysdir.h"
#include "filebuf.h"
#include "index.h"
#include "config.h"
#include "refs.h"
#include "filter.h"
#include "odb.h"
#include "refdb.h"
#include "remote.h"
#include "merge.h"
#include "diff_driver.h"
#include "annotated_commit.h"
#include "submodule.h"
#include "worktree.h"
#include "path.h"

#ifdef GIT3_WIN32
# include "win32/w32_util.h"
#endif

bool git3_repository__validate_ownership = true;
bool git3_repository__fsync_gitdir = false;

static const struct {
    git3_repository_item_t parent;
	git3_repository_item_t fallback;
    const char *name;
    bool directory;
} items[] = {
	{ GIT3_REPOSITORY_ITEM_GITDIR, GIT3_REPOSITORY_ITEM__LAST, NULL, true },
	{ GIT3_REPOSITORY_ITEM_WORKDIR, GIT3_REPOSITORY_ITEM__LAST, NULL, true },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM__LAST, NULL, true },
	{ GIT3_REPOSITORY_ITEM_GITDIR, GIT3_REPOSITORY_ITEM__LAST, "index", false },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "objects", true },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "refs", true },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "packed-refs", false },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "remotes", true },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "config", false },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "info", true },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "hooks", true },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "logs", true },
	{ GIT3_REPOSITORY_ITEM_GITDIR, GIT3_REPOSITORY_ITEM__LAST, "modules", true },
	{ GIT3_REPOSITORY_ITEM_COMMONDIR, GIT3_REPOSITORY_ITEM_GITDIR, "worktrees", true },
	{ GIT3_REPOSITORY_ITEM_GITDIR, GIT3_REPOSITORY_ITEM_GITDIR, "config.worktree", false }
};

static int check_repositoryformatversion(int *version, git3_config *config);
static int check_extensions(git3_config *config, int version);
static int load_global_config(git3_config **config, bool use_env);
static int load_objectformat(git3_repository *repo, git3_config *config);

#define GIT3_COMMONDIR_FILE "commondir"
#define GIT3_GITDIR_FILE "gitdir"

#define GIT3_FILE_CONTENT_PREFIX "gitdir:"

#define GIT3_BRANCH_DEFAULT "master"

#define GIT3_REPO_VERSION_DEFAULT 0
#define GIT3_REPO_VERSION_MAX 3  /* Support Git3 repositories with SHA3-256 */

git3_str git3_repository__reserved_names_win32[] = {
	{ DOT_GIT, 0, CONST_STRLEN(DOT_GIT) },
	{ GIT3_DIR_SHORTNAME, 0, CONST_STRLEN(GIT3_DIR_SHORTNAME) }
};
size_t git3_repository__reserved_names_win32_len = 2;

git3_str git3_repository__reserved_names_posix[] = {
	{ DOT_GIT, 0, CONST_STRLEN(DOT_GIT) },
};
size_t git3_repository__reserved_names_posix_len = 1;

static void set_odb(git3_repository *repo, git3_odb *odb)
{
	if (odb) {
		GIT3_REFCOUNT_OWN(odb, repo);
		GIT3_REFCOUNT_INC(odb);
	}

	if ((odb = git3_atomic_swap(repo->_odb, odb)) != NULL) {
		GIT3_REFCOUNT_OWN(odb, NULL);
		git3_odb_free(odb);
	}
}

static void set_refdb(git3_repository *repo, git3_refdb *refdb)
{
	if (refdb) {
		GIT3_REFCOUNT_OWN(refdb, repo);
		GIT3_REFCOUNT_INC(refdb);
	}

	if ((refdb = git3_atomic_swap(repo->_refdb, refdb)) != NULL) {
		GIT3_REFCOUNT_OWN(refdb, NULL);
		git3_refdb_free(refdb);
	}
}

static void set_config(git3_repository *repo, git3_config *config)
{
	if (config) {
		GIT3_REFCOUNT_OWN(config, repo);
		GIT3_REFCOUNT_INC(config);
	}

	if ((config = git3_atomic_swap(repo->_config, config)) != NULL) {
		GIT3_REFCOUNT_OWN(config, NULL);
		git3_config_free(config);
	}

	git3_repository__configmap_lookup_cache_clear(repo);
}

static void set_index(git3_repository *repo, git3_index *index)
{
	if (index) {
		GIT3_REFCOUNT_OWN(index, repo);
		GIT3_REFCOUNT_INC(index);
	}

	if ((index = git3_atomic_swap(repo->_index, index)) != NULL) {
		GIT3_REFCOUNT_OWN(index, NULL);
		git3_index_free(index);
	}
}

int git3_repository__cleanup(git3_repository *repo)
{
	GIT3_ASSERT_ARG(repo);

	git3_repository_submodule_cache_clear(repo);
	git3_cache_clear(&repo->objects);
	git3_attr_cache_flush(repo);
	git3_grafts_free(repo->grafts);
	repo->grafts = NULL;
	git3_grafts_free(repo->shallow_grafts);
	repo->shallow_grafts = NULL;

	set_config(repo, NULL);
	set_index(repo, NULL);
	set_odb(repo, NULL);
	set_refdb(repo, NULL);

	return 0;
}

void git3_repository_free(git3_repository *repo)
{
	size_t i;

	if (repo == NULL)
		return;

	git3_repository__cleanup(repo);

	git3_cache_dispose(&repo->objects);

	git3_diff_driver_registry_free(repo->diff_drivers);
	repo->diff_drivers = NULL;

	for (i = 0; i < repo->reserved_names.size; i++)
		git3_str_dispose(git3_array_get(repo->reserved_names, i));
	git3_array_clear(repo->reserved_names);

	git3__free(repo->gitlink);
	git3__free(repo->gitdir);
	git3__free(repo->commondir);
	git3__free(repo->workdir);
	git3__free(repo->namespace);
	git3__free(repo->ident_name);
	git3__free(repo->ident_email);

	git3__memzero(repo, sizeof(*repo));
	git3__free(repo);
}

/* Check if we have a separate commondir (e.g. we have a worktree) */
static int lookup_commondir(
	bool *separate,
	git3_str *commondir,
	git3_str *repository_path,
	uint32_t flags)
{
	git3_str common_link = GIT3_STR_INIT;
	int error;

	/* Environment variable overrides configuration */
	if ((flags & GIT3_REPOSITORY_OPEN_FROM_ENV)) {
		error = git3__getenv(commondir, "GIT3_COMMON_DIR");

		if (!error || error != GIT3_ENOTFOUND)
			goto done;
	}

	/*
	 * If there's no commondir file, the repository path is the
	 * common path, but it needs a trailing slash.
	 */
	if (!git3_fs_path_contains_file(repository_path, GIT3_COMMONDIR_FILE)) {
		if ((error = git3_str_set(commondir, repository_path->ptr, repository_path->size)) == 0)
		    error = git3_fs_path_to_dir(commondir);

		*separate = false;
		goto done;
	}

	*separate = true;

	if ((error = git3_str_joinpath(&common_link, repository_path->ptr, GIT3_COMMONDIR_FILE)) < 0 ||
	    (error = git3_futils_readbuffer(&common_link, common_link.ptr)) < 0)
		goto done;

	git3_str_rtrim(&common_link);
	if (git3_fs_path_is_relative(common_link.ptr)) {
		if ((error = git3_str_joinpath(commondir, repository_path->ptr, common_link.ptr)) < 0)
			goto done;
	} else {
		git3_str_swap(commondir, &common_link);
	}

	/* Make sure the commondir path always has a trailing slash */
	error = git3_fs_path_prettify_dir(commondir, commondir->ptr, NULL);

done:
	git3_str_dispose(&common_link);
	return error;
}

GIT3_INLINE(int) validate_repo_path(git3_str *path)
{
	/*
	 * The longest static path in a repository (or commondir) is the
	 * packed refs file.  (Loose refs may be longer since they
	 * include the reference name, but will be validated when the
	 * path is constructed.)
	 */
	static size_t suffix_len =
		CONST_STRLEN("objects/pack/pack-.pack.lock") +
		GIT3_OID_MAX_HEXSIZE;

	return git3_fs_path_validate_str_length_with_suffix(
		path, suffix_len);
}

/*
 * Git repository open methods
 *
 * Open a repository object from its path
 */
static int is_valid_repository_path(
	bool *out,
	git3_str *repository_path,
	git3_str *common_path,
	uint32_t flags)
{
	bool separate_commondir = false;
	int error;

	*out = false;

	if ((error = lookup_commondir(&separate_commondir,
			common_path, repository_path, flags)) < 0)
		return error;

	/* Ensure HEAD file exists */
	if (git3_fs_path_contains_file(repository_path, GIT3_HEAD_FILE) == false)
		return 0;

	/* Check files in common dir */
	if (git3_fs_path_contains_dir(common_path, GIT3_OBJECTS_DIR) == false)
		return 0;
	if (git3_fs_path_contains_dir(common_path, GIT3_REFS_DIR) == false)
		return 0;

	/* Ensure the repo (and commondir) are valid paths */
	if ((error = validate_repo_path(common_path)) < 0 ||
	    (separate_commondir &&
	     (error = validate_repo_path(repository_path)) < 0))
		return error;

	*out = true;
	return 0;
}

static git3_repository *repository_alloc(void)
{
	git3_repository *repo = git3__calloc(1, sizeof(git3_repository));

	if (repo == NULL ||
		git3_cache_init(&repo->objects) < 0)
		goto on_error;

	git3_array_init_to_size(repo->reserved_names, 4);
	if (!repo->reserved_names.ptr)
		goto on_error;

	/* set all the entries in the configmap cache to `unset` */
	git3_repository__configmap_lookup_cache_clear(repo);

	return repo;

on_error:
	if (repo)
		git3_cache_dispose(&repo->objects);

	git3__free(repo);
	return NULL;
}

int git3_repository_new_ext(
	git3_repository **out,
	git3_repository_new_options *opts)
{
	git3_repository *repo;

	GIT3_ASSERT_ARG(out);
	GIT3_ERROR_CHECK_VERSION(opts,
		GIT3_REPOSITORY_NEW_OPTIONS_VERSION,
		"git3_repository_new_options");

	if (opts && opts->oid_type)
		GIT3_ASSERT_ARG(git3_oid_type_is_valid(opts->oid_type));

	*out = repo = repository_alloc();
	GIT3_ERROR_CHECK_ALLOC(repo);

	repo->is_bare = 1;
	repo->is_worktree = 0;
	repo->oid_type = opts && opts->oid_type ? opts->oid_type :
		GIT3_OID_DEFAULT;

	return 0;
}

int git3_repository_new(git3_repository **out)
{
	return git3_repository_new_ext(out, NULL);
}

static int load_config_data(git3_repository *repo, const git3_config *config)
{
	int is_bare;

	int err = git3_config_get_bool(&is_bare, config, "core.bare");
	if (err < 0 && err != GIT3_ENOTFOUND)
		return err;

	/* Try to figure out if it's bare, default to non-bare if it's not set */
	if (err != GIT3_ENOTFOUND)
		repo->is_bare = is_bare && !repo->is_worktree;
	else
		repo->is_bare = 0;

	return 0;
}

static int load_workdir(
	git3_repository *repo,
	git3_config *config,
	git3_str *parent_path)
{
	git3_config_entry *ce = NULL;
	git3_str worktree = GIT3_STR_INIT;
	git3_str path = GIT3_STR_INIT;
	git3_str workdir_env = GIT3_STR_INIT;
	const char *value = NULL;
	int error;

	if (repo->is_bare)
		return 0;

	/* Environment variables are preferred */
	if (repo->use_env) {
		error = git3__getenv(&workdir_env, "GIT3_WORK_TREE");

		if (error == 0)
			value = workdir_env.ptr;
		else if (error == GIT3_ENOTFOUND)
			error = 0;
		else
			goto cleanup;
	}

	/* Examine configuration values if necessary */
	if (!value) {
		if ((error = git3_config__lookup_entry(&ce, config,
				"core.worktree", false)) < 0)
			return error;

		if (ce && ce->value)
			value = ce->value;
	}

	if (repo->is_worktree) {
		char *gitlink = git3_worktree__read_link(repo->gitdir, GIT3_GITDIR_FILE);
		if (!gitlink) {
			error = -1;
			goto cleanup;
		}

		git3_str_attach(&worktree, gitlink, 0);

		if ((git3_fs_path_dirname_r(&worktree, worktree.ptr)) < 0 ||
		    git3_fs_path_to_dir(&worktree) < 0) {
			error = -1;
			goto cleanup;
		}

		repo->workdir = git3_str_detach(&worktree);
	} else if (value) {
		if (!*value) {
			git3_error_set(GIT3_ERROR_NET, "working directory cannot be set to empty path");
			error = -1;
			goto cleanup;
		}

		if ((error = git3_fs_path_prettify_dir(&worktree,
				value, repo->gitdir)) < 0)
			goto cleanup;

		repo->workdir = git3_str_detach(&worktree);
	} else if (parent_path && git3_fs_path_isdir(parent_path->ptr)) {
		repo->workdir = git3_str_detach(parent_path);
	} else {
		if (git3_fs_path_dirname_r(&worktree, repo->gitdir) < 0 ||
		    git3_fs_path_to_dir(&worktree) < 0) {
			error = -1;
			goto cleanup;
		}

		repo->workdir = git3_str_detach(&worktree);
	}

	GIT3_ERROR_CHECK_ALLOC(repo->workdir);

cleanup:
	git3_str_dispose(&path);
	git3_str_dispose(&workdir_env);
	git3_config_entry_free(ce);
	return error;
}

/*
 * This function returns furthest offset into path where a ceiling dir
 * is found, so we can stop processing the path at that point.
 *
 * Note: converting this to use git3_strs instead of GIT3_PATH_MAX buffers on
 * the stack could remove directories name limits, but at the cost of doing
 * repeated malloc/frees inside the loop below, so let's not do it now.
 */
static size_t find_ceiling_dir_offset(
	const char *path,
	const char *ceiling_directories)
{
	char buf[GIT3_PATH_MAX + 1];
	char buf2[GIT3_PATH_MAX + 1];
	const char *ceil, *sep;
	size_t len, max_len = 0, min_len;

	GIT3_ASSERT_ARG(path);

	min_len = (size_t)(git3_fs_path_root(path) + 1);

	if (ceiling_directories == NULL || min_len == 0)
		return min_len;

	for (sep = ceil = ceiling_directories; *sep; ceil = sep + 1) {
		for (sep = ceil; *sep && *sep != GIT3_PATH_LIST_SEPARATOR; sep++);
		len = sep - ceil;

		if (len == 0 || len >= sizeof(buf) || git3_fs_path_root(ceil) == -1)
			continue;

		strncpy(buf, ceil, len);
		buf[len] = '\0';

		if (p_realpath(buf, buf2) == NULL)
			continue;

		len = strlen(buf2);
		if (len > 0 && buf2[len-1] == '/')
			buf[--len] = '\0';

		if (!strncmp(path, buf2, len) &&
			(path[len] == '/' || !path[len]) &&
			len > max_len)
		{
			max_len = len;
		}
	}

	return (max_len <= min_len ? min_len : max_len);
}

/*
 * Read the contents of `file_path` and set `path_out` to the repo dir that
 * it points to.  Before calling, set `path_out` to the base directory that
 * should be used if the contents of `file_path` are a relative path.
 */
static int read_gitfile(git3_str *path_out, const char *file_path)
{
	int     error = 0;
	git3_str file = GIT3_STR_INIT;
	size_t  prefix_len = strlen(GIT3_FILE_CONTENT_PREFIX);

	GIT3_ASSERT_ARG(path_out);
	GIT3_ASSERT_ARG(file_path);

	if (git3_futils_readbuffer(&file, file_path) < 0)
		return -1;

	git3_str_rtrim(&file);
	/* apparently on Windows, some people use backslashes in paths */
	git3_fs_path_mkposix(file.ptr);

	if (git3_str_len(&file) <= prefix_len ||
		memcmp(git3_str_cstr(&file), GIT3_FILE_CONTENT_PREFIX, prefix_len) != 0)
	{
		git3_error_set(GIT3_ERROR_REPOSITORY,
			"the `.git` file at '%s' is malformed", file_path);
		error = -1;
	}
	else if ((error = git3_fs_path_dirname_r(path_out, file_path)) >= 0) {
		const char *gitlink = git3_str_cstr(&file) + prefix_len;
		while (*gitlink && git3__isspace(*gitlink)) gitlink++;

		error = git3_fs_path_prettify_dir(
			path_out, gitlink, git3_str_cstr(path_out));
	}

	git3_str_dispose(&file);
	return error;
}

typedef struct {
	const char *repo_path;
	git3_str tmp;
	bool *is_safe;
} validate_ownership_data;

static int validate_ownership_cb(const git3_config_entry *entry, void *payload)
{
	validate_ownership_data *data = payload;
	const char *test_path;

	if (strcmp(entry->value, "") == 0) {
		*data->is_safe = false;
	} else if (strcmp(entry->value, "*") == 0) {
		*data->is_safe = true;
	} else {
		if (git3_str_sets(&data->tmp, entry->value) < 0)
			return -1;

		if (!git3_fs_path_is_root(data->tmp.ptr)) {
			/* Input must not have trailing backslash. */
			if (!data->tmp.size ||
			    data->tmp.ptr[data->tmp.size - 1] == '/')
				return 0;

			if (git3_fs_path_to_dir(&data->tmp) < 0)
				return -1;
		}

		test_path = data->tmp.ptr;

		/*
		 * Git - and especially, Git for Windows - does some
		 * truly bizarre things with paths that start with a
		 * forward slash; and expects you to escape that with
		 * `%(prefix)`. This syntax generally means to add the
		 * prefix that Git was installed to (eg `/usr/local`)
		 * unless it's an absolute path, in which case the
		 * leading `%(prefix)/` is just removed. And Git for
		 * Windows expects you to use this syntax for absolute
		 * Unix-style paths (in "Git Bash" or Windows Subsystem
		 * for Linux).
		 *
		 * Worse, the behavior used to be that a leading `/` was
		 * not absolute. It would indicate that Git for Windows
		 * should add the prefix. So `//` is required for absolute
		 * Unix-style paths. Yes, this is truly horrifying.
		 *
		 * Emulate that behavior, I guess, but only for absolute
		 * paths. We won't deal with the Git install prefix. Also,
		 * give WSL users an escape hatch where they don't have to
		 * think about this and can use the literal path that the
		 * filesystem APIs provide (`//wsl.localhost/...`).
		 */
		if (strncmp(test_path, "%(prefix)//", strlen("%(prefix)//")) == 0)
			test_path += strlen("%(prefix)/");

		if (strcmp(test_path, data->repo_path) == 0)
			*data->is_safe = true;
	}

	return 0;
}

static int validate_ownership_config(
	bool *is_safe,
	const char *path,
	bool use_env)
{
	validate_ownership_data ownership_data = {
		path, GIT3_STR_INIT, is_safe
	};
	git3_config *config;
	int error;

	if (load_global_config(&config, use_env) != 0)
		return 0;

	error = git3_config_get_multivar_foreach(config,
		"safe.directory", NULL,
		validate_ownership_cb,
		&ownership_data);

	if (error == GIT3_ENOTFOUND)
		error = 0;

	git3_config_free(config);
	git3_str_dispose(&ownership_data.tmp);

	return error;
}

static int validate_ownership_path(bool *is_safe, const char *path)
{
	git3_fs_path_owner_t owner_level =
		GIT3_FS_PATH_OWNER_CURRENT_USER |
		GIT3_FS_PATH_USER_IS_ADMINISTRATOR |
		GIT3_FS_PATH_OWNER_RUNNING_SUDO;
	int error = 0;

	if (path)
		error = git3_fs_path_owner_is(is_safe, path, owner_level);

	if (error == GIT3_ENOTFOUND) {
		*is_safe = true;
		error = 0;
	} else if (error == GIT3_EINVALID) {
		*is_safe = false;
		error = 0;
	}

	return error;
}

static int validate_ownership(git3_repository *repo)
{
	const char *validation_paths[3] = { NULL }, *path;
	size_t validation_len = 0, i;
	bool is_safe = false;
	int error = 0;

	/*
	 * If there's a worktree, validate the permissions to it *and*
	 * the git directory, and use the worktree as the configuration
	 * key for allowlisting the directory. In a bare setup, only
	 * look at the gitdir and use that as the allowlist. So we
	 * examine all `validation_paths` but use only the first as
	 * the configuration lookup.
	 */

	if (repo->workdir)
		validation_paths[validation_len++] = repo->workdir;

	if (repo->gitlink)
		validation_paths[validation_len++] = repo->gitlink;

	validation_paths[validation_len++] = repo->gitdir;

	for (i = 0; i < validation_len; i++) {
		path = validation_paths[i];

		if ((error = validate_ownership_path(&is_safe, path)) < 0)
			goto done;

		if (!is_safe)
			break;
	}

	if (is_safe ||
	    (error = validate_ownership_config(
			&is_safe, validation_paths[0], repo->use_env)) < 0)
		goto done;

	if (!is_safe) {
		size_t path_len = git3_fs_path_is_root(path) ?
			strlen(path) : git3_fs_path_dirlen(path);

		git3_error_set(GIT3_ERROR_CONFIG,
			"repository path '%.*s' is not owned by current user",
			(int)min(path_len, INT_MAX), path);
		error = GIT3_EOWNER;
	}

done:
	return error;
}

struct repo_paths {
	git3_str gitdir;
	git3_str workdir;
	git3_str gitlink;
	git3_str commondir;
};

#define REPO_PATHS_INIT { GIT3_STR_INIT }

GIT3_INLINE(void) repo_paths_dispose(struct repo_paths *paths)
{
	git3_str_dispose(&paths->gitdir);
	git3_str_dispose(&paths->workdir);
	git3_str_dispose(&paths->gitlink);
	git3_str_dispose(&paths->commondir);
}

static int find_repo_traverse(
	struct repo_paths *out,
	const char *start_path,
	const char *ceiling_dirs,
	uint32_t flags)
{
	git3_str path = GIT3_STR_INIT;
	git3_str repo_link = GIT3_STR_INIT;
	git3_str common_link = GIT3_STR_INIT;
	struct stat st;
	dev_t initial_device = 0;
	int min_iterations;
	bool in_dot_git, is_valid;
	size_t ceiling_offset = 0;
	int error;

	git3_str_clear(&out->gitdir);

	if ((error = git3_fs_path_prettify(&path, start_path, NULL)) < 0)
		return error;

	/*
	 * In each loop we look first for a `.git` dir within the
	 * directory, then to see if the directory itself is a repo.
	 *
	 * In other words: if we start in /a/b/c, then we look at:
	 * /a/b/c/.git, /a/b/c, /a/b/.git, /a/b, /a/.git, /a
	 *
	 * With GIT3_REPOSITORY_OPEN_BARE or GIT3_REPOSITORY_OPEN_NO_DOTGIT,
	 * we assume we started with /a/b/c.git and don't append .git the
	 * first time through.  min_iterations indicates the number of
	 * iterations left before going further counts as a search.
	 */
	if (flags & (GIT3_REPOSITORY_OPEN_BARE | GIT3_REPOSITORY_OPEN_NO_DOTGIT)) {
		in_dot_git = true;
		min_iterations = 1;
	} else {
		in_dot_git = false;
		min_iterations = 2;
	}

	for (;;) {
		if (!(flags & GIT3_REPOSITORY_OPEN_NO_DOTGIT)) {
			if (!in_dot_git) {
				if ((error = git3_str_joinpath(&path, path.ptr, DOT_GIT)) < 0)
					goto out;
			}
			in_dot_git = !in_dot_git;
		}

		if (p_stat(path.ptr, &st) == 0) {
			/* check that we have not crossed device boundaries */
			if (initial_device == 0)
				initial_device = st.st_dev;
			else if (st.st_dev != initial_device &&
				 !(flags & GIT3_REPOSITORY_OPEN_CROSS_FS))
				break;

			if (S_ISDIR(st.st_mode)) {
				if ((error = is_valid_repository_path(&is_valid, &path, &common_link, flags)) < 0)
					goto out;

				if (is_valid) {
					if ((error = git3_fs_path_to_dir(&path)) < 0 ||
					    (error = git3_str_set(&out->gitdir, path.ptr, path.size)) < 0)
						goto out;

					if ((error = git3_str_attach(&out->gitlink, git3_worktree__read_link(path.ptr, GIT3_GITDIR_FILE), 0)) < 0)
						goto out;

					git3_str_swap(&common_link, &out->commondir);

					break;
				}
			} else if (S_ISREG(st.st_mode) && git3__suffixcmp(path.ptr, "/" DOT_GIT) == 0) {
				if ((error = read_gitfile(&repo_link, path.ptr)) < 0 ||
				    (error = is_valid_repository_path(&is_valid, &repo_link, &common_link, flags)) < 0)
					goto out;

				if (is_valid) {
					git3_str_swap(&out->gitdir, &repo_link);

					if ((error = git3_str_put(&out->gitlink, path.ptr, path.size)) < 0)
						goto out;

					git3_str_swap(&common_link, &out->commondir);
				}
				break;
			}
		}

		/*
		 * Move up one directory. If we're in_dot_git, we'll
		 * search the parent itself next. If we're !in_dot_git,
		 * we'll search .git in the parent directory next (added
		 * at the top of the loop).
		 */
		if ((error = git3_fs_path_dirname_r(&path, path.ptr)) < 0)
			goto out;

		/*
		 * Once we've checked the directory (and .git if
		 * applicable), find the ceiling for a search.
		 */
		if (min_iterations && (--min_iterations == 0))
			ceiling_offset = find_ceiling_dir_offset(path.ptr, ceiling_dirs);

		/* Check if we should stop searching here. */
		if (min_iterations == 0 &&
		    (path.ptr[ceiling_offset] == 0 || (flags & GIT3_REPOSITORY_OPEN_NO_SEARCH)))
			break;
	}

	if (!(flags & GIT3_REPOSITORY_OPEN_BARE)) {
		if (!git3_str_len(&out->gitdir))
			git3_str_clear(&out->workdir);
		else if ((error = git3_fs_path_dirname_r(&out->workdir, path.ptr)) < 0 ||
			 (error = git3_fs_path_to_dir(&out->workdir)) < 0)
			goto out;
	}

	/* If we didn't find the repository, and we don't have any other
	 * error to report, report that. */
	if (!git3_str_len(&out->gitdir)) {
		git3_error_set(GIT3_ERROR_REPOSITORY, "could not find repository at '%s'", start_path);
		error = GIT3_ENOTFOUND;
		goto out;
	}

out:
	if (error)
		repo_paths_dispose(out);

	git3_str_dispose(&path);
	git3_str_dispose(&repo_link);
	git3_str_dispose(&common_link);
	return error;
}

static int load_grafts(git3_repository *repo)
{
	git3_str path = GIT3_STR_INIT;
	int error;

	/* refresh if they've both been opened previously */
	if (repo->grafts && repo->shallow_grafts) {
		if ((error = git3_grafts_refresh(repo->grafts)) < 0 ||
		    (error = git3_grafts_refresh(repo->shallow_grafts)) < 0)
			return error;
	}

	/* resolve info path, which may not be found for inmemory repository */
	if ((error = git3_repository__item_path(&path, repo, GIT3_REPOSITORY_ITEM_INFO)) < 0) {
		if (error != GIT3_ENOTFOUND)
			return error;

		/* create empty/inmemory grafts for inmemory repository */
		if (!repo->grafts && (error = git3_grafts_new(&repo->grafts, repo->oid_type)) < 0)
			return error;

		if (!repo->shallow_grafts && (error = git3_grafts_new(&repo->shallow_grafts, repo->oid_type)) < 0)
			return error;

		return 0;
	}

	/* load grafts from disk */
	if ((error = git3_str_joinpath(&path, path.ptr, "grafts")) < 0 ||
	    (error = git3_grafts_open_or_refresh(&repo->grafts, path.ptr, repo->oid_type)) < 0)
		goto error;

	git3_str_clear(&path);

	if ((error = git3_str_joinpath(&path, repo->gitdir, "shallow")) < 0 ||
	    (error = git3_grafts_open_or_refresh(&repo->shallow_grafts, path.ptr, repo->oid_type)) < 0)
		goto error;

error:
	git3_str_dispose(&path);
	return error;
}

static int find_repo(
	struct repo_paths *out,
	const char *start_path,
	const char *ceiling_dirs,
	uint32_t flags)
{
	bool use_env = !!(flags & GIT3_REPOSITORY_OPEN_FROM_ENV);
	git3_str gitdir_buf = GIT3_STR_INIT,
	        ceiling_dirs_buf = GIT3_STR_INIT,
	        across_fs_buf = GIT3_STR_INIT;
	int error;

	if (use_env && !start_path) {
		error = git3__getenv(&gitdir_buf, "GIT3_DIR");

		if (!error) {
			start_path = gitdir_buf.ptr;
			flags |= GIT3_REPOSITORY_OPEN_NO_SEARCH;
			flags |= GIT3_REPOSITORY_OPEN_NO_DOTGIT;
		} else if (error == GIT3_ENOTFOUND) {
			start_path = ".";
		} else {
			goto done;
		}
	}

	if (use_env && !ceiling_dirs) {
		error = git3__getenv(&ceiling_dirs_buf,
			"GIT3_CEILING_DIRECTORIES");

		if (!error)
			ceiling_dirs = ceiling_dirs_buf.ptr;
		else if (error != GIT3_ENOTFOUND)
			goto done;
	}

	if (use_env) {
		error = git3__getenv(&across_fs_buf,
			"GIT3_DISCOVERY_ACROSS_FILESYSTEM");

		if (!error) {
			int across_fs = 0;

			if ((error = git3_config_parse_bool(&across_fs,
				git3_str_cstr(&across_fs_buf))) < 0)
				goto done;

			if (across_fs)
				flags |= GIT3_REPOSITORY_OPEN_CROSS_FS;
		} else if (error != GIT3_ENOTFOUND) {
			goto done;
		}
	}

	error = find_repo_traverse(out, start_path, ceiling_dirs, flags);

done:
	git3_str_dispose(&gitdir_buf);
	git3_str_dispose(&ceiling_dirs_buf);
	git3_str_dispose(&across_fs_buf);

	return error;
}

static int obtain_config_and_set_oid_type(
	git3_config **config_ptr,
	git3_repository *repo)
{
	int error;
	git3_config *config = NULL;
	int version = 0;

	/*
	 * We'd like to have the config, but git doesn't particularly
	 * care if it's not there, so we need to deal with that.
	 */

	error = git3_repository_config_snapshot(&config, repo);
	if (error < 0 && error != GIT3_ENOTFOUND)
		goto out;

	if (config &&
	    (error = check_repositoryformatversion(&version, config)) < 0)
		goto out;

	if ((error = check_extensions(config, version)) < 0)
		goto out;

	/* For QED/libgit3: ALWAYS use SHA3-256 regardless of version */
	repo->oid_type = GIT3_OID_SHA3_256;
	
	/* Original code disabled - always use SHA3-256 for QED
	if (version > 0) {
		if ((error = load_objectformat(repo, config)) < 0)
			goto out;
	} else {
		repo->oid_type = GIT3_OID_DEFAULT;
	}
	*/

out:
	*config_ptr = config;

	return error;
}

int git3_repository_open_bare(
	git3_repository **repo_ptr,
	const char *bare_path)
{
	git3_str path = GIT3_STR_INIT, common_path = GIT3_STR_INIT;
	git3_repository *repo = NULL;
	bool is_valid;
	int error;
	git3_config *config;

	if ((error = git3_fs_path_prettify_dir(&path, bare_path, NULL)) < 0 ||
	    (error = is_valid_repository_path(&is_valid, &path, &common_path, 0)) < 0)
		return error;

	if (!is_valid) {
		git3_str_dispose(&path);
		git3_str_dispose(&common_path);
		git3_error_set(GIT3_ERROR_REPOSITORY, "path is not a repository: %s", bare_path);
		return GIT3_ENOTFOUND;
	}

	repo = repository_alloc();
	GIT3_ERROR_CHECK_ALLOC(repo);

	repo->gitdir = git3_str_detach(&path);
	GIT3_ERROR_CHECK_ALLOC(repo->gitdir);
	repo->commondir = git3_str_detach(&common_path);
	GIT3_ERROR_CHECK_ALLOC(repo->commondir);

	/* of course we're bare! */
	repo->is_bare = 1;
	repo->is_worktree = 0;
	repo->workdir = NULL;

	if ((error = obtain_config_and_set_oid_type(&config, repo)) < 0)
		goto cleanup;

	*repo_ptr = repo;

cleanup:
	git3_config_free(config);

	return error;
}

static int repo_load_namespace(git3_repository *repo)
{
	git3_str namespace_buf = GIT3_STR_INIT;
	int error;

	if (!repo->use_env)
		return 0;

	error = git3__getenv(&namespace_buf, "GIT3_NAMESPACE");

	if (error == 0)
		repo->namespace = git3_str_detach(&namespace_buf);
	else if (error != GIT3_ENOTFOUND)
		return error;

	return 0;
}

static int repo_is_worktree(unsigned *out, const git3_repository *repo)
{
	git3_str gitdir_link = GIT3_STR_INIT;
	int error;

	/* Worktrees cannot have the same commondir and gitdir */
	if (repo->commondir && repo->gitdir
	    && !strcmp(repo->commondir, repo->gitdir)) {
		*out = 0;
		return 0;
	}

	if ((error = git3_str_joinpath(&gitdir_link, repo->gitdir, "gitdir")) < 0)
		return -1;

	/* A 'gitdir' file inside a git directory is currently
	 * only used when the repository is a working tree. */
	*out = !!git3_fs_path_exists(gitdir_link.ptr);

	git3_str_dispose(&gitdir_link);
	return error;
}

int git3_repository_open_ext(
	git3_repository **repo_ptr,
	const char *start_path,
	unsigned int flags,
	const char *ceiling_dirs)
{
	struct repo_paths paths = { GIT3_STR_INIT };
	git3_repository *repo = NULL;
	git3_config *config = NULL;
	unsigned is_worktree;
	int error;

	if (repo_ptr)
		*repo_ptr = NULL;

	error = find_repo(&paths, start_path, ceiling_dirs, flags);

	if (error < 0 || !repo_ptr)
		goto cleanup;

	repo = repository_alloc();
	GIT3_ERROR_CHECK_ALLOC(repo);

	repo->use_env = !!(flags & GIT3_REPOSITORY_OPEN_FROM_ENV);

	repo->gitdir = git3_str_detach(&paths.gitdir);
	GIT3_ERROR_CHECK_ALLOC(repo->gitdir);

	if (paths.gitlink.size) {
		repo->gitlink = git3_str_detach(&paths.gitlink);
		GIT3_ERROR_CHECK_ALLOC(repo->gitlink);
	}
	if (paths.commondir.size) {
		repo->commondir = git3_str_detach(&paths.commondir);
		GIT3_ERROR_CHECK_ALLOC(repo->commondir);
	}

	if ((error = repo_is_worktree(&is_worktree, repo)) < 0)
		goto cleanup;

	repo->is_worktree = is_worktree;

	error = obtain_config_and_set_oid_type(&config, repo);
	if (error < 0)
		goto cleanup;

	if ((error = load_grafts(repo)) < 0)
		goto cleanup;

	if ((flags & GIT3_REPOSITORY_OPEN_BARE) != 0) {
		repo->is_bare = 1;
	} else {
		if (config &&
		    ((error = load_config_data(repo, config)) < 0 ||
		     (error = load_workdir(repo, config, &paths.workdir)) < 0))
			goto cleanup;
	}

	if ((error = repo_load_namespace(repo)) < 0)
		goto cleanup;

	/*
	 * Ensure that the git directory and worktree are
	 * owned by the current user.
	 */
	if (git3_repository__validate_ownership &&
	    (error = validate_ownership(repo)) < 0)
		goto cleanup;

cleanup:
	repo_paths_dispose(&paths);
	git3_config_free(config);

	if (error < 0)
		git3_repository_free(repo);
	else if (repo_ptr)
		*repo_ptr = repo;

	return error;
}

int git3_repository_open(git3_repository **repo_out, const char *path)
{
	return git3_repository_open_ext(
		repo_out, path, GIT3_REPOSITORY_OPEN_NO_SEARCH, NULL);
}

int git3_repository_open_from_worktree(git3_repository **repo_out, git3_worktree *wt)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo = NULL;
	size_t len;
	int err;

	GIT3_ASSERT_ARG(repo_out);
	GIT3_ASSERT_ARG(wt);

	*repo_out = NULL;
	len = strlen(wt->gitlink_path);

	if (len <= 4 || strcasecmp(wt->gitlink_path + len - 4, ".git")) {
		err = -1;
		goto out;
	}

	if ((err = git3_str_set(&path, wt->gitlink_path, len - 4)) < 0)
		goto out;

	if ((err = git3_repository_open(&repo, path.ptr)) < 0)
		goto out;

	*repo_out = repo;

out:
	git3_str_dispose(&path);

	return err;
}

int git3_repository_wrap_odb(git3_repository **out, git3_odb *odb)
{
	git3_repository *repo;

	repo = repository_alloc();
	GIT3_ERROR_CHECK_ALLOC(repo);

	GIT3_ASSERT(git3_oid_type_is_valid(odb->options.oid_type));
	repo->oid_type = odb->options.oid_type;

	git3_repository_set_odb(repo, odb);
	*out = repo;

	return 0;
}

int git3_repository_discover(
	git3_buf *out,
	const char *start_path,
	int across_fs,
	const char *ceiling_dirs)
{
	struct repo_paths paths = { GIT3_STR_INIT };
	uint32_t flags = across_fs ? GIT3_REPOSITORY_OPEN_CROSS_FS : 0;
	int error;

	GIT3_ASSERT_ARG(start_path);

	if ((error = find_repo(&paths, start_path, ceiling_dirs, flags)) == 0)
		error = git3_buf_fromstr(out, &paths.gitdir);

	repo_paths_dispose(&paths);
	return error;
}

static int has_config_worktree(bool *out, git3_config *cfg)
{
	int worktreeconfig = 0, error;

	*out = false;

	error = git3_config_get_bool(&worktreeconfig, cfg, "extensions.worktreeconfig");

	if (error == 0)
		*out = worktreeconfig;
	else if (error == GIT3_ENOTFOUND)
		*out = false;
	else
		return error;

	return 0;
}

static int load_config(
	git3_config **out,
	git3_repository *repo,
	const char *global_config_path,
	const char *xdg_config_path,
	const char *system_config_path,
	const char *programdata_path)
{
	git3_str config_path = GIT3_STR_INIT;
	git3_config *cfg = NULL;
	git3_config_level_t write_order;
	bool has_worktree;
	int error;

	GIT3_ASSERT_ARG(out);

	if ((error = git3_config_new(&cfg)) < 0)
		return error;

	if (repo) {
		if ((error = git3_repository__item_path(&config_path, repo, GIT3_REPOSITORY_ITEM_CONFIG)) == 0)
			error = git3_config_add_file_ondisk(cfg, config_path.ptr, GIT3_CONFIG_LEVEL_LOCAL, repo, 0);

		if (error && error != GIT3_ENOTFOUND)
			goto on_error;

		if ((error = has_config_worktree(&has_worktree, cfg)) == 0 &&
		    has_worktree &&
		    (error = git3_repository__item_path(&config_path, repo, GIT3_REPOSITORY_ITEM_WORKTREE_CONFIG)) == 0)
			error = git3_config_add_file_ondisk(cfg, config_path.ptr, GIT3_CONFIG_LEVEL_WORKTREE, repo, 0);

		if (error && error != GIT3_ENOTFOUND)
			goto on_error;

		git3_str_dispose(&config_path);
	}

	if (global_config_path != NULL &&
		(error = git3_config_add_file_ondisk(
			cfg, global_config_path, GIT3_CONFIG_LEVEL_GLOBAL, repo, 0)) < 0 &&
		error != GIT3_ENOTFOUND)
		goto on_error;

	if (xdg_config_path != NULL &&
		(error = git3_config_add_file_ondisk(
			cfg, xdg_config_path, GIT3_CONFIG_LEVEL_XDG, repo, 0)) < 0 &&
		error != GIT3_ENOTFOUND)
		goto on_error;

	if (system_config_path != NULL &&
		(error = git3_config_add_file_ondisk(
			cfg, system_config_path, GIT3_CONFIG_LEVEL_SYSTEM, repo, 0)) < 0 &&
		error != GIT3_ENOTFOUND)
		goto on_error;

	if (programdata_path != NULL &&
		(error = git3_config_add_file_ondisk(
			cfg, programdata_path, GIT3_CONFIG_LEVEL_PROGRAMDATA, repo, 0)) < 0 &&
		error != GIT3_ENOTFOUND)
		goto on_error;

	git3_error_clear(); /* clear any lingering ENOTFOUND errors */

	write_order = GIT3_CONFIG_LEVEL_LOCAL;

	if ((error = git3_config_set_writeorder(cfg, &write_order, 1)) < 0)
		goto on_error;

	*out = cfg;
	return 0;

on_error:
	git3_str_dispose(&config_path);
	git3_config_free(cfg);
	*out = NULL;
	return error;
}

static const char *path_unless_empty(git3_str *buf)
{
	return git3_str_len(buf) > 0 ? git3_str_cstr(buf) : NULL;
}

GIT3_INLINE(int) config_path_system(git3_str *out, bool use_env)
{
	if (use_env) {
		git3_str no_system_buf = GIT3_STR_INIT;
		int no_system = 0;
		int error;

		error = git3__getenv(&no_system_buf, "GIT3_CONFIG_NOSYSTEM");

		if (error && error != GIT3_ENOTFOUND)
			return error;

		error = git3_config_parse_bool(&no_system, no_system_buf.ptr);
		git3_str_dispose(&no_system_buf);

		if (no_system)
			return 0;

		error = git3__getenv(out, "GIT3_CONFIG_SYSTEM");

		if (error == 0 || error != GIT3_ENOTFOUND)
			return 0;
	}

	git3_config__find_system(out);
	return 0;
}

GIT3_INLINE(int) config_path_global(git3_str *out, bool use_env)
{
	if (use_env) {
		int error = git3__getenv(out, "GIT3_CONFIG_GLOBAL");

		if (error == 0 || error != GIT3_ENOTFOUND)
			return 0;
	}

	git3_config__find_global(out);
	return 0;
}

int git3_repository_config__weakptr(git3_config **out, git3_repository *repo)
{
	int error = 0;

	if (repo->_config == NULL) {
		git3_str system_buf = GIT3_STR_INIT;
		git3_str global_buf = GIT3_STR_INIT;
		git3_str xdg_buf = GIT3_STR_INIT;
		git3_str programdata_buf = GIT3_STR_INIT;
		bool use_env = repo->use_env;
		git3_config *config;

		if (!(error = config_path_system(&system_buf, use_env)) &&
		    !(error = config_path_global(&global_buf, use_env))) {
			git3_config__find_xdg(&xdg_buf);
			git3_config__find_programdata(&programdata_buf);
		}

		if (!error) {
			/*
			 * If there is no global file, open a backend
			 * for it anyway.
			 */
			if (git3_str_len(&global_buf) == 0)
				git3_config__global_location(&global_buf);

			error = load_config(
				&config, repo,
				path_unless_empty(&global_buf),
				path_unless_empty(&xdg_buf),
				path_unless_empty(&system_buf),
				path_unless_empty(&programdata_buf));
		}

		if (!error) {
			GIT3_REFCOUNT_OWN(config, repo);

			if (git3_atomic_compare_and_swap(&repo->_config, NULL, config) != NULL) {
				GIT3_REFCOUNT_OWN(config, NULL);
				git3_config_free(config);
			}
		}

		git3_str_dispose(&global_buf);
		git3_str_dispose(&xdg_buf);
		git3_str_dispose(&system_buf);
		git3_str_dispose(&programdata_buf);
	}

	*out = repo->_config;
	return error;
}

int git3_repository_config(git3_config **out, git3_repository *repo)
{
	if (git3_repository_config__weakptr(out, repo) < 0)
		return -1;

	GIT3_REFCOUNT_INC(*out);
	return 0;
}

int git3_repository_config_snapshot(git3_config **out, git3_repository *repo)
{
	int error;
	git3_config *weak;

	if ((error = git3_repository_config__weakptr(&weak, repo)) < 0)
		return error;

	return git3_config_snapshot(out, weak);
}

int git3_repository_set_config(git3_repository *repo, git3_config *config)
{
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(config);

	set_config(repo, config);
	return 0;
}

static int repository_odb_path(git3_str *out, git3_repository *repo)
{
	int error = GIT3_ENOTFOUND;

	if (repo->use_env)
		error = git3__getenv(out, "GIT3_OBJECT_DIRECTORY");

	if (error == GIT3_ENOTFOUND)
		error = git3_repository__item_path(out, repo,
			GIT3_REPOSITORY_ITEM_OBJECTS);

	return error;
}

static int repository_odb_alternates(
	git3_odb *odb,
	git3_repository *repo)
{
	git3_str alternates = GIT3_STR_INIT;
	char *sep, *alt;
	int error;

	if (!repo->use_env)
		return 0;

	error = git3__getenv(&alternates, "GIT3_ALTERNATE_OBJECT_DIRECTORIES");

	if (error != 0)
		return (error == GIT3_ENOTFOUND) ? 0 : error;

	alt = alternates.ptr;

	while (*alt) {
		sep = strchr(alt, GIT3_PATH_LIST_SEPARATOR);

		if (sep)
			*sep = '\0';

		error = git3_odb_add_disk_alternate(odb, alt);

		if (sep)
			alt = sep + 1;
		else
			break;
	}

	git3_str_dispose(&alternates);
	return 0;
}

int git3_repository_odb__weakptr(git3_odb **out, git3_repository *repo)
{
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(out);

	*out = git3_atomic_load(repo->_odb);
	if (*out == NULL) {
		git3_str odb_path = GIT3_STR_INIT;
		git3_odb_options odb_opts = GIT3_ODB_OPTIONS_INIT;
		git3_odb *odb;

		odb_opts.oid_type = repo->oid_type;

		if ((error = repository_odb_path(&odb_path, repo)) < 0 ||
		    (error = git3_odb_new_ext(&odb, &odb_opts)) < 0 ||
		    (error = repository_odb_alternates(odb, repo)) < 0)
			return error;

		GIT3_REFCOUNT_OWN(odb, repo);

		if ((error = git3_odb__set_caps(odb, GIT3_ODB_CAP_FROM_OWNER)) < 0 ||
			(error = git3_odb__add_default_backends(odb, odb_path.ptr, 0, 0)) < 0) {
			git3_odb_free(odb);
			return error;
		}

		if (git3_atomic_compare_and_swap(&repo->_odb, NULL, odb) != NULL) {
			GIT3_REFCOUNT_OWN(odb, NULL);
			git3_odb_free(odb);
		}

		git3_str_dispose(&odb_path);
		*out = git3_atomic_load(repo->_odb);
	}

	return error;
}

int git3_repository_odb(git3_odb **out, git3_repository *repo)
{
	if (git3_repository_odb__weakptr(out, repo) < 0)
		return -1;

	GIT3_REFCOUNT_INC(*out);
	return 0;
}

int git3_repository_set_odb(git3_repository *repo, git3_odb *odb)
{
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(odb);

	set_odb(repo, odb);
	return 0;
}

int git3_repository_refdb__weakptr(git3_refdb **out, git3_repository *repo)
{
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	if (repo->_refdb == NULL) {
		git3_refdb *refdb;

		error = git3_refdb_open(&refdb, repo);
		if (!error) {
			GIT3_REFCOUNT_OWN(refdb, repo);

			if (git3_atomic_compare_and_swap(&repo->_refdb, NULL, refdb) != NULL) {
				GIT3_REFCOUNT_OWN(refdb, NULL);
				git3_refdb_free(refdb);
			}
		}
	}

	*out = repo->_refdb;
	return error;
}

int git3_repository_refdb(git3_refdb **out, git3_repository *repo)
{
	if (git3_repository_refdb__weakptr(out, repo) < 0)
		return -1;

	GIT3_REFCOUNT_INC(*out);
	return 0;
}

int git3_repository_set_refdb(git3_repository *repo, git3_refdb *refdb)
{
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(refdb);

	set_refdb(repo, refdb);
	return 0;
}

static int repository_index_path(git3_str *out, git3_repository *repo)
{
	int error = GIT3_ENOTFOUND;

	if (repo->use_env)
		error = git3__getenv(out, "GIT3_INDEX_FILE");

	if (error == GIT3_ENOTFOUND)
		error = git3_repository__item_path(out, repo,
			GIT3_REPOSITORY_ITEM_INDEX);

	return error;
}

int git3_repository_index__weakptr(git3_index **out, git3_repository *repo)
{
	int error = 0;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);

	if (repo->_index == NULL) {
		git3_str index_path = GIT3_STR_INIT;
		git3_index *index;
		git3_index_options index_opts = GIT3_INDEX_OPTIONS_INIT;

		if ((error = repository_index_path(&index_path, repo)) < 0)
			return error;

		index_opts.oid_type = repo->oid_type;
		error = git3_index_open_ext(&index, index_path.ptr, &index_opts);

		if (!error) {
			GIT3_REFCOUNT_OWN(index, repo);

			if (git3_atomic_compare_and_swap(&repo->_index, NULL, index) != NULL) {
				GIT3_REFCOUNT_OWN(index, NULL);
				git3_index_free(index);
			}

			error = git3_index_set_caps(repo->_index,
			                           GIT3_INDEX_CAPABILITY_FROM_OWNER);
		}

		git3_str_dispose(&index_path);
	}

	*out = repo->_index;
	return error;
}

int git3_repository_index(git3_index **out, git3_repository *repo)
{
	if (git3_repository_index__weakptr(out, repo) < 0)
		return -1;

	GIT3_REFCOUNT_INC(*out);
	return 0;
}

int git3_repository_set_index(git3_repository *repo, git3_index *index)
{
	GIT3_ASSERT_ARG(repo);
	set_index(repo, index);
	return 0;
}

int git3_repository_grafts__weakptr(git3_grafts **out, git3_repository *repo)
{
	GIT3_ASSERT_ARG(out && repo);
	GIT3_ASSERT(repo->grafts);
	*out = repo->grafts;
	return 0;
}

int git3_repository_shallow_grafts__weakptr(git3_grafts **out, git3_repository *repo)
{
	GIT3_ASSERT_ARG(out && repo);
	GIT3_ASSERT(repo->shallow_grafts);
	*out = repo->shallow_grafts;
	return 0;
}

int git3_repository_set_namespace(git3_repository *repo, const char *namespace)
{
	git3__free(repo->namespace);

	if (namespace == NULL) {
		repo->namespace = NULL;
		return 0;
	}

	return (repo->namespace = git3__strdup(namespace)) ? 0 : -1;
}

const char *git3_repository_get_namespace(git3_repository *repo)
{
	return repo->namespace;
}

#ifdef GIT3_WIN32
static int reserved_names_add8dot3(git3_repository *repo, const char *path)
{
	char *name = git3_win32_path_8dot3_name(path);
	const char *def = GIT3_DIR_SHORTNAME;
	const char *def_dot_git = DOT_GIT;
	size_t name_len, def_len = CONST_STRLEN(GIT3_DIR_SHORTNAME);
	size_t def_dot_git_len = CONST_STRLEN(DOT_GIT);
	git3_str *buf;

	if (!name)
		return 0;

	name_len = strlen(name);

	if ((name_len == def_len && memcmp(name, def, def_len) == 0) ||
		(name_len == def_dot_git_len && memcmp(name, def_dot_git, def_dot_git_len) == 0)) {
		git3__free(name);
		return 0;
	}

	if ((buf = git3_array_alloc(repo->reserved_names)) == NULL)
		return -1;

	git3_str_attach(buf, name, name_len);
	return true;
}

bool git3_repository__reserved_names(
	git3_str **out, size_t *outlen, git3_repository *repo, bool include_ntfs)
{
	GIT3_UNUSED(include_ntfs);

	if (repo->reserved_names.size == 0) {
		git3_str *buf;
		size_t i;

		/* Add the static defaults */
		for (i = 0; i < git3_repository__reserved_names_win32_len; i++) {
			if ((buf = git3_array_alloc(repo->reserved_names)) == NULL)
				goto on_error;

			buf->ptr = git3_repository__reserved_names_win32[i].ptr;
			buf->size = git3_repository__reserved_names_win32[i].size;
		}

		/* Try to add any repo-specific reserved names - the gitlink file
		 * within a submodule or the repository (if the repository directory
		 * is beneath the workdir).  These are typically `.git`, but should
		 * be protected in case they are not.  Note, repo and workdir paths
		 * are always prettified to end in `/`, so a prefixcmp is safe.
		 */
		if (!repo->is_bare) {
			int (*prefixcmp)(const char *, const char *);
			int error, ignorecase;

			error = git3_repository__configmap_lookup(
				&ignorecase, repo, GIT3_CONFIGMAP_IGNORECASE);
			prefixcmp = (error || ignorecase) ? git3__prefixcmp_icase :
				git3__prefixcmp;

			if (repo->gitlink &&
				reserved_names_add8dot3(repo, repo->gitlink) < 0)
				goto on_error;

			if (repo->gitdir &&
				prefixcmp(repo->gitdir, repo->workdir) == 0 &&
				reserved_names_add8dot3(repo, repo->gitdir) < 0)
				goto on_error;
		}
	}

	*out = repo->reserved_names.ptr;
	*outlen = repo->reserved_names.size;

	return true;

	/* Always give good defaults, even on OOM */
on_error:
	*out = git3_repository__reserved_names_win32;
	*outlen = git3_repository__reserved_names_win32_len;

	return false;
}
#else
bool git3_repository__reserved_names(
	git3_str **out, size_t *outlen, git3_repository *repo, bool include_ntfs)
{
	GIT3_UNUSED(repo);

	if (include_ntfs) {
		*out = git3_repository__reserved_names_win32;
		*outlen = git3_repository__reserved_names_win32_len;
	} else {
		*out = git3_repository__reserved_names_posix;
		*outlen = git3_repository__reserved_names_posix_len;
	}

	return true;
}
#endif

static int check_repositoryformatversion(int *version, git3_config *config)
{
	int error;

	error = git3_config_get_int32(version, config, "core.repositoryformatversion");

	/* git ignores this if the config variable isn't there */
	if (error == GIT3_ENOTFOUND)
		return 0;

	if (error < 0)
		return -1;

	if (*version < 0) {
		git3_error_set(GIT3_ERROR_REPOSITORY,
			"invalid repository version %d", *version);
	}

	if (GIT3_REPO_VERSION_MAX < *version) {
		git3_error_set(GIT3_ERROR_REPOSITORY,
			"unsupported repository version %d; only versions up to %d are supported",
			*version, GIT3_REPO_VERSION_MAX);
		return -1;
	}

	return 0;
}

static const char *builtin_extensions[] = {
	"noop",
	"objectformat",
	"worktreeconfig",
	"preciousobjects"
};

static git3_vector user_extensions = { 0, git3__strcmp_cb };

static int check_valid_extension(const git3_config_entry *entry, void *payload)
{
	git3_str cfg = GIT3_STR_INIT;
	bool reject;
	const char *extension;
	size_t i;
	int error = 0;

	GIT3_UNUSED(payload);

	git3_vector_foreach (&user_extensions, i, extension) {
		git3_str_clear(&cfg);

		/*
		 * Users can specify that they don't want to support an
		 * extension with a '!' prefix.
		 */
		if ((reject = (extension[0] == '!')) == true)
			extension = &extension[1];

		if ((error = git3_str_printf(&cfg, "extensions.%s", extension)) < 0)
			goto done;

		if (strcmp(entry->name, cfg.ptr) == 0) {
			if (reject)
				goto fail;

			goto done;
		}
	}

	for (i = 0; i < ARRAY_SIZE(builtin_extensions); i++) {
		git3_str_clear(&cfg);
		extension = builtin_extensions[i];

		if ((error = git3_str_printf(&cfg, "extensions.%s", extension)) < 0)
			goto done;

		if (strcmp(entry->name, cfg.ptr) == 0)
			goto done;
	}

fail:
	git3_error_set(GIT3_ERROR_REPOSITORY, "unsupported extension name %s", entry->name);
	error = -1;

done:
	git3_str_dispose(&cfg);
	return error;
}

static int check_extensions(git3_config *config, int version)
{
	if (version < 1)
		return 0;

	return git3_config_foreach_match(config, "^extensions\\.", check_valid_extension, NULL);
}

static int load_objectformat(git3_repository *repo, git3_config *config)
{
	/* For QED/libgit3: ALWAYS use SHA3-256, ignore config */
	(void)config; /* unused parameter */
	repo->oid_type = GIT3_OID_SHA3_256;
	return 0;
}

int git3_repository__set_objectformat(
	git3_repository *repo,
	git3_oid_t oid_type)
{
	git3_config *cfg;

	/*
	 * Older clients do not necessarily understand the
	 * `objectformat` extension, even when it's set to an
	 * object format that they understand (SHA1). Do not set
	 * the objectformat extension unless we're not using the
	 * default object format.
	 */
	if (oid_type == GIT3_OID_DEFAULT)
		return 0;

	if (!git3_repository_is_empty(repo) && repo->oid_type != oid_type) {
		git3_error_set(GIT3_ERROR_REPOSITORY,
			"cannot change object id type of existing repository");
		return -1;
	}

	if (git3_repository_config__weakptr(&cfg, repo) < 0)
		return -1;

	if (git3_config_set_int32(cfg,
			"core.repositoryformatversion", 1) < 0 ||
	    git3_config_set_string(cfg, "extensions.objectformat",
			git3_oid_type_name(oid_type)) < 0)
		return -1;

	/*
	 * During repo init, we may create some backends with the
	 * default oid type. Clear them so that we create them with
	 * the proper oid type.
	 */
	if (repo->oid_type != oid_type) {
		set_index(repo, NULL);
		set_odb(repo, NULL);
		set_refdb(repo, NULL);

		repo->oid_type = oid_type;
	}

	return 0;
}

int git3_repository__extensions(char ***out, size_t *out_len)
{
	git3_vector extensions;
	const char *builtin, *user;
	char *extension;
	size_t i, j;

	if (git3_vector_init(&extensions, 8, git3__strcmp_cb) < 0)
		return -1;

	for (i = 0; i < ARRAY_SIZE(builtin_extensions); i++) {
		bool match = false;

		builtin = builtin_extensions[i];

		git3_vector_foreach (&user_extensions, j, user) {
			if (user[0] == '!' && strcmp(builtin, &user[1]) == 0) {
				match = true;
				break;
			}
		}

		if (match)
			continue;

		if ((extension = git3__strdup(builtin)) == NULL ||
		    git3_vector_insert(&extensions, extension) < 0)
			return -1;
	}

	git3_vector_foreach (&user_extensions, i, user) {
		if (user[0] == '!')
			continue;

		if ((extension = git3__strdup(user)) == NULL ||
		    git3_vector_insert(&extensions, extension) < 0)
			return -1;
	}

	git3_vector_sort(&extensions);

	*out = (char **)git3_vector_detach(out_len, NULL, &extensions);
	return 0;
}

static int dup_ext_err(void **old, void *extension)
{
	GIT3_UNUSED(old);
	GIT3_UNUSED(extension);
	return GIT3_EEXISTS;
}

int git3_repository__set_extensions(const char **extensions, size_t len)
{
	char *extension;
	size_t i, j;
	int error;

	git3_repository__free_extensions();

	for (i = 0; i < len; i++) {
		bool is_builtin = false;

		for (j = 0; j < ARRAY_SIZE(builtin_extensions); j++) {
			if (strcmp(builtin_extensions[j], extensions[i]) == 0) {
				is_builtin = true;
				break;
			}
		}

		if (is_builtin)
			continue;

		if ((extension = git3__strdup(extensions[i])) == NULL)
			return -1;

		if ((error = git3_vector_insert_sorted(&user_extensions, extension, dup_ext_err)) < 0) {
			git3__free(extension);

			if (error != GIT3_EEXISTS)
				return -1;
		}
	}

	return 0;
}

void git3_repository__free_extensions(void)
{
	git3_vector_dispose_deep(&user_extensions);
}

int git3_repository_create_head(const char *git3_dir, const char *ref_name)
{
	git3_str ref_path = GIT3_STR_INIT;
	git3_filebuf ref = GIT3_FILEBUF_INIT;
	const char *fmt;
	int error;

	if ((error = git3_str_joinpath(&ref_path, git3_dir, GIT3_HEAD_FILE)) < 0 ||
	    (error = git3_filebuf_open(&ref, ref_path.ptr, 0, GIT3_REFS_FILE_MODE)) < 0)
		goto out;

	if (git3__prefixcmp(ref_name, GIT3_REFS_DIR) == 0)
		fmt = "ref: %s\n";
	else
		fmt = "ref: " GIT3_REFS_HEADS_DIR "%s\n";

	if ((error = git3_filebuf_printf(&ref, fmt, ref_name)) < 0 ||
	    (error = git3_filebuf_commit(&ref)) < 0)
		goto out;

out:
	git3_str_dispose(&ref_path);
	git3_filebuf_cleanup(&ref);
	return error;
}

static bool is_chmod_supported(const char *file_path)
{
	struct stat st1, st2;

	if (p_stat(file_path, &st1) < 0)
		return false;

	if (p_chmod(file_path, st1.st_mode ^ S_IXUSR) < 0)
		return false;

	if (p_stat(file_path, &st2) < 0)
		return false;

	return (st1.st_mode != st2.st_mode);
}

static bool is_filesystem_case_insensitive(const char *gitdir_path)
{
	git3_str path = GIT3_STR_INIT;
	int is_insensitive = -1;

	if (!git3_str_joinpath(&path, gitdir_path, "CoNfIg"))
		is_insensitive = git3_fs_path_exists(git3_str_cstr(&path));

	git3_str_dispose(&path);
	return is_insensitive;
}

/*
 * Return a configuration object with only the global and system
 * configurations; no repository-level configuration.
 */
static int load_global_config(git3_config **config, bool use_env)
{
	git3_str global_buf = GIT3_STR_INIT;
	git3_str xdg_buf = GIT3_STR_INIT;
	git3_str system_buf = GIT3_STR_INIT;
	git3_str programdata_buf = GIT3_STR_INIT;
	int error;

	if (!(error = config_path_system(&system_buf, use_env)) &&
	    !(error = config_path_global(&global_buf, use_env))) {
		git3_config__find_xdg(&xdg_buf);
		git3_config__find_programdata(&programdata_buf);

		error = load_config(config, NULL,
		                    path_unless_empty(&global_buf),
		                    path_unless_empty(&xdg_buf),
		                    path_unless_empty(&system_buf),
		                    path_unless_empty(&programdata_buf));
	}

	git3_str_dispose(&global_buf);
	git3_str_dispose(&xdg_buf);
	git3_str_dispose(&system_buf);
	git3_str_dispose(&programdata_buf);

	return error;
}

static bool are_symlinks_supported(const char *wd_path, bool use_env)
{
	git3_config *config = NULL;
	int symlinks = 0;

	/*
	 * To emulate Git for Windows, symlinks on Windows must be explicitly
	 * opted-in.  We examine the system configuration for a core.symlinks
	 * set to true.  If found, we then examine the filesystem to see if
	 * symlinks are _actually_ supported by the current user.  If that is
	 * _not_ set, then we do not test or enable symlink support.
	 */
#ifdef GIT3_WIN32
	if (load_global_config(&config, use_env) < 0 ||
	    git3_config_get_bool(&symlinks, config, "core.symlinks") < 0 ||
	    !symlinks)
		goto done;
#else
	GIT3_UNUSED(use_env);
#endif

	if (!(symlinks = git3_fs_path_supports_symlinks(wd_path)))
		goto done;

done:
	git3_config_free(config);
	return symlinks != 0;
}

static int create_empty_file(const char *path, mode_t mode)
{
	int fd;

	if ((fd = p_creat(path, mode)) < 0) {
		git3_error_set(GIT3_ERROR_OS, "error while creating '%s'", path);
		return -1;
	}

	if (p_close(fd) < 0) {
		git3_error_set(GIT3_ERROR_OS, "error while closing '%s'", path);
		return -1;
	}

	return 0;
}

static int repo_local_config(
	git3_config **out,
	git3_str *config_dir,
	git3_repository *repo,
	const char *repo_dir)
{
	int error = 0;
	git3_config *parent;
	const char *cfg_path;

	if (git3_str_joinpath(config_dir, repo_dir, GIT3_CONFIG_FILENAME_INREPO) < 0)
		return -1;
	cfg_path = git3_str_cstr(config_dir);

	/* make LOCAL config if missing */
	if (!git3_fs_path_isfile(cfg_path) &&
		(error = create_empty_file(cfg_path, GIT3_CONFIG_FILE_MODE)) < 0)
		return error;

	/* if no repo, just open that file directly */
	if (!repo)
		return git3_config_open_ondisk(out, cfg_path);

	/* otherwise, open parent config and get that level */
	if ((error = git3_repository_config__weakptr(&parent, repo)) < 0)
		return error;

	if (git3_config_open_level(out, parent, GIT3_CONFIG_LEVEL_LOCAL) < 0) {
		git3_error_clear();

		if (!(error = git3_config_add_file_ondisk(
				parent, cfg_path, GIT3_CONFIG_LEVEL_LOCAL, repo, false)))
			error = git3_config_open_level(out, parent, GIT3_CONFIG_LEVEL_LOCAL);
	}

	git3_config_free(parent);

	return error;
}

static int repo_init_fs_configs(
	git3_config *cfg,
	const char *cfg_path,
	const char *repo_dir,
	const char *work_dir,
	bool update_ignorecase,
	bool use_env)
{
	int error = 0;

	if (!work_dir)
		work_dir = repo_dir;

	if ((error = git3_config_set_bool(
			cfg, "core.filemode", is_chmod_supported(cfg_path))) < 0)
		return error;

	if (!are_symlinks_supported(work_dir, use_env)) {
		if ((error = git3_config_set_bool(cfg, "core.symlinks", false)) < 0)
			return error;
	} else if (git3_config_delete_entry(cfg, "core.symlinks") < 0)
		git3_error_clear();

	if (update_ignorecase) {
		if (is_filesystem_case_insensitive(repo_dir)) {
			if ((error = git3_config_set_bool(cfg, "core.ignorecase", true)) < 0)
				return error;
		} else if (git3_config_delete_entry(cfg, "core.ignorecase") < 0)
			git3_error_clear();
	}

#ifdef GIT3_I18N_ICONV
	if ((error = git3_config_set_bool(
			cfg, "core.precomposeunicode",
			git3_fs_path_does_decompose_unicode(work_dir))) < 0)
		return error;
	/* on non-iconv platforms, don't even set core.precomposeunicode */
#endif

	return 0;
}

static int repo_init_config(
	const char *repo_dir,
	const char *work_dir,
	uint32_t flags,
	uint32_t mode,
	git3_oid_t oid_type)
{
	int error = 0;
	git3_str cfg_path = GIT3_STR_INIT, worktree_path = GIT3_STR_INIT;
	git3_config *config = NULL;
	bool is_bare = ((flags & GIT3_REPOSITORY_INIT_BARE) != 0);
	bool is_reinit = ((flags & GIT3_REPOSITORY_INIT__IS_REINIT) != 0);
	bool use_env = ((flags & GIT3_REPOSITORY_OPEN_FROM_ENV) != 0);
	int version = GIT3_REPO_VERSION_DEFAULT;

	if ((error = repo_local_config(&config, &cfg_path, NULL, repo_dir)) < 0)
		goto cleanup;

	if (is_reinit &&
	    (error = check_repositoryformatversion(&version, config)) < 0)
		goto cleanup;

	if ((error = check_extensions(config, version)) < 0)
		goto cleanup;

#define SET_REPO_CONFIG(TYPE, NAME, VAL) do { \
	if ((error = git3_config_set_##TYPE(config, NAME, VAL)) < 0) \
		goto cleanup; } while (0)

	SET_REPO_CONFIG(bool, "core.bare", is_bare);
	SET_REPO_CONFIG(int32, "core.repositoryformatversion", version);

	if ((error = repo_init_fs_configs(
			config, cfg_path.ptr, repo_dir, work_dir,
			!is_reinit, use_env)) < 0)
		goto cleanup;

	if (!is_bare) {
		SET_REPO_CONFIG(bool, "core.logallrefupdates", true);

		if (!(flags & GIT3_REPOSITORY_INIT__NATURAL_WD)) {
			if ((error = git3_str_sets(&worktree_path, work_dir)) < 0)
				goto cleanup;

			if ((flags & GIT3_REPOSITORY_INIT_RELATIVE_GITLINK))
				if ((error = git3_fs_path_make_relative(&worktree_path, repo_dir)) < 0)
					goto cleanup;

			SET_REPO_CONFIG(string, "core.worktree", worktree_path.ptr);
		} else if (is_reinit) {
			if (git3_config_delete_entry(config, "core.worktree") < 0)
				git3_error_clear();
		}
	}

	if (mode == GIT3_REPOSITORY_INIT_SHARED_GROUP) {
		SET_REPO_CONFIG(int32, "core.sharedrepository", 1);
		SET_REPO_CONFIG(bool, "receive.denyNonFastforwards", true);
	}
	else if (mode == GIT3_REPOSITORY_INIT_SHARED_ALL) {
		SET_REPO_CONFIG(int32, "core.sharedrepository", 2);
		SET_REPO_CONFIG(bool, "receive.denyNonFastforwards", true);
	}

	if (oid_type != GIT3_OID_DEFAULT) {
		SET_REPO_CONFIG(int32, "core.repositoryformatversion", 1);
		SET_REPO_CONFIG(string, "extensions.objectformat", git3_oid_type_name(oid_type));
	}

cleanup:
	git3_str_dispose(&cfg_path);
	git3_str_dispose(&worktree_path);
	git3_config_free(config);

	return error;
}

static int repo_reinit_submodule_fs(git3_submodule *sm, const char *n, void *p)
{
	git3_repository *smrepo = NULL;
	GIT3_UNUSED(n); GIT3_UNUSED(p);

	if (git3_submodule_open(&smrepo, sm) < 0 ||
		git3_repository_reinit_filesystem(smrepo, true) < 0)
		git3_error_clear();
	git3_repository_free(smrepo);

	return 0;
}

int git3_repository_reinit_filesystem(git3_repository *repo, int recurse)
{
	int error = 0;
	git3_str path = GIT3_STR_INIT;
	git3_config *config = NULL;
	const char *repo_dir = git3_repository_path(repo);

	if (!(error = repo_local_config(&config, &path, repo, repo_dir)))
		error = repo_init_fs_configs(config, path.ptr, repo_dir,
			git3_repository_workdir(repo), true, repo->use_env);

	git3_config_free(config);
	git3_str_dispose(&path);

	git3_repository__configmap_lookup_cache_clear(repo);

	if (!repo->is_bare && recurse)
		(void)git3_submodule_foreach(repo, repo_reinit_submodule_fs, NULL);

	return error;
}

static int repo_write_template(
	const char *git3_dir,
	bool allow_overwrite,
	const char *file,
	mode_t mode,
	bool hidden,
	const char *content)
{
	git3_str path = GIT3_STR_INIT;
	int fd, error = 0, flags;

	if (git3_str_joinpath(&path, git3_dir, file) < 0)
		return -1;

	if (allow_overwrite)
		flags = O_WRONLY | O_CREAT | O_TRUNC;
	else
		flags = O_WRONLY | O_CREAT | O_EXCL;

	fd = p_open(git3_str_cstr(&path), flags, mode);

	if (fd >= 0) {
		error = p_write(fd, content, strlen(content));

		p_close(fd);
	}
	else if (errno != EEXIST)
		error = fd;

#ifdef GIT3_WIN32
	if (!error && hidden) {
		if (git3_win32__set_hidden(path.ptr, true) < 0)
			error = -1;
	}
#else
	GIT3_UNUSED(hidden);
#endif

	git3_str_dispose(&path);

	if (error)
		git3_error_set(GIT3_ERROR_OS,
			"failed to initialize repository with template '%s'", file);

	return error;
}

static int repo_write_gitlink(
	const char *in_dir, const char *to_repo, bool use_relative_path)
{
	int error;
	git3_str buf = GIT3_STR_INIT;
	git3_str path_to_repo = GIT3_STR_INIT;
	struct stat st;

	git3_fs_path_dirname_r(&buf, to_repo);
	git3_fs_path_to_dir(&buf);
	if (git3_str_oom(&buf))
		return -1;

	/* don't write gitlink to natural workdir */
	if (git3__suffixcmp(to_repo, "/" DOT_GIT "/") == 0 &&
		strcmp(in_dir, buf.ptr) == 0)
	{
		error = GIT3_PASSTHROUGH;
		goto cleanup;
	}

	if ((error = git3_str_joinpath(&buf, in_dir, DOT_GIT)) < 0)
		goto cleanup;

	if (!p_stat(buf.ptr, &st) && !S_ISREG(st.st_mode)) {
		git3_error_set(GIT3_ERROR_REPOSITORY,
			"cannot overwrite gitlink file into path '%s'", in_dir);
		error = GIT3_EEXISTS;
		goto cleanup;
	}

	git3_str_clear(&buf);

	error = git3_str_sets(&path_to_repo, to_repo);

	if (!error && use_relative_path)
		error = git3_fs_path_make_relative(&path_to_repo, in_dir);

	if (!error)
		error = git3_str_printf(&buf, "%s %s\n", GIT3_FILE_CONTENT_PREFIX, path_to_repo.ptr);

	if (!error)
		error = repo_write_template(in_dir, true, DOT_GIT, 0666, true, buf.ptr);

cleanup:
	git3_str_dispose(&buf);
	git3_str_dispose(&path_to_repo);
	return error;
}

static mode_t pick_dir_mode(git3_repository_init_options *opts)
{
	if (opts->mode == GIT3_REPOSITORY_INIT_SHARED_UMASK)
		return 0777;
	if (opts->mode == GIT3_REPOSITORY_INIT_SHARED_GROUP)
		return (0775 | S_ISGID);
	if (opts->mode == GIT3_REPOSITORY_INIT_SHARED_ALL)
		return (0777 | S_ISGID);
	return opts->mode;
}

#include "repo_template.h"

static int repo_init_structure(
	const char *repo_dir,
	const char *work_dir,
	git3_repository_init_options *opts)
{
	int error = 0;
	repo_template_item *tpl;
	bool external_tpl =
		 opts->template_path != NULL ||
		(opts->flags & GIT3_REPOSITORY_INIT_EXTERNAL_TEMPLATE) != 0;
	mode_t dmode = pick_dir_mode(opts);
	bool chmod = opts->mode != GIT3_REPOSITORY_INIT_SHARED_UMASK;

	/* Hide the ".git" directory */
#ifdef GIT3_WIN32
	if ((opts->flags & GIT3_REPOSITORY_INIT__HAS_DOTGIT) != 0) {
		if (git3_win32__set_hidden(repo_dir, true) < 0) {
			git3_error_set(GIT3_ERROR_OS,
				"failed to mark Git repository folder as hidden");
			return -1;
		}
	}
#endif

	/* Create the .git gitlink if appropriate */
	if ((opts->flags & GIT3_REPOSITORY_INIT_BARE) == 0 &&
		(opts->flags & GIT3_REPOSITORY_INIT__NATURAL_WD) == 0)
	{
		if (repo_write_gitlink(work_dir, repo_dir, opts->flags & GIT3_REPOSITORY_INIT_RELATIVE_GITLINK) < 0)
			return -1;
	}

	/* Copy external template if requested */
	if (external_tpl) {
		git3_config *cfg = NULL;
		const char *tdir = NULL;
		bool default_template = false;
		git3_str template_buf = GIT3_STR_INIT;

		if (opts->template_path)
			tdir = opts->template_path;
		else if ((error = git3_config_open_default(&cfg)) >= 0) {
			if (!git3_config__get_path(&template_buf, cfg, "init.templatedir"))
				tdir = template_buf.ptr;
			git3_error_clear();
		}

		if (!tdir) {
			if (!(error = git3_sysdir_find_template_dir(&template_buf)))
				tdir = template_buf.ptr;
			default_template = true;
		}

		/*
		 * If tdir was the empty string, treat it like tdir was a path to an
		 * empty directory (so, don't do any copying). This is the behavior
		 * that git(1) exhibits, although it doesn't seem to be officially
		 * documented.
		 */
		if (tdir && git3__strcmp(tdir, "") != 0) {
			uint32_t cpflags = GIT3_CPDIR_COPY_SYMLINKS |
				GIT3_CPDIR_SIMPLE_TO_MODE |
				GIT3_CPDIR_COPY_DOTFILES;
			if (opts->mode != GIT3_REPOSITORY_INIT_SHARED_UMASK)
					cpflags |= GIT3_CPDIR_CHMOD_DIRS;
			error = git3_futils_cp_r(tdir, repo_dir, cpflags, dmode);
		}

		git3_str_dispose(&template_buf);
		git3_config_free(cfg);

		/* If tdir does not exist, then do not error out. This matches the
		 * behaviour of git(1), which just prints a warning and continues.
		 * TODO: issue warning when warning API is available.
		 * `git` prints to stderr: 'warning: templates not found in /path/to/tdir'
		 */
		if (error < 0) {
			if (!default_template && error != GIT3_ENOTFOUND)
				return error;

			/* if template was default, ignore error and use internal */
			git3_error_clear();
			external_tpl = false;
			error = 0;
		}
	}

	/* Copy internal template
	 * - always ensure existence of dirs
	 * - only create files if no external template was specified
	 */
	for (tpl = repo_template; !error && tpl->path; ++tpl) {
		if (!tpl->content) {
			uint32_t mkdir_flags = GIT3_MKDIR_PATH;
			if (chmod)
				mkdir_flags |= GIT3_MKDIR_CHMOD;

			error = git3_futils_mkdir_relative(
				tpl->path, repo_dir, dmode, mkdir_flags, NULL);
		}
		else if (!external_tpl) {
			const char *content = tpl->content;

			if (opts->description && strcmp(tpl->path, GIT3_DESC_FILE) == 0)
				content = opts->description;

			error = repo_write_template(
				repo_dir, false, tpl->path, tpl->mode, false, content);
		}
	}

	return error;
}

static int mkdir_parent(git3_str *buf, uint32_t mode, bool skip2)
{
	/* When making parent directories during repository initialization
	 * don't try to set gid or grant world write access
	 */
	return git3_futils_mkdir(
		buf->ptr, mode & ~(S_ISGID | 0002),
		GIT3_MKDIR_PATH | GIT3_MKDIR_VERIFY_DIR |
		(skip2 ? GIT3_MKDIR_SKIP_LAST2 : GIT3_MKDIR_SKIP_LAST));
}

static int repo_init_directories(
	git3_str *repo_path,
	git3_str *wd_path,
	const char *given_repo,
	git3_repository_init_options *opts)
{
	int error = 0;
	bool is_bare, add_dotgit, has_dotgit, natural_wd;
	mode_t dirmode;

	/* There are three possible rules for what we are allowed to create:
	 * - MKPATH means anything we need
	 * - MKDIR means just the .git directory and its parent and the workdir
	 * - Neither means only the .git directory can be created
	 *
	 * There are 5 "segments" of path that we might need to deal with:
	 * 1. The .git directory
	 * 2. The parent of the .git directory
	 * 3. Everything above the parent of the .git directory
	 * 4. The working directory (often the same as #2)
	 * 5. Everything above the working directory (often the same as #3)
	 *
	 * For all directories created, we start with the init_mode value for
	 * permissions and then strip off bits in some cases:
	 *
	 * For MKPATH, we create #3 (and #5) paths without S_ISGID or S_IWOTH
	 * For MKPATH and MKDIR, we create #2 (and #4) without S_ISGID
	 * For all rules, we create #1 using the untouched init_mode
	 */

	/* set up repo path */

	is_bare = ((opts->flags & GIT3_REPOSITORY_INIT_BARE) != 0);

	add_dotgit =
		!is_bare && !opts->workdir_path &&
		git3__suffixcmp(given_repo, "/" DOT_GIT) != 0 &&
		git3__suffixcmp(given_repo, "/" GIT3_DIR) != 0;

	if (git3_str_joinpath(repo_path, given_repo, add_dotgit ? GIT3_DIR : "") < 0)
		return -1;

	git3_fs_path_mkposix(repo_path->ptr);

	has_dotgit = (git3__suffixcmp(repo_path->ptr, "/" GIT3_DIR) == 0);
	if (has_dotgit)
		opts->flags |= GIT3_REPOSITORY_INIT__HAS_DOTGIT;

	/* set up workdir path */

	if (!is_bare) {
		if (opts->workdir_path) {
			if (git3_fs_path_join_unrooted(
					wd_path, opts->workdir_path, repo_path->ptr, NULL) < 0)
				return -1;
		} else if (has_dotgit) {
			if (git3_fs_path_dirname_r(wd_path, repo_path->ptr) < 0)
				return -1;
		} else {
			git3_error_set(GIT3_ERROR_REPOSITORY, "cannot pick working directory"
				" for non-bare repository that isn't a '.git' directory");
			return -1;
		}

		if (git3_fs_path_to_dir(wd_path) < 0)
			return -1;
	} else {
		git3_str_clear(wd_path);
	}

	natural_wd =
		has_dotgit &&
		wd_path->size > 0 &&
		wd_path->size + strlen(GIT3_DIR) == repo_path->size &&
		memcmp(repo_path->ptr, wd_path->ptr, wd_path->size) == 0;
	if (natural_wd)
		opts->flags |= GIT3_REPOSITORY_INIT__NATURAL_WD;

	/* create directories as needed / requested */

	dirmode = pick_dir_mode(opts);

	if ((opts->flags & GIT3_REPOSITORY_INIT_MKPATH) != 0) {
		/* create path #5 */
		if (wd_path->size > 0 &&
			(error = mkdir_parent(wd_path, dirmode, false)) < 0)
			return error;

		/* create path #3 (if not the same as #5) */
		if (!natural_wd &&
			(error = mkdir_parent(repo_path, dirmode, has_dotgit)) < 0)
			return error;
	}

	if ((opts->flags & GIT3_REPOSITORY_INIT_MKDIR) != 0 ||
		(opts->flags & GIT3_REPOSITORY_INIT_MKPATH) != 0)
	{
		/* create path #4 */
		if (wd_path->size > 0 &&
			(error = git3_futils_mkdir(
				wd_path->ptr, dirmode & ~S_ISGID,
				GIT3_MKDIR_VERIFY_DIR)) < 0)
			return error;

		/* create path #2 (if not the same as #4) */
		if (!natural_wd &&
			(error = git3_futils_mkdir(
				repo_path->ptr, dirmode & ~S_ISGID,
				GIT3_MKDIR_VERIFY_DIR | GIT3_MKDIR_SKIP_LAST)) < 0)
			return error;
	}

	if ((opts->flags & GIT3_REPOSITORY_INIT_MKDIR) != 0 ||
		(opts->flags & GIT3_REPOSITORY_INIT_MKPATH) != 0 ||
		has_dotgit)
	{
		/* create path #1 */
		error = git3_futils_mkdir(repo_path->ptr, dirmode,
			GIT3_MKDIR_VERIFY_DIR | ((dirmode & S_ISGID) ? GIT3_MKDIR_CHMOD : 0));
	}

	/* prettify both directories now that they are created */

	if (!error) {
		error = git3_fs_path_prettify_dir(repo_path, repo_path->ptr, NULL);

		if (!error && wd_path->size > 0)
			error = git3_fs_path_prettify_dir(wd_path, wd_path->ptr, NULL);
	}

	return error;
}

static int repo_init_head(const char *repo_dir, const char *given)
{
	git3_config *cfg = NULL;
	git3_str head_path = GIT3_STR_INIT, cfg_branch = GIT3_STR_INIT;
	const char *initial_head = NULL;
	int error;

	if ((error = git3_str_joinpath(&head_path, repo_dir, GIT3_HEAD_FILE)) < 0)
		goto out;

	/*
	 * A template may have set a HEAD; use that unless it's been
	 * overridden by the caller's given initial head setting.
	 */
	if (git3_fs_path_exists(head_path.ptr) && !given)
		goto out;

	if (given) {
		initial_head = given;
	} else if ((error = git3_config_open_default(&cfg)) >= 0 &&
	           (error = git3_config__get_string_buf(&cfg_branch, cfg, "init.defaultbranch")) >= 0 &&
	           *cfg_branch.ptr) {
		initial_head = cfg_branch.ptr;
	}

	if (!initial_head)
		initial_head = GIT3_BRANCH_DEFAULT;

	error = git3_repository_create_head(repo_dir, initial_head);

out:
	git3_config_free(cfg);
	git3_str_dispose(&head_path);
	git3_str_dispose(&cfg_branch);

	return error;
}

static int repo_init_create_origin(git3_repository *repo, const char *url)
{
	int error;
	git3_remote *remote;

	if (!(error = git3_remote_create(&remote, repo, GIT3_REMOTE_ORIGIN, url))) {
		git3_remote_free(remote);
	}

	return error;
}

int git3_repository_init(
	git3_repository **repo_out, const char *path, unsigned is_bare)
{
	git3_repository_init_options opts = GIT3_REPOSITORY_INIT_OPTIONS_INIT;

	opts.flags = GIT3_REPOSITORY_INIT_MKPATH; /* don't love this default */
	if (is_bare)
		opts.flags |= GIT3_REPOSITORY_INIT_BARE;

	return git3_repository_init_ext(repo_out, path, &opts);
}

int git3_repository_init_ext(
	git3_repository **out,
	const char *given_repo,
	git3_repository_init_options *opts)
{
	git3_str repo_path = GIT3_STR_INIT, wd_path = GIT3_STR_INIT,
		common_path = GIT3_STR_INIT;
	const char *wd;
	bool is_valid;
	git3_oid_t oid_type = GIT3_OID_DEFAULT;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(given_repo);
	GIT3_ASSERT_ARG(opts);

	GIT3_ERROR_CHECK_VERSION(opts, GIT3_REPOSITORY_INIT_OPTIONS_VERSION, "git3_repository_init_options");

#ifdef GIT3_EXPERIMENTAL_SHA256
	if (opts->oid_type)
		oid_type = opts->oid_type;
#endif

	if ((error = repo_init_directories(&repo_path, &wd_path, given_repo, opts)) < 0)
		goto out;

	wd = (opts->flags & GIT3_REPOSITORY_INIT_BARE) ? NULL : git3_str_cstr(&wd_path);

	if ((error = is_valid_repository_path(&is_valid, &repo_path, &common_path, opts->flags)) < 0)
		goto out;

	if (is_valid) {
		if ((opts->flags & GIT3_REPOSITORY_INIT_NO_REINIT) != 0) {
			git3_error_set(GIT3_ERROR_REPOSITORY,
				"attempt to reinitialize '%s'", given_repo);
			error = GIT3_EEXISTS;
			goto out;
		}

		opts->flags |= GIT3_REPOSITORY_INIT__IS_REINIT;

		if ((error = repo_init_config(repo_path.ptr, wd, opts->flags, opts->mode, oid_type)) < 0)
			goto out;

		/* TODO: reinitialize the templates */
	} else {
		if ((error = repo_init_structure(repo_path.ptr, wd, opts)) < 0 ||
		    (error = repo_init_config(repo_path.ptr, wd, opts->flags, opts->mode, oid_type)) < 0 ||
		    (error = repo_init_head(repo_path.ptr, opts->initial_head)) < 0)
			goto out;
	}

	if ((error = git3_repository_open(out, repo_path.ptr)) < 0)
		goto out;

	if (opts->origin_url &&
	    (error = repo_init_create_origin(*out, opts->origin_url)) < 0)
		goto out;

out:
	git3_str_dispose(&common_path);
	git3_str_dispose(&repo_path);
	git3_str_dispose(&wd_path);

	return error;
}

int git3_repository_head_detached(git3_repository *repo)
{
	git3_reference *ref;
	git3_odb *odb = NULL;
	int exists;

	if (git3_repository_odb__weakptr(&odb, repo) < 0)
		return -1;

	if (git3_reference_lookup(&ref, repo, GIT3_HEAD_FILE) < 0)
		return -1;

	if (git3_reference_type(ref) == GIT3_REFERENCE_SYMBOLIC) {
		git3_reference_free(ref);
		return 0;
	}

	exists = git3_odb_exists(odb, git3_reference_target(ref));

	git3_reference_free(ref);
	return exists;
}

int git3_repository_head_detached_for_worktree(git3_repository *repo, const char *name)
{
	git3_reference *ref = NULL;
	int error;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(name);

	if ((error = git3_repository_head_for_worktree(&ref, repo, name)) < 0)
		goto out;

	error = (git3_reference_type(ref) != GIT3_REFERENCE_SYMBOLIC);
out:
	git3_reference_free(ref);

	return error;
}

int git3_repository_head(git3_reference **head_out, git3_repository *repo)
{
	git3_reference *head;
	int error;

	GIT3_ASSERT_ARG(head_out);

	if ((error = git3_reference_lookup(&head, repo, GIT3_HEAD_FILE)) < 0)
		return error;

	if (git3_reference_type(head) == GIT3_REFERENCE_DIRECT) {
		*head_out = head;
		return 0;
	}

	error = git3_reference_lookup_resolved(head_out, repo, git3_reference_symbolic_target(head), -1);
	git3_reference_free(head);

	return error == GIT3_ENOTFOUND ? GIT3_EUNBORNBRANCH : error;
}

int git3_repository_head_for_worktree(git3_reference **out, git3_repository *repo, const char *name)
{
	git3_repository *worktree_repo = NULL;
	git3_worktree *worktree = NULL;
	git3_reference *head = NULL;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(name);

	*out = NULL;

	if ((error = git3_worktree_lookup(&worktree, repo, name)) < 0 ||
	    (error = git3_repository_open_from_worktree(&worktree_repo, worktree)) < 0 ||
	    (error = git3_reference_lookup(&head, worktree_repo, GIT3_HEAD_FILE)) < 0)
		goto out;

	if (git3_reference_type(head) != GIT3_REFERENCE_DIRECT) {
		if ((error = git3_reference_lookup_resolved(out, worktree_repo, git3_reference_symbolic_target(head), -1)) < 0)
			goto out;
	} else {
		*out = head;
		head = NULL;
	}

out:
	git3_reference_free(head);
	git3_worktree_free(worktree);
	git3_repository_free(worktree_repo);
	return error;
}

int git3_repository_foreach_worktree(git3_repository *repo,
				    git3_repository_foreach_worktree_cb cb,
				    void *payload)
{
	git3_strarray worktrees = {0};
	git3_repository *worktree_repo = NULL;
	git3_worktree *worktree = NULL;
	int error;
	size_t i;

	/* apply operation to repository supplied when commondir is empty, implying there's
	 * no linked worktrees to iterate, which can occur when using custom odb/refdb
	 */
	if (!repo->commondir)
		return cb(repo, payload);

	if ((error = git3_repository_open(&worktree_repo, repo->commondir)) < 0 ||
	    (error = cb(worktree_repo, payload) != 0))
		goto out;

	git3_repository_free(worktree_repo);
	worktree_repo = NULL;

	if ((error = git3_worktree_list(&worktrees, repo)) < 0)
		goto out;

	for (i = 0; i < worktrees.count; i++) {
		git3_repository_free(worktree_repo);
		worktree_repo = NULL;
		git3_worktree_free(worktree);
		worktree = NULL;

		if ((error = git3_worktree_lookup(&worktree, repo, worktrees.strings[i]) < 0) ||
		    (error = git3_repository_open_from_worktree(&worktree_repo, worktree)) < 0) {
			if (error != GIT3_ENOTFOUND)
				goto out;
			error = 0;
			continue;
		}

		if ((error = cb(worktree_repo, payload)) != 0)
			goto out;
	}

out:
	git3_strarray_dispose(&worktrees);
	git3_repository_free(worktree_repo);
	git3_worktree_free(worktree);
	return error;
}

int git3_repository_head_unborn(git3_repository *repo)
{
	git3_reference *ref = NULL;
	int error;

	error = git3_repository_head(&ref, repo);
	git3_reference_free(ref);

	if (error == GIT3_EUNBORNBRANCH) {
		git3_error_clear();
		return 1;
	}

	if (error < 0)
		return -1;

	return 0;
}

static int repo_contains_no_reference(git3_repository *repo)
{
	git3_reference_iterator *iter;
	const char *refname;
	int error;

	if ((error = git3_reference_iterator_new(&iter, repo)) < 0)
		return error;

	error = git3_reference_next_name(&refname, iter);
	git3_reference_iterator_free(iter);

	if (error == GIT3_ITEROVER)
		return 1;

	return error;
}

int git3_repository_initialbranch(git3_str *out, git3_repository *repo)
{
	git3_config *config;
	git3_config_entry *entry = NULL;
	const char *branch;
	int valid, error;

	if ((error = git3_repository_config__weakptr(&config, repo)) < 0)
		return error;

	if ((error = git3_config_get_entry(&entry, config, "init.defaultbranch")) == 0 &&
		*entry->value) {
		branch = entry->value;
	}
	else if (!error || error == GIT3_ENOTFOUND) {
		branch = GIT3_BRANCH_DEFAULT;
	}
	else {
		goto done;
	}

	if ((error = git3_str_puts(out, GIT3_REFS_HEADS_DIR)) < 0 ||
	    (error = git3_str_puts(out, branch)) < 0 ||
	    (error = git3_reference_name_is_valid(&valid, out->ptr)) < 0)
	    goto done;

	if (!valid) {
		git3_error_set(GIT3_ERROR_INVALID, "the value of init.defaultBranch is not a valid branch name");
		error = -1;
	}

done:
	git3_config_entry_free(entry);
	return error;
}

int git3_repository_is_empty(git3_repository *repo)
{
	git3_reference *head = NULL;
	git3_str initialbranch = GIT3_STR_INIT;
	int result = 0;

	if ((result = git3_reference_lookup(&head, repo, GIT3_HEAD_FILE)) < 0 ||
	    (result = git3_repository_initialbranch(&initialbranch, repo)) < 0)
		goto done;

	result = (git3_reference_type(head) == GIT3_REFERENCE_SYMBOLIC &&
	          strcmp(git3_reference_symbolic_target(head), initialbranch.ptr) == 0 &&
	          repo_contains_no_reference(repo));

done:
	git3_reference_free(head);
	git3_str_dispose(&initialbranch);

	return result;
}

static const char *resolved_parent_path(const git3_repository *repo, git3_repository_item_t item, git3_repository_item_t fallback)
{
	const char *parent;

	switch (item) {
		case GIT3_REPOSITORY_ITEM_GITDIR:
			parent = git3_repository_path(repo);
			break;
		case GIT3_REPOSITORY_ITEM_WORKDIR:
			parent = git3_repository_workdir(repo);
			break;
		case GIT3_REPOSITORY_ITEM_COMMONDIR:
			parent = git3_repository_commondir(repo);
			break;
		default:
			git3_error_set(GIT3_ERROR_INVALID, "invalid item directory");
			return NULL;
	}
	if (!parent && fallback != GIT3_REPOSITORY_ITEM__LAST)
		return resolved_parent_path(repo, fallback, GIT3_REPOSITORY_ITEM__LAST);

	return parent;
}

int git3_repository_item_path(
	git3_buf *out,
	const git3_repository *repo,
	git3_repository_item_t item)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_repository__item_path, repo, item);
}

int git3_repository__item_path(
	git3_str *out,
	const git3_repository *repo,
	git3_repository_item_t item)
{
	const char *parent = resolved_parent_path(repo, items[item].parent, items[item].fallback);
	if (parent == NULL) {
		git3_error_set(GIT3_ERROR_INVALID, "path cannot exist in repository");
		return GIT3_ENOTFOUND;
	}

	if (git3_str_sets(out, parent) < 0)
		return -1;

	if (items[item].name) {
		if (git3_str_joinpath(out, parent, items[item].name) < 0)
			return -1;
	}

	if (items[item].directory) {
		if (git3_fs_path_to_dir(out) < 0)
			return -1;
	}

	return 0;
}

const char *git3_repository_path(const git3_repository *repo)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(repo, NULL);
	return repo->gitdir;
}

const char *git3_repository_workdir(const git3_repository *repo)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(repo, NULL);

	if (repo->is_bare)
		return NULL;

	return repo->workdir;
}

int git3_repository_workdir_path(
	git3_str *out, git3_repository *repo, const char *path)
{
	int error;

	if (!repo->workdir) {
		git3_error_set(GIT3_ERROR_REPOSITORY, "repository has no working directory");
		return GIT3_EBAREREPO;
	}

	if (!(error = git3_str_joinpath(out, repo->workdir, path)))
		error = git3_path_validate_str_length(repo, out);

	return error;
}

const char *git3_repository_commondir(const git3_repository *repo)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(repo, NULL);
	return repo->commondir;
}

int git3_repository_set_workdir(
	git3_repository *repo, const char *workdir, int update_gitlink)
{
	int error = 0;
	git3_str path = GIT3_STR_INIT;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(workdir);

	if (git3_fs_path_prettify_dir(&path, workdir, NULL) < 0)
		return -1;

	if (repo->workdir && strcmp(repo->workdir, path.ptr) == 0) {
		git3_str_dispose(&path);
		return 0;
	}

	if (update_gitlink) {
		git3_config *config;

		if (git3_repository_config__weakptr(&config, repo) < 0) {
			git3_str_dispose(&path);
			return -1;
		}

		error = repo_write_gitlink(path.ptr, git3_repository_path(repo), false);

		/* passthrough error means gitlink is unnecessary */
		if (error == GIT3_PASSTHROUGH)
			error = git3_config_delete_entry(config, "core.worktree");
		else if (!error)
			error = git3_config_set_string(config, "core.worktree", path.ptr);

		if (!error)
			error = git3_config_set_bool(config, "core.bare", false);
	}

	if (!error) {
		char *old_workdir = repo->workdir;

		repo->workdir = git3_str_detach(&path);
		repo->is_bare = 0;

		git3__free(old_workdir);
	}
	git3_str_dispose(&path);

	return error;
}

int git3_repository_is_bare(const git3_repository *repo)
{
	GIT3_ASSERT_ARG(repo);
	return repo->is_bare;
}

int git3_repository_is_worktree(const git3_repository *repo)
{
	GIT3_ASSERT_ARG(repo);
	return repo->is_worktree;
}

int git3_repository_set_bare(git3_repository *repo)
{
	int error;
	git3_config *config;

	GIT3_ASSERT_ARG(repo);

	if (repo->is_bare)
		return 0;

	if ((error = git3_repository_config__weakptr(&config, repo)) < 0)
		return error;

	if ((error = git3_config_set_bool(config, "core.bare", true)) < 0)
		return error;

	if ((error = git3_config__update_entry(config, "core.worktree", NULL, true, true)) < 0)
		return error;

	git3__free(repo->workdir);
	repo->workdir = NULL;
	repo->is_bare = 1;

	return 0;
}

int git3_repository_head_commit(git3_commit **commit, git3_repository *repo)
{
	git3_reference *head;
	git3_object *obj;
	int error;

	if ((error = git3_repository_head(&head, repo)) < 0)
		return error;

	if ((error = git3_reference_peel(&obj, head, GIT3_OBJECT_COMMIT)) < 0)
		goto cleanup;

	*commit = (git3_commit *)obj;

cleanup:
	git3_reference_free(head);
	return error;
}

int git3_repository_head_tree(git3_tree **tree, git3_repository *repo)
{
	git3_reference *head;
	git3_object *obj;
	int error;

	if ((error = git3_repository_head(&head, repo)) < 0)
		return error;

	if ((error = git3_reference_peel(&obj, head, GIT3_OBJECT_TREE)) < 0)
		goto cleanup;

	*tree = (git3_tree *)obj;

cleanup:
	git3_reference_free(head);
	return error;
}

int git3_repository__set_orig_head(git3_repository *repo, const git3_oid *orig_head)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str file_path = GIT3_STR_INIT;
	char orig_head_str[GIT3_OID_MAX_HEXSIZE];
	int error = 0;

	git3_oid_fmt(orig_head_str, orig_head);

	if ((error = git3_str_joinpath(&file_path, repo->gitdir, GIT3_ORIG_HEAD_FILE)) == 0 &&
		(error = git3_filebuf_open(&file, file_path.ptr, GIT3_FILEBUF_CREATE_LEADING_DIRS, GIT3_MERGE_FILE_MODE)) == 0 &&
		(error = git3_filebuf_printf(&file, "%.*s\n", (int)git3_oid_hexsize(repo->oid_type), orig_head_str)) == 0)
		error = git3_filebuf_commit(&file);

	if (error < 0)
		git3_filebuf_cleanup(&file);

	git3_str_dispose(&file_path);

	return error;
}

static int git3_repository__message(git3_str *out, git3_repository *repo)
{
	git3_str path = GIT3_STR_INIT;
	struct stat st;
	int error;

	if (git3_str_joinpath(&path, repo->gitdir, GIT3_MERGE_MSG_FILE) < 0)
		return -1;

	if ((error = p_stat(git3_str_cstr(&path), &st)) < 0) {
		if (errno == ENOENT)
			error = GIT3_ENOTFOUND;
		git3_error_set(GIT3_ERROR_OS, "could not access message file");
	} else {
		error = git3_futils_readbuffer(out, git3_str_cstr(&path));
	}

	git3_str_dispose(&path);

	return error;
}

int git3_repository_message(git3_buf *out, git3_repository *repo)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_repository__message, repo);
}

int git3_repository_message_remove(git3_repository *repo)
{
	git3_str path = GIT3_STR_INIT;
	int error;

	if (git3_str_joinpath(&path, repo->gitdir, GIT3_MERGE_MSG_FILE) < 0)
		return -1;

	error = p_unlink(git3_str_cstr(&path));
	git3_str_dispose(&path);

	return error;
}

int git3_repository_hashfile(
	git3_oid *out,
	git3_repository *repo,
	const char *path,
	git3_object_t type,
	const char *as_path)
{
	int error;
	git3_filter_list *fl = NULL;
	git3_file fd = -1;
	uint64_t len;
	git3_str full_path = GIT3_STR_INIT;
	const char *workdir = git3_repository_workdir(repo);

	 /* as_path can be NULL */
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(path);
	GIT3_ASSERT_ARG(repo);

	if ((error = git3_fs_path_join_unrooted(&full_path, path, workdir, NULL)) < 0 ||
	    (error = git3_path_validate_str_length(repo, &full_path)) < 0)
		return error;

	/*
	 * NULL as_path means that we should derive it from the
	 * given path.
	 */
	if (!as_path) {
		if (workdir && !git3__prefixcmp(full_path.ptr, workdir))
			as_path = full_path.ptr + strlen(workdir);
		else
			as_path = "";
	}

	/* passing empty string for "as_path" indicated --no-filters */
	if (strlen(as_path) > 0) {
		error = git3_filter_list_load(
			&fl, repo, NULL, as_path,
			GIT3_FILTER_TO_ODB, GIT3_FILTER_DEFAULT);

		if (error < 0)
			return error;
	}

	/* at this point, error is a count of the number of loaded filters */

	fd = git3_futils_open_ro(full_path.ptr);
	if (fd < 0) {
		error = fd;
		goto cleanup;
	}

	if ((error = git3_futils_filesize(&len, fd)) < 0)
		goto cleanup;

	if (!git3__is_sizet(len)) {
		git3_error_set(GIT3_ERROR_OS, "file size overflow for 32-bit systems");
		error = -1;
		goto cleanup;
	}

	error = git3_odb__hashfd_filtered(out, fd, (size_t)len, type, repo->oid_type, fl);

cleanup:
	if (fd >= 0)
		p_close(fd);
	git3_filter_list_free(fl);
	git3_str_dispose(&full_path);

	return error;
}

static int checkout_message(git3_str *out, git3_reference *old, const char *new)
{
	const char *idstr;

	git3_str_puts(out, "checkout: moving from ");

	if (git3_reference_type(old) == GIT3_REFERENCE_SYMBOLIC) {
		git3_str_puts(out, git3_reference__shorthand(git3_reference_symbolic_target(old)));
	} else {
		if ((idstr = git3_oid_tostr_s(git3_reference_target(old))) == NULL)
			return -1;

		git3_str_puts(out, idstr);
	}

	git3_str_puts(out, " to ");

	if (git3_reference__is_branch(new) ||
		git3_reference__is_tag(new) ||
		git3_reference__is_remote(new))
		git3_str_puts(out, git3_reference__shorthand(new));
	else
		git3_str_puts(out, new);

	if (git3_str_oom(out))
		return -1;

	return 0;
}

static int detach(git3_repository *repo, const git3_oid *id, const char *new)
{
	int error;
	git3_str log_message = GIT3_STR_INIT;
	git3_object *object = NULL, *peeled = NULL;
	git3_reference *new_head = NULL, *current = NULL;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(id);

	if ((error = git3_reference_lookup(&current, repo, GIT3_HEAD_FILE)) < 0)
		return error;

	if ((error = git3_object_lookup(&object, repo, id, GIT3_OBJECT_ANY)) < 0)
		goto cleanup;

	if ((error = git3_object_peel(&peeled, object, GIT3_OBJECT_COMMIT)) < 0)
		goto cleanup;

	if (new == NULL &&
	    (new = git3_oid_tostr_s(git3_object_id(peeled))) == NULL) {
		error = -1;
		goto cleanup;
	}

	if ((error = checkout_message(&log_message, current, new)) < 0)
		goto cleanup;

	error = git3_reference_create(&new_head, repo, GIT3_HEAD_FILE, git3_object_id(peeled), true, git3_str_cstr(&log_message));

cleanup:
	git3_str_dispose(&log_message);
	git3_object_free(object);
	git3_object_free(peeled);
	git3_reference_free(current);
	git3_reference_free(new_head);
	return error;
}

int git3_repository_set_head(
	git3_repository *repo,
	const char *refname)
{
	git3_reference *ref = NULL, *current = NULL, *new_head = NULL;
	git3_str log_message = GIT3_STR_INIT;
	int error;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(refname);

	if ((error = git3_reference_lookup(&current, repo, GIT3_HEAD_FILE)) < 0)
		return error;

	if ((error = checkout_message(&log_message, current, refname)) < 0)
		goto cleanup;

	error = git3_reference_lookup(&ref, repo, refname);
	if (error < 0 && error != GIT3_ENOTFOUND)
		goto cleanup;

	if (ref && current->type == GIT3_REFERENCE_SYMBOLIC && git3__strcmp(current->target.symbolic, ref->name) &&
	    git3_reference_is_branch(ref) && git3_branch_is_checked_out(ref)) {
		git3_error_set(GIT3_ERROR_REPOSITORY, "cannot set HEAD to reference '%s' as it is the current HEAD "
			"of a linked repository.", git3_reference_name(ref));
		error = -1;
		goto cleanup;
	}

	if (!error) {
		if (git3_reference_is_branch(ref)) {
			error = git3_reference_symbolic_create(&new_head, repo, GIT3_HEAD_FILE,
					git3_reference_name(ref), true, git3_str_cstr(&log_message));
		} else {
			error = detach(repo, git3_reference_target(ref),
				git3_reference_is_tag(ref) || git3_reference_is_remote(ref) ? refname : NULL);
		}
	} else if (git3_reference__is_branch(refname)) {
		error = git3_reference_symbolic_create(&new_head, repo, GIT3_HEAD_FILE, refname,
				true, git3_str_cstr(&log_message));
	}

cleanup:
	git3_str_dispose(&log_message);
	git3_reference_free(current);
	git3_reference_free(ref);
	git3_reference_free(new_head);
	return error;
}

int git3_repository_set_head_detached(
	git3_repository *repo,
	const git3_oid *committish)
{
	return detach(repo, committish, NULL);
}

int git3_repository_set_head_detached_from_annotated(
	git3_repository *repo,
	const git3_annotated_commit *committish)
{
	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(committish);

	return detach(repo, git3_annotated_commit_id(committish), committish->description);
}

int git3_repository_detach_head(git3_repository *repo)
{
	git3_reference *old_head = NULL,	*new_head = NULL, *current = NULL;
	git3_object *object = NULL;
	git3_str log_message = GIT3_STR_INIT;
	const char *idstr;
	int error;

	GIT3_ASSERT_ARG(repo);

	if ((error = git3_reference_lookup(&current, repo, GIT3_HEAD_FILE)) < 0)
		return error;

	if ((error = git3_repository_head(&old_head, repo)) < 0)
		goto cleanup;

	if ((error = git3_object_lookup(&object, repo, git3_reference_target(old_head), GIT3_OBJECT_COMMIT)) < 0)
		goto cleanup;

	if ((idstr = git3_oid_tostr_s(git3_object_id(object))) == NULL) {
		error = -1;
		goto cleanup;
	}

	if ((error = checkout_message(&log_message, current, idstr)) < 0)
		goto cleanup;

	error = git3_reference_create(&new_head, repo, GIT3_HEAD_FILE, git3_reference_target(old_head),
			1, git3_str_cstr(&log_message));

cleanup:
	git3_str_dispose(&log_message);
	git3_object_free(object);
	git3_reference_free(old_head);
	git3_reference_free(new_head);
	git3_reference_free(current);
	return error;
}

/**
 * Loosely ported from git.git
 * https://github.com/git/git/blob/master/contrib/completion/git-prompt.sh#L198-289
 */
int git3_repository_state(git3_repository *repo)
{
	git3_str repo_path = GIT3_STR_INIT;
	int state = GIT3_REPOSITORY_STATE_NONE;

	GIT3_ASSERT_ARG(repo);

	if (git3_str_puts(&repo_path, repo->gitdir) < 0)
		return -1;

	if (git3_fs_path_contains_file(&repo_path, GIT3_REBASE_MERGE_INTERACTIVE_FILE))
		state = GIT3_REPOSITORY_STATE_REBASE_INTERACTIVE;
	else if (git3_fs_path_contains_dir(&repo_path, GIT3_REBASE_MERGE_DIR))
		state = GIT3_REPOSITORY_STATE_REBASE_MERGE;
	else if (git3_fs_path_contains_file(&repo_path, GIT3_REBASE_APPLY_REBASING_FILE))
		state = GIT3_REPOSITORY_STATE_REBASE;
	else if (git3_fs_path_contains_file(&repo_path, GIT3_REBASE_APPLY_APPLYING_FILE))
		state = GIT3_REPOSITORY_STATE_APPLY_MAILBOX;
	else if (git3_fs_path_contains_dir(&repo_path, GIT3_REBASE_APPLY_DIR))
		state = GIT3_REPOSITORY_STATE_APPLY_MAILBOX_OR_REBASE;
	else if (git3_fs_path_contains_file(&repo_path, GIT3_MERGE_HEAD_FILE))
		state = GIT3_REPOSITORY_STATE_MERGE;
	else if (git3_fs_path_contains_file(&repo_path, GIT3_REVERT_HEAD_FILE)) {
		state = GIT3_REPOSITORY_STATE_REVERT;
		if (git3_fs_path_contains_file(&repo_path, GIT3_SEQUENCER_TODO_FILE)) {
			state = GIT3_REPOSITORY_STATE_REVERT_SEQUENCE;
		}
	} else if (git3_fs_path_contains_file(&repo_path, GIT3_CHERRYPICK_HEAD_FILE)) {
		state = GIT3_REPOSITORY_STATE_CHERRYPICK;
		if (git3_fs_path_contains_file(&repo_path, GIT3_SEQUENCER_TODO_FILE)) {
			state = GIT3_REPOSITORY_STATE_CHERRYPICK_SEQUENCE;
		}
	} else if (git3_fs_path_contains_file(&repo_path, GIT3_BISECT_LOG_FILE))
		state = GIT3_REPOSITORY_STATE_BISECT;

	git3_str_dispose(&repo_path);
	return state;
}

int git3_repository__cleanup_files(
	git3_repository *repo, const char *files[], size_t files_len)
{
	git3_str buf = GIT3_STR_INIT;
	size_t i;
	int error;

	for (error = 0, i = 0; !error && i < files_len; ++i) {
		const char *path;

		if (git3_str_joinpath(&buf, repo->gitdir, files[i]) < 0)
			return -1;

		path = git3_str_cstr(&buf);

		if (git3_fs_path_isfile(path)) {
			error = p_unlink(path);
		} else if (git3_fs_path_isdir(path)) {
			error = git3_futils_rmdir_r(path, NULL,
				GIT3_RMDIR_REMOVE_FILES | GIT3_RMDIR_REMOVE_BLOCKERS);
		}

		git3_str_clear(&buf);
	}

	git3_str_dispose(&buf);
	return error;
}

static const char *state_files[] = {
	GIT3_MERGE_HEAD_FILE,
	GIT3_MERGE_MODE_FILE,
	GIT3_MERGE_MSG_FILE,
	GIT3_REVERT_HEAD_FILE,
	GIT3_CHERRYPICK_HEAD_FILE,
	GIT3_BISECT_LOG_FILE,
	GIT3_REBASE_MERGE_DIR,
	GIT3_REBASE_APPLY_DIR,
	GIT3_SEQUENCER_DIR,
};

int git3_repository_state_cleanup(git3_repository *repo)
{
	GIT3_ASSERT_ARG(repo);

	return git3_repository__cleanup_files(repo, state_files, ARRAY_SIZE(state_files));
}

int git3_repository__shallow_roots(
	git3_oid **out,
	size_t *out_len,
	git3_repository *repo)
{
	int error = 0;

	if (!repo->shallow_grafts && (error = load_grafts(repo)) < 0)
		return error;

	if ((error = git3_grafts_refresh(repo->shallow_grafts)) < 0)
		return error;

	if ((error = git3_grafts_oids(out, out_len, repo->shallow_grafts)) < 0)
		return error;

	return 0;
}

int git3_repository__shallow_roots_write(git3_repository *repo, git3_oidarray *roots)
{
	git3_filebuf file = GIT3_FILEBUF_INIT;
	git3_str path = GIT3_STR_INIT;
	char oid_str[GIT3_OID_MAX_HEXSIZE + 1];
	size_t i;
	int filebuf_hash, error = 0;

	GIT3_ASSERT_ARG(repo);

	filebuf_hash = git3_filebuf_hash_flags(git3_oid_algorithm(repo->oid_type));
	GIT3_ASSERT(filebuf_hash);

	if ((error = git3_str_joinpath(&path, repo->gitdir, "shallow")) < 0)
		goto on_error;

	if ((error = git3_filebuf_open(&file, git3_str_cstr(&path), filebuf_hash, 0666)) < 0)
		goto on_error;

	for (i = 0; i < roots->count; i++) {
		git3_oid_tostr(oid_str, sizeof(oid_str), &roots->ids[i]);
		git3_filebuf_write(&file, oid_str, git3_oid_hexsize(repo->oid_type));
		git3_filebuf_write(&file, "\n", 1);
	}

	git3_filebuf_commit(&file);

	if ((error = load_grafts(repo)) < 0) {
		error = -1;
		goto on_error;
	}

	if (!roots->count)
		remove(path.ptr);

on_error:
	git3_str_dispose(&path);

	return error;
}

int git3_repository_is_shallow(git3_repository *repo)
{
	git3_str path = GIT3_STR_INIT;
	struct stat st;
	int error;

	if ((error = git3_str_joinpath(&path, repo->gitdir, "shallow")) < 0)
		return error;

	error = git3_fs_path_lstat(path.ptr, &st);
	git3_str_dispose(&path);

	if (error == GIT3_ENOTFOUND) {
		git3_error_clear();
		return 0;
	}

	if (error < 0)
		return error;

	return st.st_size == 0 ? 0 : 1;
}

int git3_repository_init_options_init(
	git3_repository_init_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_repository_init_options,
		GIT3_REPOSITORY_INIT_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_repository_init_init_options(
	git3_repository_init_options *opts, unsigned int version)
{
	return git3_repository_init_options_init(opts, version);
}
#endif

int git3_repository_ident(const char **name, const char **email, const git3_repository *repo)
{
	*name = repo->ident_name;
	*email = repo->ident_email;

	return 0;
}

int git3_repository_set_ident(git3_repository *repo, const char *name, const char *email)
{
	char *tmp_name = NULL, *tmp_email = NULL;

	if (name) {
		tmp_name = git3__strdup(name);
		GIT3_ERROR_CHECK_ALLOC(tmp_name);
	}

	if (email) {
		tmp_email = git3__strdup(email);
		GIT3_ERROR_CHECK_ALLOC(tmp_email);
	}

	tmp_name = git3_atomic_swap(repo->ident_name, tmp_name);
	tmp_email = git3_atomic_swap(repo->ident_email, tmp_email);

	git3__free(tmp_name);
	git3__free(tmp_email);

	return 0;
}

int git3_repository_submodule_cache_all(git3_repository *repo)
{
	GIT3_ASSERT_ARG(repo);
	return git3_submodule_cache_init(&repo->submodule_cache, repo);
}

int git3_repository_submodule_cache_clear(git3_repository *repo)
{
	int error = 0;
	GIT3_ASSERT_ARG(repo);

	error = git3_submodule_cache_free(repo->submodule_cache);
	repo->submodule_cache = NULL;
	return error;
}

git3_oid_t git3_repository_oid_type(git3_repository *repo)
{
	return repo ? repo->oid_type : 0;
}

struct mergehead_data {
	git3_repository *repo;
	git3_vector *parents;
};

static int insert_mergehead(const git3_oid *oid, void *payload)
{
	git3_commit *commit;
	struct mergehead_data *data = (struct mergehead_data *)payload;

	if (git3_commit_lookup(&commit, data->repo, oid) < 0)
		return -1;

	return git3_vector_insert(data->parents, commit);
}

int git3_repository_commit_parents(git3_commitarray *out, git3_repository *repo)
{
	git3_commit *first_parent = NULL, *commit;
	git3_reference *head_ref = NULL;
	git3_vector parents = GIT3_VECTOR_INIT;
	struct mergehead_data data;
	size_t i;
	int error;

	GIT3_ASSERT_ARG(out && repo);

	out->count = 0;
	out->commits = NULL;

	error = git3_revparse_ext((git3_object **)&first_parent, &head_ref, repo, "HEAD");

	if (error != 0) {
		if (error == GIT3_ENOTFOUND)
			error = 0;

		goto done;
	}

	if ((error = git3_vector_insert(&parents, first_parent)) < 0)
		goto done;

	data.repo = repo;
	data.parents = &parents;

	error = git3_repository_mergehead_foreach(repo, insert_mergehead, &data);

	if (error == GIT3_ENOTFOUND)
		error = 0;
	else if (error != 0)
		goto done;

	out->commits = (git3_commit **)git3_vector_detach(&out->count, NULL, &parents);

done:
	git3_vector_foreach(&parents, i, commit)
		git3__free(commit);

	git3_reference_free(head_ref);
	return error;
}

int git3_repository__abbrev_length(int *out, git3_repository *repo)
{
	size_t oid_hexsize;
	int len;
	int error;

	oid_hexsize = git3_oid_hexsize(repo->oid_type);

	if ((error = git3_repository__configmap_lookup(&len, repo, GIT3_CONFIGMAP_ABBREV)) < 0)
		return error;

	if (len < GIT3_ABBREV_MINIMUM) {
		git3_error_set(GIT3_ERROR_CONFIG, "invalid oid abbreviation setting: '%d'", len);
		return -1;
	}

	if (len == GIT3_ABBREV_FALSE || (size_t)len > oid_hexsize)
		len = (int)oid_hexsize;

	*out = len;

	return error;
}
