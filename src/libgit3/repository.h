/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_repository_h__
#define INCLUDE_repository_h__

#include "common.h"

#include "git3/common.h"
#include "git3/oid.h"
#include "git3/odb.h"
#include "git3/repository.h"
#include "git3/object.h"
#include "git3/config.h"
#include "git3/sys/repository.h"

#include "array.h"
#include "cache.h"
#include "refs.h"
#include "str.h"
#include "object.h"
#include "attrcache.h"
#include "submodule.h"
#include "diff_driver.h"
#include "grafts.h"

#define DOT_GIT ".git3"
#define GIT3_DIR DOT_GIT "/"
#define GIT3_DIR_MODE 0755
#define GIT3_BARE_DIR_MODE 0777

/* Default DOS-compatible 8.3 "short name" for a git repository, "GIT~1" */
#define GIT3_DIR_SHORTNAME "GIT~1"

extern bool git3_repository__fsync_gitdir;
extern bool git3_repository__validate_ownership;

/** Cvar cache identifiers */
typedef enum {
	GIT3_CONFIGMAP_AUTO_CRLF = 0,    /* core.autocrlf */
	GIT3_CONFIGMAP_EOL,              /* core.eol */
	GIT3_CONFIGMAP_SYMLINKS,         /* core.symlinks */
	GIT3_CONFIGMAP_IGNORECASE,       /* core.ignorecase */
	GIT3_CONFIGMAP_FILEMODE,         /* core.filemode */
	GIT3_CONFIGMAP_IGNORESTAT,       /* core.ignorestat */
	GIT3_CONFIGMAP_TRUSTCTIME,       /* core.trustctime */
	GIT3_CONFIGMAP_ABBREV,           /* core.abbrev */
	GIT3_CONFIGMAP_PRECOMPOSE,       /* core.precomposeunicode */
	GIT3_CONFIGMAP_SAFE_CRLF,		/* core.safecrlf */
	GIT3_CONFIGMAP_LOGALLREFUPDATES, /* core.logallrefupdates */
	GIT3_CONFIGMAP_PROTECTHFS,       /* core.protectHFS */
	GIT3_CONFIGMAP_PROTECTNTFS,      /* core.protectNTFS */
	GIT3_CONFIGMAP_FSYNCOBJECTFILES, /* core.fsyncObjectFiles */
	GIT3_CONFIGMAP_LONGPATHS,        /* core.longpaths */
	GIT3_CONFIGMAP_CACHE_MAX
} git3_configmap_item;

/**
 * Configuration map value enumerations
 *
 * These are the values that are actually stored in the configmap cache,
 * instead of their string equivalents. These values are internal and
 * symbolic; make sure that none of them is set to `-1`, since that is
 * the unique identifier for "not cached"
 */
typedef enum {
	/* The value hasn't been loaded from the cache yet */
	GIT3_CONFIGMAP_NOT_CACHED = -1,

	/* core.safecrlf: false, 'fail', 'warn' */
	GIT3_SAFE_CRLF_FALSE = 0,
	GIT3_SAFE_CRLF_FAIL = 1,
	GIT3_SAFE_CRLF_WARN = 2,

	/* core.autocrlf: false, true, 'input; */
	GIT3_AUTO_CRLF_FALSE = 0,
	GIT3_AUTO_CRLF_TRUE = 1,
	GIT3_AUTO_CRLF_INPUT = 2,
	GIT3_AUTO_CRLF_DEFAULT = GIT3_AUTO_CRLF_FALSE,

	/* core.eol: unset, 'crlf', 'lf', 'native' */
	GIT3_EOL_UNSET = 0,
	GIT3_EOL_CRLF = 1,
	GIT3_EOL_LF = 2,
#ifdef GIT3_WIN32
	GIT3_EOL_NATIVE = GIT3_EOL_CRLF,
#else
	GIT3_EOL_NATIVE = GIT3_EOL_LF,
#endif
	GIT3_EOL_DEFAULT = GIT3_EOL_NATIVE,

	/* core.symlinks: bool */
	GIT3_SYMLINKS_DEFAULT = GIT3_CONFIGMAP_TRUE,
	/* core.ignorecase */
	GIT3_IGNORECASE_DEFAULT = GIT3_CONFIGMAP_FALSE,
	/* core.filemode */
	GIT3_FILEMODE_DEFAULT = GIT3_CONFIGMAP_TRUE,
	/* core.ignorestat */
	GIT3_IGNORESTAT_DEFAULT = GIT3_CONFIGMAP_FALSE,
	/* core.trustctime */
	GIT3_TRUSTCTIME_DEFAULT = GIT3_CONFIGMAP_TRUE,
	/* core.abbrev */
	GIT3_ABBREV_FALSE = GIT3_OID_MAX_HEXSIZE,
	GIT3_ABBREV_MINIMUM = 4,
	GIT3_ABBREV_DEFAULT = 7,
	/* core.precomposeunicode */
	GIT3_PRECOMPOSE_DEFAULT = GIT3_CONFIGMAP_FALSE,
	/* core.safecrlf */
	GIT3_SAFE_CRLF_DEFAULT = GIT3_CONFIGMAP_FALSE,
	/* core.logallrefupdates */
	GIT3_LOGALLREFUPDATES_FALSE = GIT3_CONFIGMAP_FALSE,
	GIT3_LOGALLREFUPDATES_TRUE = GIT3_CONFIGMAP_TRUE,
	GIT3_LOGALLREFUPDATES_UNSET = 2,
	GIT3_LOGALLREFUPDATES_ALWAYS = 3,
	GIT3_LOGALLREFUPDATES_DEFAULT = GIT3_LOGALLREFUPDATES_UNSET,
	/* core.protectHFS */
	GIT3_PROTECTHFS_DEFAULT = GIT3_CONFIGMAP_FALSE,
	/* core.protectNTFS */
	GIT3_PROTECTNTFS_DEFAULT = GIT3_CONFIGMAP_TRUE,
	/* core.fsyncObjectFiles */
	GIT3_FSYNCOBJECTFILES_DEFAULT = GIT3_CONFIGMAP_FALSE,
	/* core.longpaths */
	GIT3_LONGPATHS_DEFAULT = GIT3_CONFIGMAP_FALSE
} git3_configmap_value;

/* internal repository init flags */
enum {
	GIT3_REPOSITORY_INIT__HAS_DOTGIT = (1u << 16),
	GIT3_REPOSITORY_INIT__NATURAL_WD = (1u << 17),
	GIT3_REPOSITORY_INIT__IS_REINIT  = (1u << 18)
};

/** Internal structure for repository object */
struct git3_repository {
	git3_odb *_odb;
	git3_refdb *_refdb;
	git3_config *_config;
	git3_index *_index;

	git3_cache objects;
	git3_attr_cache *attrcache;
	git3_diff_driver_registry *diff_drivers;

	char *gitlink;
	char *gitdir;
	char *commondir;
	char *workdir;
	char *namespace;

	char *ident_name;
	char *ident_email;

	git3_array_t(git3_str) reserved_names;

	unsigned use_env:1,
	         is_bare:1,
	         is_worktree:1;
	git3_oid_t oid_type;

	unsigned int lru_counter;

	git3_grafts *grafts;
	git3_grafts *shallow_grafts;

	git3_atomic32 attr_session_key;

	intptr_t configmap_cache[GIT3_CONFIGMAP_CACHE_MAX];
	git3_submodule_cache *submodule_cache;
};

GIT3_INLINE(git3_attr_cache *) git3_repository_attr_cache(git3_repository *repo)
{
	return repo->attrcache;
}

int git3_repository_head_commit(git3_commit **commit, git3_repository *repo);
int git3_repository_head_tree(git3_tree **tree, git3_repository *repo);
int git3_repository_create_head(const char *git3_dir, const char *ref_name);

typedef int (*git3_repository_foreach_worktree_cb)(git3_repository *, void *);

int git3_repository_foreach_worktree(git3_repository *repo,
				    git3_repository_foreach_worktree_cb cb,
				    void *payload);

/*
 * Weak pointers to repository internals.
 *
 * The returned pointers do not need to be freed. Do not keep
 * permanent references to these (i.e. between API calls), since they may
 * become invalidated if the user replaces a repository internal.
 */
int git3_repository_config__weakptr(git3_config **out, git3_repository *repo);
int git3_repository_odb__weakptr(git3_odb **out, git3_repository *repo);
int git3_repository_refdb__weakptr(git3_refdb **out, git3_repository *repo);
int git3_repository_index__weakptr(git3_index **out, git3_repository *repo);
int git3_repository_grafts__weakptr(git3_grafts **out, git3_repository *repo);
int git3_repository_shallow_grafts__weakptr(git3_grafts **out, git3_repository *repo);

/*
 * Configuration map cache
 *
 * Efficient access to the most used config variables of a repository.
 * The cache is cleared every time the config backend is replaced.
 */
int git3_repository__configmap_lookup(int *out, git3_repository *repo, git3_configmap_item item);
void git3_repository__configmap_lookup_cache_clear(git3_repository *repo);

/** Return the length that object names will be abbreviated to. */
int git3_repository__abbrev_length(int *out, git3_repository *repo);

int git3_repository__item_path(git3_str *out, const git3_repository *repo, git3_repository_item_t item);

GIT3_INLINE(int) git3_repository__ensure_not_bare(
	git3_repository *repo,
	const char *operation_name)
{
	if (!git3_repository_is_bare(repo))
		return 0;

	git3_error_set(
		GIT3_ERROR_REPOSITORY,
		"cannot %s. This operation is not allowed against bare repositories.",
		operation_name);

	return GIT3_EBAREREPO;
}

int git3_repository__set_orig_head(git3_repository *repo, const git3_oid *orig_head);

int git3_repository__cleanup_files(git3_repository *repo, const char *files[], size_t files_len);

/* The default "reserved names" for a repository */
extern git3_str git3_repository__reserved_names_win32[];
extern size_t git3_repository__reserved_names_win32_len;

extern git3_str git3_repository__reserved_names_posix[];
extern size_t git3_repository__reserved_names_posix_len;

/*
 * Gets any "reserved names" in the repository.  This will return paths
 * that should not be allowed in the repository (like ".git") to avoid
 * conflicting with the repository path, or with alternate mechanisms to
 * the repository path (eg, "GIT~1").  Every attempt will be made to look
 * up all possible reserved names - if there was a conflict for the shortname
 * GIT~1, for example, this function will try to look up the alternate
 * shortname.  If that fails, this function returns false, but out and outlen
 * will still be populated with good defaults.
 */
bool git3_repository__reserved_names(
	git3_str **out, size_t *outlen, git3_repository *repo, bool include_ntfs);

int git3_repository__shallow_roots(git3_oid **out, size_t *out_len, git3_repository *repo);
int git3_repository__shallow_roots_write(git3_repository *repo, git3_oidarray *roots);

/*
 * The default branch for the repository; the `init.defaultBranch`
 * configuration option, if set, or `master` if it is not.
 */
int git3_repository_initialbranch(git3_str *out, git3_repository *repo);

/*
 * Given a relative `path`, this makes it absolute based on the
 * repository's working directory.  This will perform validation
 * to ensure that the path is not longer than MAX_PATH on Windows
 * (unless `core.longpaths` is set in the repo config).
 */
int git3_repository_workdir_path(git3_str *out, git3_repository *repo, const char *path);

int git3_repository__extensions(char ***out, size_t *out_len);
int git3_repository__set_extensions(const char **extensions, size_t len);
void git3_repository__free_extensions(void);

/*
 * Set the object format (OID type) for a repository; this will set
 * both the configuration and the internal value for the oid type.
 */
int git3_repository__set_objectformat(
	git3_repository *repo,
	git3_oid_t oid_type);

/* SHA256 support */

#ifndef GIT3_EXPERIMENTAL_SHA256

GIT3_EXTERN(int) git3_repository_new_ext(
	git3_repository **out,
	git3_repository_new_options *opts);

#endif

#endif
