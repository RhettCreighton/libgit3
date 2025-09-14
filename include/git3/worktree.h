/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_worktree_h__
#define INCLUDE_git_worktree_h__

#include "common.h"
#include "buffer.h"
#include "types.h"
#include "strarray.h"
#include "checkout.h"

/**
 * @file git3/worktree.h
 * @brief Additional working directories for a repository
 * @defgroup git3_commit Additional working directories for a repository
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * List names of linked working trees
 *
 * The returned list should be released with `git3_strarray_free`
 * when no longer needed.
 *
 * @param out pointer to the array of working tree names
 * @param repo the repo to use when listing working trees
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_worktree_list(git3_strarray *out, git3_repository *repo);

/**
 * Lookup a working tree by its name for a given repository
 *
 * @param out Output pointer to looked up worktree or `NULL`
 * @param repo The repository containing worktrees
 * @param name Name of the working tree to look up
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_worktree_lookup(git3_worktree **out, git3_repository *repo, const char *name);

/**
 * Open a worktree of a given repository
 *
 * If a repository is not the main tree but a worktree, this
 * function will look up the worktree inside the parent
 * repository and create a new `git3_worktree` structure.
 *
 * @param out Out-pointer for the newly allocated worktree
 * @param repo Repository to look up worktree for
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_worktree_open_from_repository(git3_worktree **out, git3_repository *repo);

/**
 * Free a previously allocated worktree
 *
 * @param wt worktree handle to close. If NULL nothing occurs.
 */
GIT3_EXTERN(void) git3_worktree_free(git3_worktree *wt);

/**
 * Check if worktree is valid
 *
 * A valid worktree requires both the git data structures inside
 * the linked parent repository and the linked working copy to be
 * present.
 *
 * @param wt Worktree to check
 * @return 0 when worktree is valid, error-code otherwise
 */
GIT3_EXTERN(int) git3_worktree_validate(const git3_worktree *wt);

/**
 * Worktree add options structure
 *
 * Initialize with `GIT3_WORKTREE_ADD_OPTIONS_INIT`. Alternatively, you can
 * use `git3_worktree_add_options_init`.
 *
 */
typedef struct git3_worktree_add_options {
	unsigned int version;

	int lock;		/**< lock newly created worktree */
	int checkout_existing;	/**< allow checkout of existing branch matching worktree name */
	git3_reference *ref;	/**< reference to use for the new worktree HEAD */

	/**
	 * Options for the checkout.
	 */
	git3_checkout_options checkout_options;
} git3_worktree_add_options;

/** Current version for the `git3_worktree_add_options` structure */
#define GIT3_WORKTREE_ADD_OPTIONS_VERSION 1

/** Static constructor for `git3_worktree_add_options` */
#define GIT3_WORKTREE_ADD_OPTIONS_INIT { GIT3_WORKTREE_ADD_OPTIONS_VERSION, \
	0, 0, NULL, GIT3_CHECKOUT_OPTIONS_INIT }

/**
 * Initialize git3_worktree_add_options structure
 *
 * Initializes a `git3_worktree_add_options` with default values. Equivalent to
 * creating an instance with `GIT3_WORKTREE_ADD_OPTIONS_INIT`.
 *
 * @param opts The `git3_worktree_add_options` struct to initialize.
 * @param version The struct version; pass `GIT3_WORKTREE_ADD_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_worktree_add_options_init(git3_worktree_add_options *opts,
	unsigned int version);

/**
 * Add a new working tree
 *
 * Add a new working tree for the repository, that is create the
 * required data structures inside the repository and check out
 * the current HEAD at `path`
 *
 * @param out Output pointer containing new working tree
 * @param repo Repository to create working tree for
 * @param name Name of the working tree
 * @param path Path to create working tree at
 * @param opts Options to modify default behavior. May be NULL
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_worktree_add(git3_worktree **out, git3_repository *repo,
	const char *name, const char *path,
	const git3_worktree_add_options *opts);

/**
 * Lock worktree if not already locked
 *
 * Lock a worktree, optionally specifying a reason why the linked
 * working tree is being locked.
 *
 * @param wt Worktree to lock
 * @param reason Reason why the working tree is being locked
 * @return 0 on success, non-zero otherwise
 */
GIT3_EXTERN(int) git3_worktree_lock(git3_worktree *wt, const char *reason);

/**
 * Unlock a locked worktree
 *
 * @param wt Worktree to unlock
 * @return 0 on success, 1 if worktree was not locked, error-code
 *  otherwise
 */
GIT3_EXTERN(int) git3_worktree_unlock(git3_worktree *wt);

/**
 * Check if worktree is locked
 *
 * A worktree may be locked if the linked working tree is stored
 * on a portable device which is not available.
 *
 * @param reason Buffer to store reason in. If NULL no reason is stored.
 * @param wt Worktree to check
 * @return 0 when the working tree not locked, a value greater
 *  than zero if it is locked, less than zero if there was an
 *  error
 */
GIT3_EXTERN(int) git3_worktree_is_locked(git3_buf *reason, const git3_worktree *wt);

/**
 * Retrieve the name of the worktree
 *
 * @param wt Worktree to get the name for
 * @return The worktree's name. The pointer returned is valid for the
 *  lifetime of the git3_worktree
 */
GIT3_EXTERN(const char *) git3_worktree_name(const git3_worktree *wt);

/**
 * Retrieve the filesystem path for the worktree
 *
 * @param wt Worktree to get the path for
 * @return The worktree's filesystem path. The pointer returned
 *  is valid for the lifetime of the git3_worktree.
 */
GIT3_EXTERN(const char *) git3_worktree_path(const git3_worktree *wt);

/**
 * Flags which can be passed to git3_worktree_prune to alter its
 * behavior.
 */
typedef enum {
	/* Prune working tree even if working tree is valid */
	GIT3_WORKTREE_PRUNE_VALID = 1u << 0,
	/* Prune working tree even if it is locked */
	GIT3_WORKTREE_PRUNE_LOCKED = 1u << 1,
	/* Prune checked out working tree */
	GIT3_WORKTREE_PRUNE_WORKING_TREE = 1u << 2
} git3_worktree_prune_t;

/**
 * Worktree prune options structure
 *
 * Initialize with `GIT3_WORKTREE_PRUNE_OPTIONS_INIT`. Alternatively, you can
 * use `git3_worktree_prune_options_init`.
 *
 */
typedef struct git3_worktree_prune_options {
	unsigned int version;

	/** A combination of `git3_worktree_prune_t` */
	uint32_t flags;
} git3_worktree_prune_options;

/** Current version for the `git3_worktree_prune_options` structure */
#define GIT3_WORKTREE_PRUNE_OPTIONS_VERSION 1

/** Static constructor for `git3_worktree_prune_options` */
#define GIT3_WORKTREE_PRUNE_OPTIONS_INIT {GIT3_WORKTREE_PRUNE_OPTIONS_VERSION,0}

/**
 * Initialize git3_worktree_prune_options structure
 *
 * Initializes a `git3_worktree_prune_options` with default values. Equivalent to
 * creating an instance with `GIT3_WORKTREE_PRUNE_OPTIONS_INIT`.
 *
 * @param opts The `git3_worktree_prune_options` struct to initialize.
 * @param version The struct version; pass `GIT3_WORKTREE_PRUNE_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_worktree_prune_options_init(
	git3_worktree_prune_options *opts,
	unsigned int version);

/**
 * Is the worktree prunable with the given options?
 *
 * A worktree is not prunable in the following scenarios:
 *
 * - the worktree is linking to a valid on-disk worktree. The
 *   `valid` member will cause this check to be ignored.
 * - the worktree is locked. The `locked` flag will cause this
 *   check to be ignored.
 *
 * If the worktree is not valid and not locked or if the above
 * flags have been passed in, this function will return a
 * positive value. If the worktree is not prunable, an error
 * message will be set (visible in `giterr_last`) with details about
 * why.
 *
 * @param wt Worktree to check.
 * @param opts The prunable options.
 * @return 1 if the worktree is prunable, 0 otherwise, or an error code.
 */
GIT3_EXTERN(int) git3_worktree_is_prunable(git3_worktree *wt,
	git3_worktree_prune_options *opts);

/**
 * Prune working tree
 *
 * Prune the working tree, that is remove the git data
 * structures on disk. The repository will only be pruned of
 * `git3_worktree_is_prunable` succeeds.
 *
 * @param wt Worktree to prune
 * @param opts Specifies which checks to override. See
 *        `git3_worktree_is_prunable`. May be NULL
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_worktree_prune(git3_worktree *wt,
	git3_worktree_prune_options *opts);

/** @} */
GIT3_END_DECL

#endif
