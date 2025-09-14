/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_revert_h__
#define INCLUDE_git_revert_h__

#include "common.h"
#include "types.h"
#include "merge.h"

/**
 * @file git3/revert.h
 * @brief Cherry-pick the inverse of a change to "undo" its effects
 * @defgroup git3_revert Cherry-pick the inverse of a change to "undo" its effects
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Options for revert
 */
typedef struct {
	unsigned int version;

	/** For merge commits, the "mainline" is treated as the parent. */
	unsigned int mainline;

	git3_merge_options merge_opts; /**< Options for the merging */
	git3_checkout_options checkout_opts; /**< Options for the checkout */
} git3_revert_options;

/** Current version for the `git3_revert_options` structure */
#define GIT3_REVERT_OPTIONS_VERSION 1

/** Static constructor for `git3_revert_options` */
#define GIT3_REVERT_OPTIONS_INIT { \
	GIT3_REVERT_OPTIONS_VERSION, 0, \
	GIT3_MERGE_OPTIONS_INIT, GIT3_CHECKOUT_OPTIONS_INIT }

/**
 * Initialize git3_revert_options structure
 *
 * Initializes a `git3_revert_options` with default values. Equivalent to
 * creating an instance with `GIT3_REVERT_OPTIONS_INIT`.
 *
 * @param opts The `git3_revert_options` struct to initialize.
 * @param version The struct version; pass `GIT3_REVERT_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_revert_options_init(
	git3_revert_options *opts,
	unsigned int version);

/**
 * Reverts the given commit against the given "our" commit, producing an
 * index that reflects the result of the revert.
 *
 * The returned index must be freed explicitly with `git3_index_free`.
 *
 * @param out pointer to store the index result in
 * @param repo the repository that contains the given commits
 * @param revert_commit the commit to revert
 * @param our_commit the commit to revert against (eg, HEAD)
 * @param mainline the parent of the revert commit, if it is a merge
 * @param merge_options the merge options (or null for defaults)
 * @return zero on success, -1 on failure.
 */
GIT3_EXTERN(int) git3_revert_commit(
	git3_index **out,
	git3_repository *repo,
	git3_commit *revert_commit,
	git3_commit *our_commit,
	unsigned int mainline,
	const git3_merge_options *merge_options);

/**
 * Reverts the given commit, producing changes in the index and working directory.
 *
 * @param repo the repository to revert
 * @param commit the commit to revert
 * @param given_opts the revert options (or null for defaults)
 * @return zero on success, -1 on failure.
 */
GIT3_EXTERN(int) git3_revert(
	git3_repository *repo,
	git3_commit *commit,
	const git3_revert_options *given_opts);

/** @} */
GIT3_END_DECL

#endif
