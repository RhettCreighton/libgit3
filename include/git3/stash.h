/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_stash_h__
#define INCLUDE_git_stash_h__

#include "common.h"
#include "types.h"
#include "checkout.h"

/**
 * @file git3/stash.h
 * @brief Stashes stores some uncommitted state in the repository
 * @ingroup Git
 *
 * Stashes stores some uncommitted state in the repository; generally
 * this allows a user to stash some changes so that they can restore
 * the working directory to an unmodified state. This can allow a
 * developer to work on two different changes in parallel.
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Stash flags
 */
typedef enum {
	/**
	 * No option, default
	 */
	GIT3_STASH_DEFAULT = 0,

	/**
	 * All changes already added to the index are left intact in
	 * the working directory
	 */
	GIT3_STASH_KEEP_INDEX = (1 << 0),

	/**
	 * All untracked files are also stashed and then cleaned up
	 * from the working directory
	 */
	GIT3_STASH_INCLUDE_UNTRACKED = (1 << 1),

	/**
	 * All ignored files are also stashed and then cleaned up from
	 * the working directory
	 */
	GIT3_STASH_INCLUDE_IGNORED = (1 << 2),

	/**
	 * All changes in the index and working directory are left intact
	 */
	GIT3_STASH_KEEP_ALL = (1 << 3)
} git3_stash_flags;

/**
 * Save the local modifications to a new stash.
 *
 * @param out Object id of the commit containing the stashed state.
 * This commit is also the target of the direct reference refs/stash.
 * @param repo The owning repository.
 * @param stasher The identity of the person performing the stashing.
 * @param message Optional description along with the stashed state.
 * @param flags Flags to control the stashing process. (see GIT3_STASH_* above)
 * @return 0 on success, GIT3_ENOTFOUND where there's nothing to stash,
 * or error code.
 */
GIT3_EXTERN(int) git3_stash_save(
	git3_oid *out,
	git3_repository *repo,
	const git3_signature *stasher,
	const char *message,
	uint32_t flags);

/**
 * Stash save options structure
 *
 * Initialize with `GIT3_STASH_SAVE_OPTIONS_INIT`. Alternatively, you can
 * use `git3_stash_save_options_init`.
 *
 */
typedef struct git3_stash_save_options {
	unsigned int version;

	/** Flags to control the stashing process. (see GIT3_STASH_* above) */
	uint32_t flags;

	/** The identity of the person performing the stashing. */
	const git3_signature *stasher;

	/** Optional description along with the stashed state. */
	const char *message;

	/** Optional paths that control which files are stashed. */
	git3_strarray paths;
} git3_stash_save_options;

/** Current version for the `git3_stash_save_options` structure */
#define GIT3_STASH_SAVE_OPTIONS_VERSION 1

/** Static constructor for `git3_stash_save_options` */
#define GIT3_STASH_SAVE_OPTIONS_INIT { GIT3_STASH_SAVE_OPTIONS_VERSION }

/**
 * Initialize git3_stash_save_options structure
 *
 * Initializes a `git3_stash_save_options` with default values. Equivalent to
 * creating an instance with `GIT3_STASH_SAVE_OPTIONS_INIT`.
 *
 * @param opts The `git3_stash_save_options` struct to initialize.
 * @param version The struct version; pass `GIT3_STASH_SAVE_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_stash_save_options_init(
	git3_stash_save_options *opts, unsigned int version);

/**
 * Save the local modifications to a new stash, with options.
 *
 * @param out Object id of the commit containing the stashed state.
 * This commit is also the target of the direct reference refs/stash.
 * @param repo The owning repository.
 * @param opts The stash options.
 * @return 0 on success, GIT3_ENOTFOUND where there's nothing to stash,
 * or error code.
 */
GIT3_EXTERN(int) git3_stash_save_with_opts(
	git3_oid *out,
	git3_repository *repo,
	const git3_stash_save_options *opts);

/** Stash application flags. */
typedef enum {
	GIT3_STASH_APPLY_DEFAULT = 0,

	/* Try to reinstate not only the working tree's changes,
	 * but also the index's changes.
	 */
	GIT3_STASH_APPLY_REINSTATE_INDEX = (1 << 0)
} git3_stash_apply_flags;

/** Stash apply progression states */
typedef enum {
	GIT3_STASH_APPLY_PROGRESS_NONE = 0,

	/** Loading the stashed data from the object database. */
	GIT3_STASH_APPLY_PROGRESS_LOADING_STASH,

	/** The stored index is being analyzed. */
	GIT3_STASH_APPLY_PROGRESS_ANALYZE_INDEX,

	/** The modified files are being analyzed. */
	GIT3_STASH_APPLY_PROGRESS_ANALYZE_MODIFIED,

	/** The untracked and ignored files are being analyzed. */
	GIT3_STASH_APPLY_PROGRESS_ANALYZE_UNTRACKED,

	/** The untracked files are being written to disk. */
	GIT3_STASH_APPLY_PROGRESS_CHECKOUT_UNTRACKED,

	/** The modified files are being written to disk. */
	GIT3_STASH_APPLY_PROGRESS_CHECKOUT_MODIFIED,

	/** The stash was applied successfully. */
	GIT3_STASH_APPLY_PROGRESS_DONE
} git3_stash_apply_progress_t;

/**
 * Stash application progress notification function.
 * Return 0 to continue processing, or a negative value to
 * abort the stash application.
 *
 * @param progress the progress information
 * @param payload the user-specified payload to the apply function
 * @return 0 on success, -1 on error
 */
typedef int GIT3_CALLBACK(git3_stash_apply_progress_cb)(
	git3_stash_apply_progress_t progress,
	void *payload);

/**
 * Stash application options structure
 *
 * Initialize with `GIT3_STASH_APPLY_OPTIONS_INIT`. Alternatively, you can
 * use `git3_stash_apply_options_init`.
 *
 */
typedef struct git3_stash_apply_options {
	unsigned int version;

	/** See `git3_stash_apply_flags`, above. */
	uint32_t flags;

	/** Options to use when writing files to the working directory. */
	git3_checkout_options checkout_options;

	/** Optional callback to notify the consumer of application progress. */
	git3_stash_apply_progress_cb progress_cb;
	void *progress_payload;
} git3_stash_apply_options;

/** Current version for the `git3_stash_apply_options` structure */
#define GIT3_STASH_APPLY_OPTIONS_VERSION 1

/** Static constructor for `git3_stash_apply_options` */
#define GIT3_STASH_APPLY_OPTIONS_INIT { \
	GIT3_STASH_APPLY_OPTIONS_VERSION, \
	GIT3_STASH_APPLY_DEFAULT, \
	GIT3_CHECKOUT_OPTIONS_INIT }

/**
 * Initialize git3_stash_apply_options structure
 *
 * Initializes a `git3_stash_apply_options` with default values. Equivalent to
 * creating an instance with `GIT3_STASH_APPLY_OPTIONS_INIT`.
 *
 * @param opts The `git3_stash_apply_options` struct to initialize.
 * @param version The struct version; pass `GIT3_STASH_APPLY_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_stash_apply_options_init(
	git3_stash_apply_options *opts, unsigned int version);

/**
 * Apply a single stashed state from the stash list.
 *
 * If local changes in the working directory conflict with changes in the
 * stash then GIT3_EMERGECONFLICT will be returned.  In this case, the index
 * will always remain unmodified and all files in the working directory will
 * remain unmodified.  However, if you are restoring untracked files or
 * ignored files and there is a conflict when applying the modified files,
 * then those files will remain in the working directory.
 *
 * If passing the GIT3_STASH_APPLY_REINSTATE_INDEX flag and there would be
 * conflicts when reinstating the index, the function will return
 * GIT3_EMERGECONFLICT and both the working directory and index will be left
 * unmodified.
 *
 * @param repo The owning repository.
 * @param index The position within the stash list. 0 points to the
 *              most recent stashed state.
 * @param options Optional options to control how stashes are applied.
 *
 * @return 0 on success, GIT3_ENOTFOUND if there's no stashed state for the
 *         given index, GIT3_EMERGECONFLICT if changes exist in the working
 *         directory, or an error code
 */
GIT3_EXTERN(int) git3_stash_apply(
	git3_repository *repo,
	size_t index,
	const git3_stash_apply_options *options);

/**
 * This is a callback function you can provide to iterate over all the
 * stashed states that will be invoked per entry.
 *
 * @param index The position within the stash list. 0 points to the
 *              most recent stashed state.
 * @param message The stash message.
 * @param stash_id The commit oid of the stashed state.
 * @param payload Extra parameter to callback function.
 * @return 0 to continue iterating or non-zero to stop.
 */
typedef int GIT3_CALLBACK(git3_stash_cb)(
	size_t index,
	const char *message,
	const git3_oid *stash_id,
	void *payload);

/**
 * Loop over all the stashed states and issue a callback for each one.
 *
 * If the callback returns a non-zero value, this will stop looping.
 *
 * @param repo Repository where to find the stash.
 *
 * @param callback Callback to invoke per found stashed state. The most
 *                 recent stash state will be enumerated first.
 *
 * @param payload Extra parameter to callback function.
 *
 * @return 0 on success, non-zero callback return value, or error code.
 */
GIT3_EXTERN(int) git3_stash_foreach(
	git3_repository *repo,
	git3_stash_cb callback,
	void *payload);

/**
 * Remove a single stashed state from the stash list.
 *
 * @param repo The owning repository.
 *
 * @param index The position within the stash list. 0 points to the
 * most recent stashed state.
 *
 * @return 0 on success, GIT3_ENOTFOUND if there's no stashed state for the given
 * index, or error code.
 */
GIT3_EXTERN(int) git3_stash_drop(
	git3_repository *repo,
	size_t index);

/**
 * Apply a single stashed state from the stash list and remove it from the list
 * if successful.
 *
 * @param repo The owning repository.
 * @param index The position within the stash list. 0 points to the
 *              most recent stashed state.
 * @param options Optional options to control how stashes are applied.
 *
 * @return 0 on success, GIT3_ENOTFOUND if there's no stashed state for the given
 * index, or error code. (see git3_stash_apply() above for details)
*/
GIT3_EXTERN(int) git3_stash_pop(
	git3_repository *repo,
	size_t index,
	const git3_stash_apply_options *options);

/** @} */
GIT3_END_DECL

#endif
