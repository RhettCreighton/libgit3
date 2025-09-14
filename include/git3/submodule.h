/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_submodule_h__
#define INCLUDE_git_submodule_h__

#include "common.h"
#include "types.h"
#include "oid.h"
#include "remote.h"
#include "checkout.h"

/**
 * @file git3/submodule.h
 * @brief Submodules place another repository's contents within this one
 *
 * Submodule support in libgit3 builds a list of known submodules and keeps
 * it in the repository.  The list is built from the .gitmodules file, the
 * .git/config file, the index, and the HEAD tree.  Items in the working
 * directory that look like submodules (i.e. a git repo) but are not
 * mentioned in those places won't be tracked.
 *
 * @defgroup git3_submodule Git submodule management routines
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Return codes for submodule status.
 *
 * A combination of these flags will be returned to describe the status of a
 * submodule.  Depending on the "ignore" property of the submodule, some of
 * the flags may never be returned because they indicate changes that are
 * supposed to be ignored.
 *
 * Submodule info is contained in 4 places: the HEAD tree, the index, config
 * files (both .git/config and .gitmodules), and the working directory.  Any
 * or all of those places might be missing information about the submodule
 * depending on what state the repo is in.  We consider all four places to
 * build the combination of status flags.
 *
 * There are four values that are not really status, but give basic info
 * about what sources of submodule data are available.  These will be
 * returned even if ignore is set to "ALL".
 *
 * * IN_HEAD   - superproject head contains submodule
 * * IN_INDEX  - superproject index contains submodule
 * * IN_CONFIG - superproject gitmodules has submodule
 * * IN_WD     - superproject workdir has submodule
 *
 * The following values will be returned so long as ignore is not "ALL".
 *
 * * INDEX_ADDED       - in index, not in head
 * * INDEX_DELETED     - in head, not in index
 * * INDEX_MODIFIED    - index and head don't match
 * * WD_UNINITIALIZED  - workdir contains empty directory
 * * WD_ADDED          - in workdir, not index
 * * WD_DELETED        - in index, not workdir
 * * WD_MODIFIED       - index and workdir head don't match
 *
 * The following can only be returned if ignore is "NONE" or "UNTRACKED".
 *
 * * WD_INDEX_MODIFIED - submodule workdir index is dirty
 * * WD_WD_MODIFIED    - submodule workdir has modified files
 *
 * Lastly, the following will only be returned for ignore "NONE".
 *
 * * WD_UNTRACKED      - wd contains untracked files
 */
typedef enum {
	GIT3_SUBMODULE_STATUS_IN_HEAD           = (1u << 0),
	GIT3_SUBMODULE_STATUS_IN_INDEX          = (1u << 1),
	GIT3_SUBMODULE_STATUS_IN_CONFIG         = (1u << 2),
	GIT3_SUBMODULE_STATUS_IN_WD             = (1u << 3),
	GIT3_SUBMODULE_STATUS_INDEX_ADDED       = (1u << 4),
	GIT3_SUBMODULE_STATUS_INDEX_DELETED     = (1u << 5),
	GIT3_SUBMODULE_STATUS_INDEX_MODIFIED    = (1u << 6),
	GIT3_SUBMODULE_STATUS_WD_UNINITIALIZED  = (1u << 7),
	GIT3_SUBMODULE_STATUS_WD_ADDED          = (1u << 8),
	GIT3_SUBMODULE_STATUS_WD_DELETED        = (1u << 9),
	GIT3_SUBMODULE_STATUS_WD_MODIFIED       = (1u << 10),
	GIT3_SUBMODULE_STATUS_WD_INDEX_MODIFIED = (1u << 11),
	GIT3_SUBMODULE_STATUS_WD_WD_MODIFIED    = (1u << 12),
	GIT3_SUBMODULE_STATUS_WD_UNTRACKED      = (1u << 13)
} git3_submodule_status_t;

/** Submodule source bits */
#define GIT3_SUBMODULE_STATUS__IN_FLAGS		0x000Fu
/** Submodule index status */
#define GIT3_SUBMODULE_STATUS__INDEX_FLAGS	0x0070u
/** Submodule working directory status */
#define GIT3_SUBMODULE_STATUS__WD_FLAGS		0x3F80u

/** Whether the submodule is modified */
#define GIT3_SUBMODULE_STATUS_IS_UNMODIFIED(S) \
	(((S) & ~GIT3_SUBMODULE_STATUS__IN_FLAGS) == 0)

/** Whether the submodule is modified (in the index) */
#define GIT3_SUBMODULE_STATUS_IS_INDEX_UNMODIFIED(S) \
	(((S) & GIT3_SUBMODULE_STATUS__INDEX_FLAGS) == 0)

/** Whether the submodule is modified (in the working directory) */
#define GIT3_SUBMODULE_STATUS_IS_WD_UNMODIFIED(S) \
	(((S) & (GIT3_SUBMODULE_STATUS__WD_FLAGS & \
	~GIT3_SUBMODULE_STATUS_WD_UNINITIALIZED)) == 0)

/** Whether the submodule working directory is dirty */
#define GIT3_SUBMODULE_STATUS_IS_WD_DIRTY(S) \
	(((S) & (GIT3_SUBMODULE_STATUS_WD_INDEX_MODIFIED | \
	GIT3_SUBMODULE_STATUS_WD_WD_MODIFIED | \
	GIT3_SUBMODULE_STATUS_WD_UNTRACKED)) != 0)

/**
 * Function pointer to receive each submodule
 *
 * @param sm git3_submodule currently being visited
 * @param name name of the submodule
 * @param payload value you passed to the foreach function as payload
 * @return 0 on success or error code
 */
typedef int GIT3_CALLBACK(git3_submodule_cb)(
	git3_submodule *sm, const char *name, void *payload);

/**
 * Submodule update options structure
 *
 * Initialize with `GIT3_SUBMODULE_UPDATE_OPTIONS_INIT`. Alternatively, you can
 * use `git3_submodule_update_options_init`.
 *
 */
typedef struct git3_submodule_update_options {
	unsigned int version;

	/**
	 * These options are passed to the checkout step. To disable
	 * checkout, set the `checkout_strategy` to `GIT3_CHECKOUT_NONE`
	 * or `GIT3_CHECKOUT_DRY_RUN`.
	 */
	git3_checkout_options checkout_opts;

	/**
	 * Options which control the fetch, including callbacks.
	 *
	 * The callbacks to use for reporting fetch progress, and for acquiring
	 * credentials in the event they are needed.
	 */
	git3_fetch_options fetch_opts;

	/**
	 * Allow fetching from the submodule's default remote if the target
	 * commit isn't found. Enabled by default.
	 */
	int allow_fetch;
} git3_submodule_update_options;

/** Current version for the `git3_submodule_update_options` structure */
#define GIT3_SUBMODULE_UPDATE_OPTIONS_VERSION 1

/** Static constructor for `git3_submodule_update_options` */
#define GIT3_SUBMODULE_UPDATE_OPTIONS_INIT \
	{ GIT3_SUBMODULE_UPDATE_OPTIONS_VERSION, \
	  GIT3_CHECKOUT_OPTIONS_INIT, \
	  GIT3_FETCH_OPTIONS_INIT, \
	  1 }

/**
 * Initialize git3_submodule_update_options structure
 *
 * Initializes a `git3_submodule_update_options` with default values. Equivalent to
 * creating an instance with `GIT3_SUBMODULE_UPDATE_OPTIONS_INIT`.
 *
 * @param opts The `git3_submodule_update_options` struct to initialize.
 * @param version The struct version; pass `GIT3_SUBMODULE_UPDATE_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_submodule_update_options_init(
	git3_submodule_update_options *opts, unsigned int version);

/**
 * Update a submodule. This will clone a missing submodule and
 * checkout the subrepository to the commit specified in the index of
 * the containing repository. If the submodule repository doesn't contain
 * the target commit (e.g. because fetchRecurseSubmodules isn't set), then
 * the submodule is fetched using the fetch options supplied in options.
 *
 * @param submodule Submodule object
 * @param init If the submodule is not initialized, setting this flag to true
 *        will initialize the submodule before updating. Otherwise, this will
 *        return an error if attempting to update an uninitialized repository.
 *        but setting this to true forces them to be updated.
 * @param options configuration options for the update.  If NULL, the
 *        function works as though GIT3_SUBMODULE_UPDATE_OPTIONS_INIT was passed.
 * @return 0 on success, any non-zero return value from a callback
 *         function, or a negative value to indicate an error (use
 *         `git3_error_last` for a detailed error message).
 */
GIT3_EXTERN(int) git3_submodule_update(git3_submodule *submodule, int init, git3_submodule_update_options *options);

/**
 * Lookup submodule information by name or path.
 *
 * Given either the submodule name or path (they are usually the same), this
 * returns a structure describing the submodule.
 *
 * There are two expected error scenarios:
 *
 * - The submodule is not mentioned in the HEAD, the index, and the config,
 *   but does "exist" in the working directory (i.e. there is a subdirectory
 *   that appears to be a Git repository).  In this case, this function
 *   returns GIT3_EEXISTS to indicate a sub-repository exists but not in a
 *   state where a git3_submodule can be instantiated.
 * - The submodule is not mentioned in the HEAD, index, or config and the
 *   working directory doesn't contain a value git repo at that path.
 *   There may or may not be anything else at that path, but nothing that
 *   looks like a submodule.  In this case, this returns GIT3_ENOTFOUND.
 *
 * You must call `git3_submodule_free` when done with the submodule.
 *
 * @param out Output ptr to submodule; pass NULL to just get return code
 * @param repo The parent repository
 * @param name The name of or path to the submodule; trailing slashes okay
 * @return 0 on success, GIT3_ENOTFOUND if submodule does not exist,
 *         GIT3_EEXISTS if a repository is found in working directory only,
 *         -1 on other errors.
 */
GIT3_EXTERN(int) git3_submodule_lookup(
	git3_submodule **out,
	git3_repository *repo,
	const char *name);

/**
 * Create an in-memory copy of a submodule. The copy must be explicitly
 * free'd or it will leak.
 *
 * @param out Pointer to store the copy of the submodule.
 * @param source Original submodule to copy.
 * @return 0
 */
GIT3_EXTERN(int) git3_submodule_dup(git3_submodule **out, git3_submodule *source);

/**
 * Release a submodule
 *
 * @param submodule Submodule object
 */
GIT3_EXTERN(void) git3_submodule_free(git3_submodule *submodule);

/**
 * Iterate over all tracked submodules of a repository.
 *
 * See the note on `git3_submodule` above.  This iterates over the tracked
 * submodules as described therein.
 *
 * If you are concerned about items in the working directory that look like
 * submodules but are not tracked, the diff API will generate a diff record
 * for workdir items that look like submodules but are not tracked, showing
 * them as added in the workdir.  Also, the status API will treat the entire
 * subdirectory of a contained git repo as a single GIT3_STATUS_WT_NEW item.
 *
 * @param repo The repository
 * @param callback Function to be called with the name of each submodule.
 *        Return a non-zero value to terminate the iteration.
 * @param payload Extra data to pass to callback
 * @return 0 on success, -1 on error, or non-zero return value of callback
 */
GIT3_EXTERN(int) git3_submodule_foreach(
	git3_repository *repo,
	git3_submodule_cb callback,
	void *payload);

/**
 * Set up a new git submodule for checkout.
 *
 * This does "git submodule add" up to the fetch and checkout of the
 * submodule contents.  It preps a new submodule, creates an entry in
 * .gitmodules and creates an empty initialized repository either at the
 * given path in the working directory or in .git/modules with a gitlink
 * from the working directory to the new repo.
 *
 * To fully emulate "git submodule add" call this function, then open the
 * submodule repo and perform the clone step as needed (if you don't need
 * anything custom see `git3_submodule_add_clone()`). Lastly, call
 * `git3_submodule_add_finalize()` to wrap up adding the new submodule and
 * .gitmodules to the index to be ready to commit.
 *
 * You must call `git3_submodule_free` on the submodule object when done.
 *
 * @param out The newly created submodule ready to open for clone
 * @param repo The repository in which you want to create the submodule
 * @param url URL for the submodule's remote
 * @param path Path at which the submodule should be created
 * @param use_gitlink Should workdir contain a gitlink to the repo in
 *        .git/modules vs. repo directly in workdir.
 * @return 0 on success, GIT3_EEXISTS if submodule already exists,
 *         -1 on other errors.
 */
GIT3_EXTERN(int) git3_submodule_add_setup(
	git3_submodule **out,
	git3_repository *repo,
	const char *url,
	const char *path,
	int use_gitlink);

/**
 * Perform the clone step for a newly created submodule.
 *
 * This performs the necessary `git3_clone` to setup a newly-created submodule.
 *
 * @param out The newly created repository object. Optional.
 * @param submodule The submodule currently waiting for its clone.
 * @param opts The options to use.
 *
 * @return 0 on success, -1 on other errors (see git3_clone).
 */
GIT3_EXTERN(int) git3_submodule_clone(
	git3_repository **out,
	git3_submodule *submodule,
	const git3_submodule_update_options *opts);

/**
 * Resolve the setup of a new git submodule.
 *
 * This should be called on a submodule once you have called add setup
 * and done the clone of the submodule.  This adds the .gitmodules file
 * and the newly cloned submodule to the index to be ready to be committed
 * (but doesn't actually do the commit).
 *
 * @param submodule The submodule to finish adding.
 * @return 0 or an error code.
 */
GIT3_EXTERN(int) git3_submodule_add_finalize(git3_submodule *submodule);

/**
 * Add current submodule HEAD commit to index of superproject.
 *
 * @param submodule The submodule to add to the index
 * @param write_index Boolean if this should immediately write the index
 *            file.  If you pass this as false, you will have to get the
 *            git3_index and explicitly call `git3_index_write()` on it to
 *            save the change.
 * @return 0 on success, <0 on failure
 */
GIT3_EXTERN(int) git3_submodule_add_to_index(
	git3_submodule *submodule,
	int write_index);

/**
 * Get the containing repository for a submodule.
 *
 * This returns a pointer to the repository that contains the submodule.
 * This is a just a reference to the repository that was passed to the
 * original `git3_submodule_lookup()` call, so if that repository has been
 * freed, then this may be a dangling reference.
 *
 * @param submodule Pointer to submodule object
 * @return Pointer to `git3_repository`
 */
GIT3_EXTERN(git3_repository *) git3_submodule_owner(git3_submodule *submodule);

/**
 * Get the name of submodule.
 *
 * @param submodule Pointer to submodule object
 * @return Pointer to the submodule name
 */
GIT3_EXTERN(const char *) git3_submodule_name(git3_submodule *submodule);

/**
 * Get the path to the submodule.
 *
 * The path is almost always the same as the submodule name, but the
 * two are actually not required to match.
 *
 * @param submodule Pointer to submodule object
 * @return Pointer to the submodule path
 */
GIT3_EXTERN(const char *) git3_submodule_path(git3_submodule *submodule);

/**
 * Get the URL for the submodule.
 *
 * @param submodule Pointer to submodule object
 * @return Pointer to the submodule url
 */
GIT3_EXTERN(const char *) git3_submodule_url(git3_submodule *submodule);

/**
 * Resolve a submodule url relative to the given repository.
 *
 * @param out buffer to store the absolute submodule url in
 * @param repo Pointer to repository object
 * @param url Relative url
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_submodule_resolve_url(git3_buf *out, git3_repository *repo, const char *url);

/**
* Get the branch for the submodule.
*
* @param submodule Pointer to submodule object
* @return Pointer to the submodule branch
*/
GIT3_EXTERN(const char *) git3_submodule_branch(git3_submodule *submodule);

/**
 * Set the branch for the submodule in the configuration
 *
 * After calling this, you may wish to call `git3_submodule_sync()` to
 * write the changes to the checked out submodule repository.
 *
 * @param repo the repository to affect
 * @param name the name of the submodule to configure
 * @param branch Branch that should be used for the submodule
 * @return 0 on success, <0 on failure
 */
GIT3_EXTERN(int) git3_submodule_set_branch(git3_repository *repo, const char *name, const char *branch);

/**
 * Set the URL for the submodule in the configuration
 *
 *
 * After calling this, you may wish to call `git3_submodule_sync()` to
 * write the changes to the checked out submodule repository.
 *
 * @param repo the repository to affect
 * @param name the name of the submodule to configure
 * @param url URL that should be used for the submodule
 * @return 0 on success, <0 on failure
 */
GIT3_EXTERN(int) git3_submodule_set_url(git3_repository *repo, const char *name, const char *url);

/**
 * Get the OID for the submodule in the index.
 *
 * @param submodule Pointer to submodule object
 * @return Pointer to git3_oid or NULL if submodule is not in index.
 */
GIT3_EXTERN(const git3_oid *) git3_submodule_index_id(git3_submodule *submodule);

/**
 * Get the OID for the submodule in the current HEAD tree.
 *
 * @param submodule Pointer to submodule object
 * @return Pointer to git3_oid or NULL if submodule is not in the HEAD.
 */
GIT3_EXTERN(const git3_oid *) git3_submodule_head_id(git3_submodule *submodule);

/**
 * Get the OID for the submodule in the current working directory.
 *
 * This returns the OID that corresponds to looking up 'HEAD' in the checked
 * out submodule.  If there are pending changes in the index or anything
 * else, this won't notice that.  You should call `git3_submodule_status()`
 * for a more complete picture about the state of the working directory.
 *
 * @param submodule Pointer to submodule object
 * @return Pointer to git3_oid or NULL if submodule is not checked out.
 */
GIT3_EXTERN(const git3_oid *) git3_submodule_wd_id(git3_submodule *submodule);

/**
 * Get the ignore rule that will be used for the submodule.
 *
 * These values control the behavior of `git3_submodule_status()` for this
 * submodule.  There are four ignore values:
 *
 *  - **GIT3_SUBMODULE_IGNORE_NONE** will consider any change to the contents
 *    of the submodule from a clean checkout to be dirty, including the
 *    addition of untracked files.  This is the default if unspecified.
 *  - **GIT3_SUBMODULE_IGNORE_UNTRACKED** examines the contents of the
 *    working tree (i.e. call `git3_status_foreach()` on the submodule) but
 *    UNTRACKED files will not count as making the submodule dirty.
 *  - **GIT3_SUBMODULE_IGNORE_DIRTY** means to only check if the HEAD of the
 *    submodule has moved for status.  This is fast since it does not need to
 *    scan the working tree of the submodule at all.
 *  - **GIT3_SUBMODULE_IGNORE_ALL** means not to open the submodule repo.
 *    The working directory will be consider clean so long as there is a
 *    checked out version present.
 *
 * @param submodule The submodule to check
 * @return The current git3_submodule_ignore_t valyue what will be used for
 *         this submodule.
 */
GIT3_EXTERN(git3_submodule_ignore_t) git3_submodule_ignore(
	git3_submodule *submodule);

/**
 * Set the ignore rule for the submodule in the configuration
 *
 * This does not affect any currently-loaded instances.
 *
 * @param repo the repository to affect
 * @param name the name of the submdule
 * @param ignore The new value for the ignore rule
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_submodule_set_ignore(
	git3_repository *repo,
	const char *name,
	git3_submodule_ignore_t ignore);

/**
 * Get the update rule that will be used for the submodule.
 *
 * This value controls the behavior of the `git submodule update` command.
 * There are four useful values documented with `git3_submodule_update_t`.
 *
 * @param submodule The submodule to check
 * @return The current git3_submodule_update_t value that will be used
 *         for this submodule.
 */
GIT3_EXTERN(git3_submodule_update_t) git3_submodule_update_strategy(
	git3_submodule *submodule);

/**
 * Set the update rule for the submodule in the configuration
 *
 * This setting won't affect any existing instances.
 *
 * @param repo the repository to affect
 * @param name the name of the submodule to configure
 * @param update The new value to use
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_submodule_set_update(
	git3_repository *repo,
	const char *name,
	git3_submodule_update_t update);

/**
 * Read the fetchRecurseSubmodules rule for a submodule.
 *
 * This accesses the submodule.<name>.fetchRecurseSubmodules value for
 * the submodule that controls fetching behavior for the submodule.
 *
 * Note that at this time, libgit3 does not honor this setting and the
 * fetch functionality current ignores submodules.
 *
 * @param submodule the submodule to examine
 * @return the submodule recursion configuration
 */
GIT3_EXTERN(git3_submodule_recurse_t) git3_submodule_fetch_recurse_submodules(
	git3_submodule *submodule);

/**
 * Set the fetchRecurseSubmodules rule for a submodule in the configuration
 *
 * This setting won't affect any existing instances.
 *
 * @param repo the repository to affect
 * @param name the submodule to configure
 * @param fetch_recurse_submodules the submodule recursion configuration
 * @return old value for fetchRecurseSubmodules
 */
GIT3_EXTERN(int) git3_submodule_set_fetch_recurse_submodules(
	git3_repository *repo,
	const char *name,
	git3_submodule_recurse_t fetch_recurse_submodules);

/**
 * Copy submodule info into ".git/config" file.
 *
 * Just like "git submodule init", this copies information about the
 * submodule into ".git/config".  You can use the accessor functions
 * above to alter the in-memory git3_submodule object and control what
 * is written to the config, overriding what is in .gitmodules.
 *
 * @param submodule The submodule to write into the superproject config
 * @param overwrite By default, existing entries will not be overwritten,
 *                  but setting this to true forces them to be updated.
 * @return 0 on success, <0 on failure.
 */
GIT3_EXTERN(int) git3_submodule_init(git3_submodule *submodule, int overwrite);

/**
 * Set up the subrepository for a submodule in preparation for clone.
 *
 * This function can be called to init and set up a submodule
 * repository from a submodule in preparation to clone it from
 * its remote.
 *
 * @param out Output pointer to the created git repository.
 * @param sm The submodule to create a new subrepository from.
 * @param use_gitlink Should the workdir contain a gitlink to
 *        the repo in .git/modules vs. repo directly in workdir.
 * @return 0 on success, <0 on failure.
 */
GIT3_EXTERN(int) git3_submodule_repo_init(
	git3_repository **out,
	const git3_submodule *sm,
	int use_gitlink);

/**
 * Copy submodule remote info into submodule repo.
 *
 * This copies the information about the submodules URL into the checked out
 * submodule config, acting like "git submodule sync".  This is useful if
 * you have altered the URL for the submodule (or it has been altered by a
 * fetch of upstream changes) and you need to update your local repo.
 *
 * @param submodule The submodule to copy.
 * @return 0 or an error code.
 */
GIT3_EXTERN(int) git3_submodule_sync(git3_submodule *submodule);

/**
 * Open the repository for a submodule.
 *
 * This is a newly opened repository object.  The caller is responsible for
 * calling `git3_repository_free()` on it when done.  Multiple calls to this
 * function will return distinct `git3_repository` objects.  This will only
 * work if the submodule is checked out into the working directory.
 *
 * @param repo Pointer to the submodule repo which was opened
 * @param submodule Submodule to be opened
 * @return 0 on success, <0 if submodule repo could not be opened.
 */
GIT3_EXTERN(int) git3_submodule_open(
	git3_repository **repo,
	git3_submodule *submodule);

/**
 * Reread submodule info from config, index, and HEAD.
 *
 * Call this to reread cached submodule information for this submodule if
 * you have reason to believe that it has changed.
 *
 * @param submodule The submodule to reload
 * @param force Force reload even if the data doesn't seem out of date
 * @return 0 on success, <0 on error
 */
GIT3_EXTERN(int) git3_submodule_reload(git3_submodule *submodule, int force);

/**
 * Get the status for a submodule.
 *
 * This looks at a submodule and tries to determine the status.  It
 * will return a combination of the `GIT3_SUBMODULE_STATUS` values above.
 * How deeply it examines the working directory to do this will depend
 * on the `git3_submodule_ignore_t` value for the submodule.
 *
 * @param status Combination of `GIT3_SUBMODULE_STATUS` flags
 * @param repo the repository in which to look
 * @param name name of the submodule
 * @param ignore the ignore rules to follow
 * @return 0 on success, <0 on error
 */
GIT3_EXTERN(int) git3_submodule_status(
	unsigned int *status,
	git3_repository *repo,
	const char *name,
	git3_submodule_ignore_t ignore);

/**
 * Get the locations of submodule information.
 *
 * This is a bit like a very lightweight version of `git3_submodule_status`.
 * It just returns a made of the first four submodule status values (i.e.
 * the ones like GIT3_SUBMODULE_STATUS_IN_HEAD, etc) that tell you where the
 * submodule data comes from (i.e. the HEAD commit, gitmodules file, etc.).
 * This can be useful if you want to know if the submodule is present in the
 * working directory at this point in time, etc.
 *
 * @param location_status Combination of first four `GIT3_SUBMODULE_STATUS` flags
 * @param submodule Submodule for which to get status
 * @return 0 on success, <0 on error
 */
GIT3_EXTERN(int) git3_submodule_location(
	unsigned int *location_status,
	git3_submodule *submodule);

/** @} */
GIT3_END_DECL

#endif
