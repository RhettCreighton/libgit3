/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_merge_h__
#define INCLUDE_sys_git_merge_h__

#include "git3/common.h"
#include "git3/types.h"
#include "git3/index.h"
#include "git3/merge.h"

/**
 * @file git3/sys/merge.h
 * @brief Custom merge drivers
 * @defgroup git3_merge Custom merge drivers
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * A "merge driver" is a mechanism that can be configured to handle
 * conflict resolution for files changed in both the "ours" and "theirs"
 * side of a merge.
 */
typedef struct git3_merge_driver git3_merge_driver;

/**
 * Look up a merge driver by name
 *
 * @param name The name of the merge driver
 * @return Pointer to the merge driver object or NULL if not found
 */
GIT3_EXTERN(git3_merge_driver *) git3_merge_driver_lookup(const char *name);

/** The "text" merge driver */
#define GIT3_MERGE_DRIVER_TEXT   "text"
/** The "binary" merge driver */
#define GIT3_MERGE_DRIVER_BINARY "binary"
/** The "union" merge driver */
#define GIT3_MERGE_DRIVER_UNION  "union"

/**
 * A merge driver source represents the file to be merged
 */
typedef struct git3_merge_driver_source git3_merge_driver_source;

/**
 * Get the repository that the source data is coming from.
 *
 * @param src the merge driver source
 * @return the repository
 */
GIT3_EXTERN(git3_repository *) git3_merge_driver_source_repo(
	const git3_merge_driver_source *src);

/**
 * Gets the ancestor of the file to merge.
 *
 * @param src the merge driver source
 * @return the ancestor or NULL if there was no ancestor
 */
GIT3_EXTERN(const git3_index_entry *) git3_merge_driver_source_ancestor(
	const git3_merge_driver_source *src);

/**
 * Gets the ours side of the file to merge.
 *
 * @param src the merge driver source
 * @return the ours side or NULL if there was no ours side
 */
GIT3_EXTERN(const git3_index_entry *) git3_merge_driver_source_ours(
	const git3_merge_driver_source *src);

/**
 * Gets the theirs side of the file to merge.
 *
 * @param src the merge driver source
 * @return the theirs side or NULL if there was no theirs side
 */
GIT3_EXTERN(const git3_index_entry *) git3_merge_driver_source_theirs(
	const git3_merge_driver_source *src);

/**
 * Gets the merge file options that the merge was invoked with.
 *
 * @param src the merge driver source
 * @return the options
 */
GIT3_EXTERN(const git3_merge_file_options *) git3_merge_driver_source_file_options(
	const git3_merge_driver_source *src);


/**
 * Initialize callback on merge driver
 *
 * Specified as `driver.initialize`, this is an optional callback invoked
 * before a merge driver is first used.  It will be called once at most
 * per library lifetime.
 *
 * If non-NULL, the merge driver's `initialize` callback will be invoked
 * right before the first use of the driver, so you can defer expensive
 * initialization operations (in case libgit3 is being used in a way that
 * doesn't need the merge driver).
 *
 * @param self the merge driver to initialize
 * @return 0 on success, or a negative number on failure
 */
typedef int GIT3_CALLBACK(git3_merge_driver_init_fn)(git3_merge_driver *self);

/**
 * Shutdown callback on merge driver
 *
 * Specified as `driver.shutdown`, this is an optional callback invoked
 * when the merge driver is unregistered or when libgit3 is shutting down.
 * It will be called once at most and should release resources as needed.
 * This may be called even if the `initialize` callback was not made.
 *
 * Typically this function will free the `git3_merge_driver` object itself.
 *
 * @param self the merge driver to shutdown
 */
typedef void GIT3_CALLBACK(git3_merge_driver_shutdown_fn)(git3_merge_driver *self);

/**
 * Callback to perform the merge.
 *
 * Specified as `driver.apply`, this is the callback that actually does the
 * merge.  If it can successfully perform a merge, it should populate
 * `path_out` with a pointer to the filename to accept, `mode_out` with
 * the resultant mode, and `merged_out` with the buffer of the merged file
 * and then return 0.  If the driver returns `GIT3_PASSTHROUGH`, then the
 * default merge driver should instead be run.  It can also return
 * `GIT3_EMERGECONFLICT` if the driver is not able to produce a merge result,
 * and the file will remain conflicted.  Any other errors will fail and
 * return to the caller.
 *
 * The `filter_name` contains the name of the filter that was invoked, as
 * specified by the file's attributes.
 *
 * The `src` contains the data about the file to be merged.
 *
 * @param self the merge driver
 * @param path_out the resolved path
 * @param mode_out the resolved mode
 * @param merged_out the merged output contents
 * @param filter_name the filter that was invoked
 * @param src the data about the unmerged file
 * @return 0 on success, or an error code
 */
typedef int GIT3_CALLBACK(git3_merge_driver_apply_fn)(
	git3_merge_driver *self,
	const char **path_out,
	uint32_t *mode_out,
	git3_buf *merged_out,
	const char *filter_name,
	const git3_merge_driver_source *src);

/**
 * Merge driver structure used to register custom merge drivers.
 *
 * To associate extra data with a driver, allocate extra data and put the
 * `git3_merge_driver` struct at the start of your data buffer, then cast
 * the `self` pointer to your larger structure when your callback is invoked.
 */
struct git3_merge_driver {
	/** The `version` should be set to `GIT3_MERGE_DRIVER_VERSION`. */
	unsigned int                 version;

	/** Called when the merge driver is first used for any file. */
	git3_merge_driver_init_fn     initialize;

	/** Called when the merge driver is unregistered from the system. */
	git3_merge_driver_shutdown_fn shutdown;

	/**
	 * Called to merge the contents of a conflict.  If this function
	 * returns `GIT3_PASSTHROUGH` then the default (`text`) merge driver
	 * will instead be invoked.  If this function returns
	 * `GIT3_EMERGECONFLICT` then the file will remain conflicted.
	 */
	git3_merge_driver_apply_fn    apply;
};

/** The version for the `git3_merge_driver` */
#define GIT3_MERGE_DRIVER_VERSION 1

/**
 * Register a merge driver under a given name.
 *
 * As mentioned elsewhere, the initialize callback will not be invoked
 * immediately.  It is deferred until the driver is used in some way.
 *
 * Currently the merge driver registry is not thread safe, so any
 * registering or deregistering of merge drivers must be done outside of
 * any possible usage of the drivers (i.e. during application setup or
 * shutdown).
 *
 * @param name The name of this driver to match an attribute.  Attempting
 * 			to register with an in-use name will return GIT3_EEXISTS.
 * @param driver The merge driver definition.  This pointer will be stored
 *			as is by libgit3 so it must be a durable allocation (either
 *			static or on the heap).
 * @return 0 on successful registry, error code <0 on failure
 */
GIT3_EXTERN(int) git3_merge_driver_register(
	const char *name, git3_merge_driver *driver);

/**
 * Remove the merge driver with the given name.
 *
 * Attempting to remove the builtin libgit3 merge drivers is not permitted
 * and will return an error.
 *
 * Currently the merge driver registry is not thread safe, so any
 * registering or deregistering of drivers must be done outside of any
 * possible usage of the drivers (i.e. during application setup or shutdown).
 *
 * @param name The name under which the merge driver was registered
 * @return 0 on success, error code <0 on failure
 */
GIT3_EXTERN(int) git3_merge_driver_unregister(const char *name);

/** @} */
GIT3_END_DECL

#endif
