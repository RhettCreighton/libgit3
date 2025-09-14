/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_indexer_h__
#define INCLUDE_git_indexer_h__

#include "common.h"
#include "types.h"
#include "oid.h"

/**
 * @file git3/indexer.h
 * @brief Packfile indexing
 * @ingroup Git
 * @{
 *
 * Indexing is the operation of taking a packfile - which is simply a
 * collection of unordered commits - and producing an "index" so that
 * one can lookup a commit in the packfile by object ID.
 */
GIT3_BEGIN_DECL

/** A git indexer object */
typedef struct git3_indexer git3_indexer;

/**
 * This structure is used to provide callers information about the
 * progress of indexing a packfile, either directly or part of a
 * fetch or clone that downloads a packfile.
 */
typedef struct git3_indexer_progress {
	/** number of objects in the packfile being indexed */
	unsigned int total_objects;

	/** received objects that have been hashed */
	unsigned int indexed_objects;

	/** received_objects: objects which have been downloaded */
	unsigned int received_objects;

	/**
	 * locally-available objects that have been injected in order
	 * to fix a thin pack
	 */
	unsigned int local_objects;

	/** number of deltas in the packfile being indexed */
	unsigned int total_deltas;

	/** received deltas that have been indexed */
	unsigned int indexed_deltas;

	/** size of the packfile received up to now */
	size_t received_bytes;
} git3_indexer_progress;

/**
 * Type for progress callbacks during indexing.  Return a value less
 * than zero to cancel the indexing or download.
 *
 * @param stats Structure containing information about the state of the transfer
 * @param payload Payload provided by caller
 * @return 0 on success or an error code
 */
typedef int GIT3_CALLBACK(git3_indexer_progress_cb)(const git3_indexer_progress *stats, void *payload);

/**
 * Options for indexer configuration
 */
typedef struct git3_indexer_options {
	unsigned int version;

#ifdef GIT3_EXPERIMENTAL_SHA256
	/** permissions to use creating packfile or 0 for defaults */
	unsigned int mode;

	/** the type of object ids in the packfile or 0 for SHA1 */
	git3_oid_t oid_type;

	/**
	 * object database from which to read base objects when
	 * fixing thin packs. This can be NULL if there are no thin
	 * packs; if a thin pack is encountered, an error will be
	 * returned if there are bases missing.
	 */
	git3_odb *odb;
#endif

	/** progress_cb function to call with progress information */
	git3_indexer_progress_cb progress_cb;

	/** progress_cb_payload payload for the progress callback */
	void *progress_cb_payload;

	/** Do connectivity checks for the received pack */
	unsigned char verify;
} git3_indexer_options;

/** Current version for the `git3_indexer_options` structure */
#define GIT3_INDEXER_OPTIONS_VERSION 1

/** Static constructor for `git3_indexer_options` */
#define GIT3_INDEXER_OPTIONS_INIT { GIT3_INDEXER_OPTIONS_VERSION }

/**
 * Initializes a `git3_indexer_options` with default values. Equivalent to
 * creating an instance with GIT3_INDEXER_OPTIONS_INIT.
 *
 * @param opts the `git3_indexer_options` struct to initialize.
 * @param version Version of struct; pass `GIT3_INDEXER_OPTIONS_VERSION`
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_indexer_options_init(
	git3_indexer_options *opts,
	unsigned int version);

#ifdef GIT3_EXPERIMENTAL_SHA256
/**
 * Create a new indexer instance
 *
 * @param out where to store the indexer instance
 * @param path to the directory where the packfile should be stored
 * @param opts the options to create the indexer with
 * @return 0 or an error code.
 */
GIT3_EXTERN(int) git3_indexer_new(
		git3_indexer **out,
		const char *path,
		git3_indexer_options *opts);
#else
/**
 * Create a new indexer instance
 *
 * @param out where to store the indexer instance
 * @param path to the directory where the packfile should be stored
 * @param mode permissions to use creating packfile or 0 for defaults
 * @param odb object database from which to read base objects when
 * fixing thin packs. Pass NULL if no thin pack is expected (an error
 * will be returned if there are bases missing)
 * @param opts Optional structure containing additional options. See
 * `git3_indexer_options` above.
 * @return 0 or an error code.
 */
GIT3_EXTERN(int) git3_indexer_new(
		git3_indexer **out,
		const char *path,
		unsigned int mode,
		git3_odb *odb,
		git3_indexer_options *opts);
#endif

/**
 * Add data to the indexer
 *
 * @param idx the indexer
 * @param data the data to add
 * @param size the size of the data in bytes
 * @param stats stat storage
 * @return 0 or an error code.
 */
GIT3_EXTERN(int) git3_indexer_append(git3_indexer *idx, const void *data, size_t size, git3_indexer_progress *stats);

/**
 * Finalize the pack and index
 *
 * Resolve any pending deltas and write out the index file
 *
 * @param idx the indexer
 * @param stats Stat storage.
 * @return 0 or an error code.
 */
GIT3_EXTERN(int) git3_indexer_commit(git3_indexer *idx, git3_indexer_progress *stats);

#ifndef GIT3_DEPRECATE_HARD
/**
 * Get the packfile's hash
 *
 * A packfile's name is derived from the sorted hashing of all object
 * names. This is only correct after the index has been finalized.
 *
 * @deprecated use git3_indexer_name
 * @param idx the indexer instance
 * @return the packfile's hash
 */
GIT3_EXTERN(const git3_oid *) git3_indexer_hash(const git3_indexer *idx);
#endif

/**
 * Get the unique name for the resulting packfile.
 *
 * The packfile's name is derived from the packfile's content.
 * This is only correct after the index has been finalized.
 *
 * @param idx the indexer instance
 * @return a NUL terminated string for the packfile name
 */
GIT3_EXTERN(const char *) git3_indexer_name(const git3_indexer *idx);

/**
 * Free the indexer and its resources
 *
 * @param idx the indexer to free
 */
GIT3_EXTERN(void) git3_indexer_free(git3_indexer *idx);

/** @} */
GIT3_END_DECL

#endif
