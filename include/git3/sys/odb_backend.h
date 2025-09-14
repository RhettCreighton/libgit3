/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_odb_backend_h__
#define INCLUDE_sys_git_odb_backend_h__

#include "git3/common.h"
#include "git3/types.h"
#include "git3/oid.h"
#include "git3/odb.h"

/**
 * @file git3/sys/odb_backend.h
 * @brief Object database backends for custom object storage
 * @defgroup git3_backend Object database backends for custom object storage
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * An instance for a custom backend
 */
struct git3_odb_backend {
	unsigned int version;
	git3_odb *odb;

	/* read and read_prefix each return to libgit3 a buffer which
	 * will be freed later. The buffer should be allocated using
	 * the function git3_odb_backend_data_alloc to ensure that libgit3
	 * can safely free it later. */
	int GIT3_CALLBACK(read)(
		void **, size_t *, git3_object_t *, git3_odb_backend *, const git3_oid *);

	/* To find a unique object given a prefix of its oid.  The oid given
	 * must be so that the remaining (GIT3_OID_SHA1_HEXSIZE - len)*4 bits are 0s.
	 */
	int GIT3_CALLBACK(read_prefix)(
		git3_oid *, void **, size_t *, git3_object_t *,
		git3_odb_backend *, const git3_oid *, size_t);

	int GIT3_CALLBACK(read_header)(
		size_t *, git3_object_t *, git3_odb_backend *, const git3_oid *);

	/**
	 * Write an object into the backend. The id of the object has
	 * already been calculated and is passed in.
	 */
	int GIT3_CALLBACK(write)(
		git3_odb_backend *, const git3_oid *, const void *, size_t, git3_object_t);

	int GIT3_CALLBACK(writestream)(
		git3_odb_stream **, git3_odb_backend *, git3_object_size_t, git3_object_t);

	int GIT3_CALLBACK(readstream)(
		git3_odb_stream **, size_t *, git3_object_t *,
		git3_odb_backend *, const git3_oid *);

	int GIT3_CALLBACK(exists)(
		git3_odb_backend *, const git3_oid *);

	int GIT3_CALLBACK(exists_prefix)(
		git3_oid *, git3_odb_backend *, const git3_oid *, size_t);

	/**
	 * If the backend implements a refreshing mechanism, it should be exposed
	 * through this endpoint. Each call to `git3_odb_refresh()` will invoke it.
	 *
	 * The odb layer will automatically call this when needed on failed
	 * lookups (ie. `exists()`, `read()`, `read_header()`).
	 */
	int GIT3_CALLBACK(refresh)(git3_odb_backend *);

	int GIT3_CALLBACK(foreach)(
		git3_odb_backend *, git3_odb_foreach_cb cb, void *payload);

	int GIT3_CALLBACK(writepack)(
		git3_odb_writepack **, git3_odb_backend *, git3_odb *odb,
		git3_indexer_progress_cb progress_cb, void *progress_payload);

	/**
	 * If the backend supports pack files, this will create a
	 * `multi-pack-index` file which will contain an index of all objects
	 * across all the `.pack` files.
	 */
	int GIT3_CALLBACK(writemidx)(git3_odb_backend *);

	/**
	 * "Freshens" an already existing object, updating its last-used
	 * time.  This occurs when `git3_odb_write` was called, but the
	 * object already existed (and will not be re-written).  The
	 * underlying implementation may want to update last-used timestamps.
	 *
	 * If callers implement this, they should return `0` if the object
	 * exists and was freshened, and non-zero otherwise.
	 */
	int GIT3_CALLBACK(freshen)(git3_odb_backend *, const git3_oid *);

	/**
	 * Frees any resources held by the odb (including the `git3_odb_backend`
	 * itself). An odb backend implementation must provide this function.
	 */
	void GIT3_CALLBACK(free)(git3_odb_backend *);
};

/** Current version for the `git3_odb_backend_options` structure */
#define GIT3_ODB_BACKEND_VERSION 1

/** Static constructor for `git3_odb_backend_options` */
#define GIT3_ODB_BACKEND_INIT {GIT3_ODB_BACKEND_VERSION}

/**
 * Initializes a `git3_odb_backend` with default values. Equivalent to
 * creating an instance with GIT3_ODB_BACKEND_INIT.
 *
 * @param backend the `git3_odb_backend` struct to initialize.
 * @param version Version the struct; pass `GIT3_ODB_BACKEND_VERSION`
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_odb_init_backend(
	git3_odb_backend *backend,
	unsigned int version);

/**
 * Allocate data for an ODB object.  Custom ODB backends may use this
 * to provide data back to the ODB from their read function.  This
 * memory should not be freed once it is returned to libgit3.  If a
 * custom ODB uses this function but encounters an error and does not
 * return this data to libgit3, then they should use the corresponding
 * git3_odb_backend_data_free function.
 *
 * @param backend the ODB backend that is allocating this memory
 * @param len the number of bytes to allocate
 * @return the allocated buffer on success or NULL if out of memory
 */
GIT3_EXTERN(void *) git3_odb_backend_data_alloc(git3_odb_backend *backend, size_t len);

/**
 * Frees custom allocated ODB data.  This should only be called when
 * memory allocated using git3_odb_backend_data_alloc is not returned
 * to libgit3 because the backend encountered an error in the read
 * function after allocation and did not return this data to libgit3.
 *
 * @param backend the ODB backend that is freeing this memory
 * @param data the buffer to free
 */
GIT3_EXTERN(void) git3_odb_backend_data_free(git3_odb_backend *backend, void *data);


/*
 * Users can avoid deprecated functions by defining `GIT3_DEPRECATE_HARD`.
 */
#ifndef GIT3_DEPRECATE_HARD

/**
 * Allocate memory for an ODB object from a custom backend.  This is
 * an alias of `git3_odb_backend_data_alloc` and is preserved for
 * backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated git3_odb_backend_data_alloc
 * @see git3_odb_backend_data_alloc
 */
GIT3_EXTERN(void *) git3_odb_backend_malloc(git3_odb_backend *backend, size_t len);

#endif

/** @} */
GIT3_END_DECL

#endif
