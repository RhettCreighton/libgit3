/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_blob_h__
#define INCLUDE_git_blob_h__

#include "common.h"
#include "types.h"
#include "oid.h"
#include "object.h"
#include "buffer.h"

/**
 * @file git3/blob.h
 * @brief A blob represents a file in a git repository.
 * @defgroup git3_blob Git blob load and write routines
 * @ingroup Git
 *
 * A blob represents a file in a git repository. This is the raw data
 * as it is stored in the repository itself. Blobs may be "filtered"
 * to produce the on-disk content.
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Lookup a blob object from a repository.
 *
 * @param[out] blob pointer to the looked up blob
 * @param repo the repo to use when locating the blob.
 * @param id identity of the blob to locate.
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_blob_lookup(
	git3_blob **blob,
	git3_repository *repo,
	const git3_oid *id);

/**
 * Lookup a blob object from a repository,
 * given a prefix of its identifier (short id).
 *
 * @see git3_object_lookup_prefix
 *
 * @param[out] blob pointer to the looked up blob
 * @param repo the repo to use when locating the blob.
 * @param id identity of the blob to locate.
 * @param len the length of the short identifier
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_blob_lookup_prefix(git3_blob **blob, git3_repository *repo, const git3_oid *id, size_t len);

/**
 * Close an open blob
 *
 * This is a wrapper around git3_object_free()
 *
 * IMPORTANT:
 * It *is* necessary to call this method when you stop
 * using a blob. Failure to do so will cause a memory leak.
 *
 * @param blob the blob to close
 */
GIT3_EXTERN(void) git3_blob_free(git3_blob *blob);

/**
 * Get the id of a blob.
 *
 * @param blob a previously loaded blob.
 * @return SHA1 hash for this blob.
 */
GIT3_EXTERN(const git3_oid *) git3_blob_id(const git3_blob *blob);

/**
 * Get the repository that contains the blob.
 *
 * @param blob A previously loaded blob.
 * @return Repository that contains this blob.
 */
GIT3_EXTERN(git3_repository *) git3_blob_owner(const git3_blob *blob);

/**
 * Get a read-only buffer with the raw content of a blob.
 *
 * A pointer to the raw content of a blob is returned;
 * this pointer is owned internally by the object and shall
 * not be free'd. The pointer may be invalidated at a later
 * time.
 *
 * @param blob pointer to the blob
 * @return @type `unsigned char *` the pointer, or NULL on error
 */
GIT3_EXTERN(const void *) git3_blob_rawcontent(const git3_blob *blob);

/**
 * Get the size in bytes of the contents of a blob
 *
 * @param blob pointer to the blob
 * @return size in bytes
 */
GIT3_EXTERN(git3_object_size_t) git3_blob_rawsize(const git3_blob *blob);

/**
 * Flags to control the functionality of `git3_blob_filter`.
 *
 * @flags
 */
typedef enum {
	/** When set, filters will not be applied to binary files. */
	GIT3_BLOB_FILTER_CHECK_FOR_BINARY = (1 << 0),

	/**
	 * When set, filters will not load configuration from the
	 * system-wide `gitattributes` in `/etc` (or system equivalent).
	 */
	GIT3_BLOB_FILTER_NO_SYSTEM_ATTRIBUTES = (1 << 1),

	/**
	 * When set, filters will be loaded from a `.gitattributes` file
	 * in the HEAD commit.
	 */
	GIT3_BLOB_FILTER_ATTRIBUTES_FROM_HEAD = (1 << 2),

	/**
	 * When set, filters will be loaded from a `.gitattributes` file
	 * in the specified commit.
	 */
	GIT3_BLOB_FILTER_ATTRIBUTES_FROM_COMMIT = (1 << 3)
} git3_blob_filter_flag_t;

/**
 * The options used when applying filter options to a file.
 *
 * Initialize with `GIT3_BLOB_FILTER_OPTIONS_INIT`. Alternatively, you can
 * use `git3_blob_filter_options_init`.
 *
 * @options[version] GIT3_BLOB_FILTER_OPTIONS_VERSION
 * @options[init_macro] GIT3_BLOB_FILTER_OPTIONS_INIT
 * @options[init_function] git3_blob_filter_options_init
 */
typedef struct {
	/** Version number of the options structure. */
	int version;

	/**
	 * Flags to control the filtering process, see `git3_blob_filter_flag_t` above.
	 *
	 * @type[flags] git3_blob_filter_flag_t
	 */
	uint32_t flags;

#ifdef GIT3_DEPRECATE_HARD
	/**
	 * Unused and reserved for ABI compatibility.
	 *
	 * @deprecated this value should not be set
	 */
	void *reserved;
#else
	/**
	 * This value is unused and reserved for API compatibility.
	 *
	 * @deprecated this value should not be set
	 */
	git3_oid *commit_id;
#endif

	/**
	 * The commit to load attributes from, when
	 * `GIT3_BLOB_FILTER_ATTRIBUTES_FROM_COMMIT` is specified.
	 */
	git3_oid attr_commit_id;
} git3_blob_filter_options;

/**
 * The current version number for the `git3_blob_filter_options` structure ABI.
 */
#define GIT3_BLOB_FILTER_OPTIONS_VERSION 1

/**
 * The default values for `git3_blob_filter_options`.
 */
#define GIT3_BLOB_FILTER_OPTIONS_INIT { \
		GIT3_BLOB_FILTER_OPTIONS_VERSION, \
		GIT3_BLOB_FILTER_CHECK_FOR_BINARY \
	}

/**
 * Initialize git3_blob_filter_options structure
 *
 * Initializes a `git3_blob_filter_options` with default values. Equivalent
 * to creating an instance with `GIT3_BLOB_FILTER_OPTIONS_INIT`.
 *
 * @param opts The `git3_blob_filter_options` struct to initialize.
 * @param version The struct version; pass GIT3_BLOB_FILTER_OPTIONS_VERSION
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_blob_filter_options_init(
	git3_blob_filter_options *opts,
	unsigned int version);

/**
 * Get a buffer with the filtered content of a blob.
 *
 * This applies filters as if the blob was being checked out to the
 * working directory under the specified filename.  This may apply
 * CRLF filtering or other types of changes depending on the file
 * attributes set for the blob and the content detected in it.
 *
 * The output is written into a `git3_buf` which the caller must dispose
 * when done (via `git3_buf_dispose`).
 *
 * If no filters need to be applied, then the `out` buffer will just
 * be populated with a pointer to the raw content of the blob.  In
 * that case, be careful to *not* free the blob until done with the
 * buffer or copy it into memory you own.
 *
 * @param out The git3_buf to be filled in
 * @param blob Pointer to the blob
 * @param as_path Path used for file attribute lookups, etc.
 * @param opts Options to use for filtering the blob
 * @return @type[enum] git3_error_code 0 on success or an error code
 */
GIT3_EXTERN(int) git3_blob_filter(
	git3_buf *out,
	git3_blob *blob,
	const char *as_path,
	git3_blob_filter_options *opts);

/**
 * Read a file from the working folder of a repository and write it
 * to the object database.
 *
 * @param[out] id return the id of the written blob
 * @param repo repository where the blob will be written.
 *	this repository cannot be bare
 * @param relative_path file from which the blob will be created,
 *	relative to the repository's working dir
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_blob_create_from_workdir(git3_oid *id, git3_repository *repo, const char *relative_path);

/**
 * Read a file from the filesystem (not necessarily inside the
 * working folder of the repository) and write it to the object
 * database.
 *
 * @param[out] id return the id of the written blob
 * @param repo repository where the blob will be written.
 *	this repository can be bare or not
 * @param path file from which the blob will be created
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_blob_create_from_disk(
	git3_oid *id,
	git3_repository *repo,
	const char *path);

/**
 * Create a stream to write a new blob into the object database.
 *
 * This function may need to buffer the data on disk and will in
 * general not be the right choice if you know the size of the data
 * to write. If you have data in memory, use
 * `git3_blob_create_from_buffer()`. If you do not, but know the size of
 * the contents (and don't want/need to perform filtering), use
 * `git3_odb_open_wstream()`.
 *
 * Don't close this stream yourself but pass it to
 * `git3_blob_create_from_stream_commit()` to commit the write to the
 * object db and get the object id.
 *
 * If the `hintpath` parameter is filled, it will be used to determine
 * what git filters should be applied to the object before it is written
 * to the object database.
 *
 * @param[out] out the stream into which to write
 * @param repo Repository where the blob will be written.
 *        This repository can be bare or not.
 * @param hintpath If not NULL, will be used to select data filters
 *        to apply onto the content of the blob to be created.
 * @return 0 or error code
 */
GIT3_EXTERN(int) git3_blob_create_from_stream(
	git3_writestream **out,
	git3_repository *repo,
	const char *hintpath);

/**
 * Close the stream and finalize writing the blob to the object database.
 *
 * The stream will be closed and freed.
 *
 * @param[out] out the id of the new blob
 * @param stream the stream to close
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_blob_create_from_stream_commit(
	git3_oid *out,
	git3_writestream *stream);

/**
 * Write an in-memory buffer to the object database as a blob.
 *
 * @param[out] id return the id of the written blob
 * @param repo repository where the blob will be written
 * @param buffer data to be written into the blob
 * @param len length of the data
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_blob_create_from_buffer(
	git3_oid *id, git3_repository *repo, const void *buffer, size_t len);

/**
 * Determine if the blob content is most likely binary or not.
 *
 * The heuristic used to guess if a file is binary is taken from core git:
 * Searching for NUL bytes and looking for a reasonable ratio of printable
 * to non-printable characters among the first 8000 bytes.
 *
 * @param blob The blob which content should be analyzed
 * @return @type bool 1 if the content of the blob is detected
 * as binary; 0 otherwise.
 */
GIT3_EXTERN(int) git3_blob_is_binary(const git3_blob *blob);

/**
 * Determine if the given content is most certainly binary or not;
 * this is the same mechanism used by `git3_blob_is_binary` but only
 * looking at raw data.
 *
 * @param data The blob data which content should be analyzed
 * @param len The length of the data
 * @return 1 if the content of the blob is detected
 * as binary; 0 otherwise.
 */
GIT3_EXTERN(int) git3_blob_data_is_binary(const char *data, size_t len);

/**
 * Create an in-memory copy of a blob. The copy must be explicitly
 * free'd or it will leak.
 *
 * @param[out] out Pointer to store the copy of the object
 * @param source Original object to copy
 * @return 0.
 */
GIT3_EXTERN(int) git3_blob_dup(git3_blob **out, git3_blob *source);

/** @} */
GIT3_END_DECL
#endif
