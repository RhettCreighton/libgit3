/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_midx_h__
#define INCLUDE_sys_git_midx_h__

#include "git3/common.h"
#include "git3/types.h"

/**
 * @file git3/sys/midx.h
 * @brief Incremental multi-pack indexes
 * @defgroup git3_midx Incremental multi-pack indexes
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Options structure for `git3_midx_writer_options`.
 *
 * Initialize with `GIT3_MIDX_WRITER_OPTIONS_INIT`. Alternatively,
 * you can use `git3_midx_writer_options_init`.
 */
typedef struct {
	unsigned int version;

#ifdef GIT3_EXPERIMENTAL_SHA256
	/** The object ID type that this commit graph contains. */
	git3_oid_t oid_type;
#endif
} git3_midx_writer_options;

/** Current version for the `git3_midx_writer_options` structure */
#define GIT3_MIDX_WRITER_OPTIONS_VERSION 1

/** Static constructor for `git3_midx_writer_options` */
#define GIT3_MIDX_WRITER_OPTIONS_INIT { \
		GIT3_MIDX_WRITER_OPTIONS_VERSION \
	}

/**
 * Initialize git3_midx_writer_options structure
 *
 * Initializes a `git3_midx_writer_options` with default values.
 * Equivalent to creating an instance with
 * `GIT3_MIDX_WRITER_OPTIONS_INIT`.
 *
 * @param opts The `git3_midx_writer_options` struct to initialize.
 * @param version The struct version; pass `GIT3_MIDX_WRITER_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_midx_writer_options_init(
	git3_midx_writer_options *opts,
	unsigned int version);

/**
 * Create a new writer for `multi-pack-index` files.
 *
 * @param out location to store the writer pointer.
 * @param pack_dir the directory where the `.pack` and `.idx` files are. The
 * `multi-pack-index` file will be written in this directory, too.
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_midx_writer_new(
		git3_midx_writer **out,
		const char *pack_dir
#ifdef GIT3_EXPERIMENTAL_SHA256
		, git3_midx_writer_options *options
#endif
		);

/**
 * Free the multi-pack-index writer and its resources.
 *
 * @param w the writer to free. If NULL no action is taken.
 */
GIT3_EXTERN(void) git3_midx_writer_free(git3_midx_writer *w);

/**
 * Add an `.idx` file to the writer.
 *
 * @param w the writer
 * @param idx_path the path of an `.idx` file.
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_midx_writer_add(
		git3_midx_writer *w,
		const char *idx_path);

/**
 * Write a `multi-pack-index` file to a file.
 *
 * @param w the writer
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_midx_writer_commit(
		git3_midx_writer *w);

/**
 * Dump the contents of the `multi-pack-index` to an in-memory buffer.
 *
 * @param midx Buffer where to store the contents of the `multi-pack-index`.
 * @param w the writer
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_midx_writer_dump(
		git3_buf *midx,
		git3_midx_writer *w);

/** @} */
GIT3_END_DECL

#endif
