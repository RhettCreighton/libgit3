/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_diff_h__
#define INCLUDE_sys_git_diff_h__

#include "git3/common.h"
#include "git3/types.h"
#include "git3/oid.h"
#include "git3/diff.h"
#include "git3/status.h"

/**
 * @file git3/sys/diff.h
 * @brief Low-level diff utilities
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Diff print callback that writes to a git3_buf.
 *
 * This function is provided not for you to call it directly, but instead
 * so you can use it as a function pointer to the `git3_diff_print` or
 * `git3_patch_print` APIs.  When using those APIs, you specify a callback
 * to actually handle the diff and/or patch data.
 *
 * Use this callback to easily write that data to a `git3_buf` buffer.  You
 * must pass a `git3_buf *` value as the payload to the `git3_diff_print`
 * and/or `git3_patch_print` function.  The data will be appended to the
 * buffer (after any existing content).
 *
 * @param delta the delta being processed
 * @param hunk the hunk being processed
 * @param line the line being processed
 * @param payload the payload provided by the diff generator
 * @return 0 on success or an error code
 */
GIT3_EXTERN(int) git3_diff_print_callback__to_buf(
	const git3_diff_delta *delta,
	const git3_diff_hunk *hunk,
	const git3_diff_line *line,
	void *payload); /**< payload must be a `git3_buf *` */

/**
 * Diff print callback that writes to stdio FILE handle.
 *
 * This function is provided not for you to call it directly, but instead
 * so you can use it as a function pointer to the `git3_diff_print` or
 * `git3_patch_print` APIs.  When using those APIs, you specify a callback
 * to actually handle the diff and/or patch data.
 *
 * Use this callback to easily write that data to a stdio FILE handle.  You
 * must pass a `FILE *` value (such as `stdout` or `stderr` or the return
 * value from `fopen()`) as the payload to the `git3_diff_print`
 * and/or `git3_patch_print` function.  If you pass NULL, this will write
 * data to `stdout`.
 *
 * @param delta the delta being processed
 * @param hunk the hunk being processed
 * @param line the line being processed
 * @param payload the payload provided by the diff generator
 * @return 0 on success or an error code
 */
GIT3_EXTERN(int) git3_diff_print_callback__to_file_handle(
	const git3_diff_delta *delta,
	const git3_diff_hunk *hunk,
	const git3_diff_line *line,
	void *payload); /**< payload must be a `FILE *` */


/**
 * Performance data from diffing
 */
typedef struct {
	unsigned int version;
	size_t stat_calls; /**< Number of stat() calls performed */
	size_t oid_calculations; /**< Number of ID calculations */
} git3_diff_perfdata;

/** Current version for the `git3_diff_perfdata_options` structure */
#define GIT3_DIFF_PERFDATA_VERSION 1

/** Static constructor for `git3_diff_perfdata_options` */
#define GIT3_DIFF_PERFDATA_INIT {GIT3_DIFF_PERFDATA_VERSION,0,0}

/**
 * Get performance data for a diff object.
 *
 * @param out Structure to be filled with diff performance data
 * @param diff Diff to read performance data from
 * @return 0 for success, <0 for error
 */
GIT3_EXTERN(int) git3_diff_get_perfdata(
	git3_diff_perfdata *out, const git3_diff *diff);

/**
 * Get performance data for diffs from a git3_status_list
 *
 * @param out Structure to be filled with diff performance data
 * @param status Diff to read performance data from
 * @return 0 for success, <0 for error
 */
GIT3_EXTERN(int) git3_status_list_get_perfdata(
	git3_diff_perfdata *out, const git3_status_list *status);

/** @} */
GIT3_END_DECL

#endif
