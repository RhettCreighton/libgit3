/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_trace_h__
#define INCLUDE_git_trace_h__

#include "common.h"
#include "types.h"

/**
 * @file git3/trace.h
 * @brief Tracing functionality to introspect libgit3 in your application
 * @defgroup git3_trace Tracing functionality to introspect libgit3 in your application
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * Available tracing levels.  When tracing is set to a particular level,
 * callers will be provided tracing at the given level and all lower levels.
 */
typedef enum {
	/** No tracing will be performed. */
	GIT3_TRACE_NONE = 0,

	/** Severe errors that may impact the program's execution */
	GIT3_TRACE_FATAL = 1,

	/** Errors that do not impact the program's execution */
	GIT3_TRACE_ERROR = 2,

	/** Warnings that suggest abnormal data */
	GIT3_TRACE_WARN = 3,

	/** Informational messages about program execution */
	GIT3_TRACE_INFO = 4,

	/** Detailed data that allows for debugging */
	GIT3_TRACE_DEBUG = 5,

	/** Exceptionally detailed debugging data */
	GIT3_TRACE_TRACE = 6
} git3_trace_level_t;

/**
 * An instance for a tracing function
 *
 * @param level the trace level
 * @param msg the trace message
 */
typedef void GIT3_CALLBACK(git3_trace_cb)(
	git3_trace_level_t level,
	const char *msg);

/**
 * Sets the system tracing configuration to the specified level with the
 * specified callback.  When system events occur at a level equal to, or
 * lower than, the given level they will be reported to the given callback.
 *
 * @param level Level to set tracing to
 * @param cb Function to call with trace data
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_trace_set(git3_trace_level_t level, git3_trace_cb cb);

/** @} */
GIT3_END_DECL

#endif
