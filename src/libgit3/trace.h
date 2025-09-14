/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_trace_h__
#define INCLUDE_trace_h__

#include "common.h"

#include <git3/trace.h>
#include "str.h"

struct git3_trace_data {
	git3_trace_level_t level;
	git3_trace_cb callback;
};

extern struct git3_trace_data git3_trace__data;

GIT3_INLINE(void) git3_trace__write_fmt(
	git3_trace_level_t level,
	const char *fmt,
	va_list ap)
{
	git3_trace_cb callback = git3_trace__data.callback;
	git3_str message = GIT3_STR_INIT;

	git3_str_vprintf(&message, fmt, ap);

	callback(level, git3_str_cstr(&message));

	git3_str_dispose(&message);
}

#define git3_trace_level()	(git3_trace__data.level)

GIT3_INLINE(void) git3_trace(git3_trace_level_t level, const char *fmt, ...)
{
	if (git3_trace__data.level >= level &&
	    git3_trace__data.callback != NULL) {
		va_list ap;

		va_start(ap, fmt);
		git3_trace__write_fmt(level, fmt, ap);
		va_end(ap);
	}
}

#endif
