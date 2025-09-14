/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_buf_h__
#define INCLUDE_buf_h__

#include "git3/buffer.h"
#include "common.h"

/*
 * Adapts a private API that takes a `git3_str` into a public API that
 * takes a `git3_buf`.
 */

#define GIT3_BUF_WRAP_PRIVATE(buf, fn, ...) \
  { \
	git3_str str = GIT3_STR_INIT; \
	int error; \
	if ((error = git3_buf_tostr(&str, buf)) == 0 && \
	    (error = fn(&str, __VA_ARGS__)) == 0) \
		error = git3_buf_fromstr(buf, &str); \
	git3_str_dispose(&str); \
	return error; \
}

/**
 * "Sanitizes" a buffer from user input.  This simply ensures that the
 * `git3_buf` has nice defaults if the user didn't set the members to
 * anything, so that if we return early we don't leave it populated
 * with nonsense.
 */
extern int git3_buf_sanitize(git3_buf *from_user);

/**
 * Populate a `git3_str` from a `git3_buf` for passing to libgit3 internal
 * functions.  Sanitizes the given `git3_buf` before proceeding.  The
 * `git3_buf` will no longer point to this memory.
 */
extern int git3_buf_tostr(git3_str *out, git3_buf *buf);

/**
 * Populate a `git3_buf` from a `git3_str` for returning to a user.
 * The `git3_str` will no longer point to this memory.
 */
extern int git3_buf_fromstr(git3_buf *out, git3_str *str);

#endif
