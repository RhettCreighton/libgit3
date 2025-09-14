/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

/*
 * This file provides the necessary indirection between xdiff and
 * libgit3.  libgit3-specific functionality should live here, so
 * that git and libgit3 can share a common xdiff implementation.
 */

#ifndef INCLUDE_git_xdiff_h__
#define INCLUDE_git_xdiff_h__

#include "regexp.h"

/* Work around C90-conformance issues */
#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
# if defined(_MSC_VER)
#  define inline __inline
# elif defined(__GNUC__)
#  define inline __inline__
# else
#  define inline
# endif
#endif

#define XDL_UNUSED GIT3_UNUSED_ARG

#define xdl_malloc(x) git3__malloc(x)
#define xdl_calloc(n, sz) git3__calloc(n, sz)
#define xdl_free(ptr) git3__free(ptr)
#define xdl_realloc(ptr, x) git3__realloc(ptr, x)

#define XDL_BUG(msg) GIT3_ASSERT(!msg)

#define xdl_regex_t git3_regexp
#define xdl_regmatch_t git3_regmatch

GIT3_INLINE(int) xdl_regexec_buf(
	const xdl_regex_t *preg, const char *buf, size_t size,
	size_t nmatch, xdl_regmatch_t pmatch[], int eflags)
{
	GIT3_UNUSED(preg);
	GIT3_UNUSED(buf);
	GIT3_UNUSED(size);
	GIT3_UNUSED(nmatch);
	GIT3_UNUSED(pmatch);
	GIT3_UNUSED(eflags);
	GIT3_ASSERT("not implemented");
	return -1;
}

#endif
