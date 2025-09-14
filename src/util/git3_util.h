/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git2_util_h__
#define INCLUDE_git2_util_h__

#if !defined(LIBGIT3_NO_FEATURES_H)
# include "git3_features.h"
#endif

#include "git3/common.h"
#include "git3/sys/errors.h"
#include "cc-compat.h"

typedef struct git3_str git3_str;

/** Declare a function as always inlined. */
#if defined(_MSC_VER)
# define GIT3_INLINE(type) static __inline type
#elif defined(__GNUC__)
# define GIT3_INLINE(type) static __inline__ type
#else
# define GIT3_INLINE(type) static type
#endif

/** Support for gcc/clang __has_builtin intrinsic */
#ifndef __has_builtin
# define __has_builtin(x) 0
#endif

/**
 * Declare that a function's return value must be used.
 *
 * Used mostly to guard against potential silent bugs at runtime. This is
 * recommended to be added to functions that:
 *
 * - Allocate / reallocate memory. This prevents memory leaks or errors where
 *   buffers are expected to have grown to a certain size, but could not be
 *   resized.
 * - Acquire locks. When a lock cannot be acquired, that will almost certainly
 *   cause a data race / undefined behavior.
 */
#if defined(__GNUC__)
# define GIT3_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
# define GIT3_WARN_UNUSED_RESULT
#endif

#if (defined(_WIN32)) && !defined(__CYGWIN__)
# define GIT3_WIN32 1
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef GIT3_WIN32

# include <io.h>
# include <direct.h>
# include <winsock2.h>
# include <windows.h>
# include <ws2tcpip.h>
# include "win32/msvc-compat.h"
# include "win32/mingw-compat.h"
# include "win32/win32-compat.h"
# include "win32/w32_common.h"
# include "win32/version.h"
# include "win32/error.h"
# ifdef GIT3_THREADS
#  include "win32/thread.h"
# endif

#else

# include <unistd.h>
# include <strings.h>
# ifdef GIT3_THREADS
#	include <pthread.h>
#	include <sched.h>
# endif

#define GIT3_LIBGIT3_CALL
#define GIT3_SYSTEM_CALL

#ifdef GIT3_USE_STAT_ATIMESPEC
# define st_atim st_atimespec
# define st_ctim st_ctimespec
# define st_mtim st_mtimespec
#endif

# include <arpa/inet.h>

#endif

#include "git3/types.h"
#include "git3/errors.h"
#include "thread.h"
#include "integer.h"
#include "assert_safe.h"

#include "posix.h"

#define GIT3_BUFSIZE_DEFAULT 65536
#define GIT3_BUFSIZE_FILEIO GIT3_BUFSIZE_DEFAULT
#define GIT3_BUFSIZE_FILTERIO GIT3_BUFSIZE_DEFAULT
#define GIT3_BUFSIZE_NETIO GIT3_BUFSIZE_DEFAULT


/**
 * Check a pointer allocation result, returning -1 if it failed.
 */
#define GIT3_ERROR_CHECK_ALLOC(ptr) do { \
	if ((ptr) == NULL) { return -1; } \
	} while(0)

/**
 * Check a buffer allocation result, returning -1 if it failed.
 */
#define GIT3_ERROR_CHECK_ALLOC_STR(buf) do { \
	if ((void *)(buf) == NULL || git3_str_oom(buf)) { return -1; } \
	} while(0)

/**
 * Check a return value and propagate result if non-zero.
 */
#define GIT3_ERROR_CHECK_ERROR(code) \
	do { int _err = (code); if (_err) return _err; } while (0)


/** Check for additive overflow, setting an error if would occur. */
#define GIT3_ADD_SIZET_OVERFLOW(out, one, two) \
	(git3__add_sizet_overflow(out, one, two) ? (git3_error_set_oom(), 1) : 0)

/** Check for additive overflow, setting an error if would occur. */
#define GIT3_MULTIPLY_SIZET_OVERFLOW(out, nelem, elsize) \
	(git3__multiply_sizet_overflow(out, nelem, elsize) ? (git3_error_set_oom(), 1) : 0)

/** Check for additive overflow, failing if it would occur. */
#define GIT3_ERROR_CHECK_ALLOC_ADD(out, one, two) \
	if (GIT3_ADD_SIZET_OVERFLOW(out, one, two)) { return -1; }

#define GIT3_ERROR_CHECK_ALLOC_ADD3(out, one, two, three) \
	if (GIT3_ADD_SIZET_OVERFLOW(out, one, two) || \
		GIT3_ADD_SIZET_OVERFLOW(out, *(out), three)) { return -1; }

#define GIT3_ERROR_CHECK_ALLOC_ADD4(out, one, two, three, four) \
	if (GIT3_ADD_SIZET_OVERFLOW(out, one, two) || \
		GIT3_ADD_SIZET_OVERFLOW(out, *(out), three) || \
		GIT3_ADD_SIZET_OVERFLOW(out, *(out), four)) { return -1; }

#define GIT3_ERROR_CHECK_ALLOC_ADD5(out, one, two, three, four, five) \
	if (GIT3_ADD_SIZET_OVERFLOW(out, one, two) || \
		GIT3_ADD_SIZET_OVERFLOW(out, *(out), three) || \
		GIT3_ADD_SIZET_OVERFLOW(out, *(out), four) || \
		GIT3_ADD_SIZET_OVERFLOW(out, *(out), five)) { return -1; }

/** Check for multiplicative overflow, failing if it would occur. */
#define GIT3_ERROR_CHECK_ALLOC_MULTIPLY(out, nelem, elsize) \
	if (GIT3_MULTIPLY_SIZET_OVERFLOW(out, nelem, elsize)) { return -1; }

#include "util.h"
#include "ctype_compat.h"

#endif
