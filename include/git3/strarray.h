/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_strarray_h__
#define INCLUDE_git_strarray_h__

#include "common.h"

/**
 * @file git3/strarray.h
 * @brief An array of strings for the user to free
 * @defgroup git3_strarray An array of strings for the user to free
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/** Array of strings */
typedef struct git3_strarray {
	char **strings;
	size_t count;
} git3_strarray;

/**
 * Free the strings contained in a string array.  This method should
 * be called on `git3_strarray` objects that were provided by the
 * library.  Not doing so, will result in a memory leak.
 *
 * This does not free the `git3_strarray` itself, since the library will
 * never allocate that object directly itself.
 *
 * @param array The git3_strarray that contains strings to free
 */
GIT3_EXTERN(void) git3_strarray_dispose(git3_strarray *array);

/** @} */
GIT3_END_DECL

#endif
