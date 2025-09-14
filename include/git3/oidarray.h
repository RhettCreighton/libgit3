/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_oidarray_h__
#define INCLUDE_git_oidarray_h__

#include "common.h"
#include "oid.h"

/**
 * @file git3/oidarray.h
 * @brief An array of object IDs
 * @defgroup git3_oidarray Arrays of object IDs
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/** Array of object ids */
typedef struct git3_oidarray {
	git3_oid *ids;
	size_t count;
} git3_oidarray;

/**
 * Free the object IDs contained in an oid_array.  This method should
 * be called on `git3_oidarray` objects that were provided by the
 * library.  Not doing so will result in a memory leak.
 *
 * This does not free the `git3_oidarray` itself, since the library will
 * never allocate that object directly itself.
 *
 * @param array git3_oidarray from which to free oid data
 */
GIT3_EXTERN(void) git3_oidarray_dispose(git3_oidarray *array);

/** @} */
GIT3_END_DECL

#endif
