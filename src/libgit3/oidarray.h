/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_oidarray_h__
#define INCLUDE_oidarray_h__

#include "common.h"

#include "git3/oidarray.h"
#include "array.h"

typedef git3_array_t(git3_oid) git3_array_oid_t;

extern void git3_oidarray__reverse(git3_oidarray *arr);
extern void git3_oidarray__from_array(git3_oidarray *out, const git3_array_oid_t *array);
extern void git3_oidarray__to_array(git3_array_oid_t *out, const git3_oidarray *array);

int git3_oidarray__add(git3_array_oid_t *arr, git3_oid *id);
bool git3_oidarray__remove(git3_array_oid_t *arr, git3_oid *id);

#endif
