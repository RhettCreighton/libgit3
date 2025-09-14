/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "oidarray.h"

#include "git3/oidarray.h"
#include "array.h"

void git3_oidarray_dispose(git3_oidarray *arr)
{
	git3__free(arr->ids);
}

void git3_oidarray__from_array(git3_oidarray *out, const git3_array_oid_t *array)
{
	out->count = array->size;
	out->ids = array->ptr;
}

void git3_oidarray__to_array(git3_array_oid_t *out, const git3_oidarray *array)
{
	out->ptr = array->ids;
	out->size = array->count;
	out->asize = array->count;
}

void git3_oidarray__reverse(git3_oidarray *arr)
{
	size_t i;
	git3_oid tmp;

	for (i = 0; i < arr->count / 2; i++) {
		git3_oid_cpy(&tmp, &arr->ids[i]);
		git3_oid_cpy(&arr->ids[i], &arr->ids[(arr->count-1)-i]);
		git3_oid_cpy(&arr->ids[(arr->count-1)-i], &tmp);
	}
}

int git3_oidarray__add(git3_array_oid_t *arr, git3_oid *id)
{
	git3_oid *add, *iter;
	size_t i;

	git3_array_foreach(*arr, i, iter) {
		if (git3_oid_cmp(iter, id) == 0)
			return 0;
	}

	if ((add = git3_array_alloc(*arr)) == NULL)
		return -1;

	git3_oid_cpy(add, id);
	return 0;
}

bool git3_oidarray__remove(git3_array_oid_t *arr, git3_oid *id)
{
	bool found = false;
	size_t remain, i;
	git3_oid *iter;

	git3_array_foreach(*arr, i, iter) {
		if (git3_oid_cmp(iter, id) == 0) {
			arr->size--;
			remain = arr->size - i;

			if (remain > 0)
				memmove(&arr->ptr[i], &arr->ptr[i+1], remain * sizeof(git3_oid));

			found = true;
			break;
		}
	}

	return found;
}

#ifndef GIT3_DEPRECATE_HARD

void git3_oidarray_free(git3_oidarray *arr)
{
	git3_oidarray_dispose(arr);
}

#endif
