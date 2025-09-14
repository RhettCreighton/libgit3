/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "util.h"

#include "common.h"
#include "strarray.h"

int git3_strarray_copy(git3_strarray *tgt, const git3_strarray *src)
{
	size_t i;

	GIT3_ASSERT_ARG(tgt);
	GIT3_ASSERT_ARG(src);

	memset(tgt, 0, sizeof(*tgt));

	if (!src->count)
		return 0;

	tgt->strings = git3__calloc(src->count, sizeof(char *));
	GIT3_ERROR_CHECK_ALLOC(tgt->strings);

	for (i = 0; i < src->count; ++i) {
		if (!src->strings[i])
			continue;

		tgt->strings[tgt->count] = git3__strdup(src->strings[i]);
		if (!tgt->strings[tgt->count]) {
			git3_strarray_dispose(tgt);
			memset(tgt, 0, sizeof(*tgt));
			return -1;
		}

		tgt->count++;
	}

	return 0;
}

void git3_strarray_dispose(git3_strarray *array)
{
	size_t i;

	if (array == NULL)
		return;

	for (i = 0; i < array->count; ++i)
		git3__free(array->strings[i]);

	git3__free(array->strings);

	memset(array, 0, sizeof(*array));
}

#ifndef GIT3_DEPRECATE_HARD
void git3_strarray_free(git3_strarray *array)
{
	git3_strarray_dispose(array);
}
#endif
