/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "failalloc.h"

void *git3_failalloc_malloc(size_t len, const char *file, int line)
{
	GIT3_UNUSED(len);
	GIT3_UNUSED(file);
	GIT3_UNUSED(line);

	return NULL;
}

void *git3_failalloc_realloc(void *ptr, size_t size, const char *file, int line)
{
	GIT3_UNUSED(ptr);
	GIT3_UNUSED(size);
	GIT3_UNUSED(file);
	GIT3_UNUSED(line);

	return NULL;
}

void git3_failalloc_free(void *ptr)
{
	GIT3_UNUSED(ptr);
}
