/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_alloc_h__
#define INCLUDE_alloc_h__

#include "git3/sys/alloc.h"

#include "git3_util.h"

extern git3_allocator git3__allocator;

GIT3_INLINE(void *) git3__malloc(size_t len)
{
	void *p = git3__allocator.gmalloc(len, __FILE__, __LINE__);

	if (!p)
		git3_error_set_oom();

	return p;
}

GIT3_INLINE(void *) git3__realloc(void *ptr, size_t size)
{
	void *p = git3__allocator.grealloc(ptr, size, __FILE__, __LINE__);

	if (!p)
		git3_error_set_oom();

	return p;
}

GIT3_INLINE(void) git3__free(void *ptr)
{
	git3__allocator.gfree(ptr);
}

extern void *git3__calloc(size_t nelem, size_t elsize);
extern void *git3__mallocarray(size_t nelem, size_t elsize);
extern void *git3__reallocarray(void *ptr, size_t nelem, size_t elsize);

extern char *git3__strdup(const char *str);
extern char *git3__strndup(const char *str, size_t n);
extern char *git3__substrdup(const char *str, size_t n);

/**
 * This function is being called by our global setup routines to
 * initialize the standard allocator.
 */
int git3_allocator_global_init(void);

/**
 * Switch out libgit3's global memory allocator
 *
 * @param allocator The new allocator that should be used. All function pointers
 *                  of it need to be set correctly.
 * @return An error code or 0.
 */
int git3_allocator_setup(git3_allocator *allocator);

#endif
