/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "alloc.h"
#include "runtime.h"

#include "allocators/stdalloc.h"
#include "allocators/debugalloc.h"
#include "allocators/failalloc.h"
#include "allocators/win32_leakcheck.h"

/* Fail any allocation until git3_libgit3_init is called. */
git3_allocator git3__allocator = {
	git3_failalloc_malloc,
	git3_failalloc_realloc,
	git3_failalloc_free
};

void *git3__calloc(size_t nelem, size_t elsize)
{
	size_t newsize;
	void *ptr;

	if (GIT3_MULTIPLY_SIZET_OVERFLOW(&newsize, nelem, elsize))
		return NULL;

	if ((ptr = git3__malloc(newsize)))
		memset(ptr, 0, newsize);

	return ptr;
}

void *git3__reallocarray(void *ptr, size_t nelem, size_t elsize)
{
	size_t newsize;

	if (GIT3_MULTIPLY_SIZET_OVERFLOW(&newsize, nelem, elsize))
		return NULL;

	return git3__realloc(ptr, newsize);
}

void *git3__mallocarray(size_t nelem, size_t elsize)
{
	return git3__reallocarray(NULL, nelem, elsize);
}

char *git3__strdup(const char *str)
{
	size_t len = strlen(str) + 1;
	void *ptr = git3__malloc(len);

	if (ptr)
		memcpy(ptr, str, len);

	return ptr;
}

char *git3__strndup(const char *str, size_t n)
{
	size_t len = p_strnlen(str, n);
	char *ptr = git3__malloc(len + 1);

	if (ptr) {
		memcpy(ptr, str, len);
		ptr[len] = '\0';
	}

	return ptr;
}

char *git3__substrdup(const char *str, size_t n)
{
	char *ptr = git3__malloc(n + 1);

	if (ptr) {
		memcpy(ptr, str, n);
		ptr[n] = '\0';
	}

	return ptr;
}

static int setup_default_allocator(void)
{
#if defined(GIT3_DEBUG_LEAKCHECK_WIN32)
	return git3_win32_leakcheck_init_allocator(&git3__allocator);
#elif defined(GIT3_DEBUG_STRICT_ALLOC)
	return git3_debugalloc_init_allocator(&git3__allocator);
#else
	return git3_stdalloc_init_allocator(&git3__allocator);
#endif
}

int git3_allocator_global_init(void)
{
	/*
	 * We don't want to overwrite any allocator which has been set
	 * before the init function is called.
	 */
	if (git3__allocator.gmalloc != git3_failalloc_malloc)
		return 0;

	return setup_default_allocator();
}

int git3_allocator_setup(git3_allocator *allocator)
{
	if (!allocator)
		return setup_default_allocator();

	memcpy(&git3__allocator, allocator, sizeof(*allocator));
	return 0;
}
