/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "win32_leakcheck.h"

#if defined(GIT3_DEBUG_LEAKCHECK_WIN32)

#include "win32/w32_leakcheck.h"

static void *leakcheck_malloc(size_t len, const char *file, int line)
{
	void *ptr = _malloc_dbg(len, _NORMAL_BLOCK, git3_win32_leakcheck_stacktrace(1,file), line);
	if (!ptr) git3_error_set_oom();
	return ptr;
}

static void *leakcheck_realloc(void *ptr, size_t size, const char *file, int line)
{
	void *new_ptr = _realloc_dbg(ptr, size, _NORMAL_BLOCK, git3_win32_leakcheck_stacktrace(1,file), line);
	if (!new_ptr) git3_error_set_oom();
	return new_ptr;
}

static void leakcheck_free(void *ptr)
{
	free(ptr);
}

int git3_win32_leakcheck_init_allocator(git3_allocator *allocator)
{
	allocator->gmalloc = leakcheck_malloc;
	allocator->grealloc = leakcheck_realloc;
	allocator->gfree = leakcheck_free;
	return 0;
}

#else

int git3_win32_leakcheck_init_allocator(git3_allocator *allocator)
{
	GIT3_UNUSED(allocator);
	git3_error_set(GIT3_EINVALID, "leakcheck memory allocator not available");
	return -1;
}

#endif
