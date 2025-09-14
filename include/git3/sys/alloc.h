/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_sys_git_alloc_h__
#define INCLUDE_sys_git_alloc_h__

#include "git3/common.h"

/**
 * @file git3/sys/alloc.h
 * @brief Custom memory allocators
 * @defgroup git3_merge Git merge routines
 * @ingroup Git
 *
 * Users can configure custom allocators; this is particularly
 * interesting when running in constrained environments, when calling
 * from another language, or during testing.
 * @{
 */
GIT3_BEGIN_DECL

/**
 * An instance for a custom memory allocator
 *
 * Setting the pointers of this structure allows the developer to implement
 * custom memory allocators. The global memory allocator can be set by using
 * "GIT3_OPT_SET_ALLOCATOR" with the `git3_libgit3_opts` function. Keep in mind
 * that all fields need to be set to a proper function.
 */
typedef struct {
	/** Allocate `n` bytes of memory */
	void * GIT3_CALLBACK(gmalloc)(size_t n, const char *file, int line);

	/**
	 * This function shall deallocate the old object `ptr` and return a
	 * pointer to a new object that has the size specified by `size`. In
	 * case `ptr` is `NULL`, a new array shall be allocated.
	 */
	void * GIT3_CALLBACK(grealloc)(void *ptr, size_t size, const char *file, int line);

	/**
	 * This function shall free the memory pointed to by `ptr`. In case
	 * `ptr` is `NULL`, this shall be a no-op.
	 */
	void GIT3_CALLBACK(gfree)(void *ptr);
} git3_allocator;

/**
 * Initialize the allocator structure to use the `stdalloc` pointer.
 *
 * Set up the structure so that all of its members are using the standard
 * "stdalloc" allocator functions. The structure can then be used with
 * `git3_allocator_setup`.
 *
 * @param allocator The allocator that is to be initialized.
 * @return An error code or 0.
 */
int git3_stdalloc_init_allocator(git3_allocator *allocator);

/**
 * Initialize the allocator structure to use the `crtdbg` pointer.
 *
 * Set up the structure so that all of its members are using the "crtdbg"
 * allocator functions. Note that this allocator is only available on Windows
 * platforms and only if libgit3 is being compiled with "-DMSVC_CRTDBG".
 *
 * @param allocator The allocator that is to be initialized.
 * @return An error code or 0.
 */
int git3_win32_crtdbg_init_allocator(git3_allocator *allocator);

/** @} */
GIT3_END_DECL

#endif
