/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_pool_h__
#define INCLUDE_pool_h__

#include "git3_util.h"

#include "vector.h"

typedef struct git3_pool_page git3_pool_page;

#ifndef GIT3_DEBUG_POOL
/**
 * Chunked allocator.
 *
 * A `git3_pool` can be used when you want to cheaply allocate
 * multiple items of the same type and are willing to free them
 * all together with a single call.  The two most common cases
 * are a set of fixed size items (such as lots of OIDs) or a
 * bunch of strings.
 *
 * Internally, a `git3_pool` allocates pages of memory and then
 * deals out blocks from the trailing unused portion of each page.
 * The pages guarantee that the number of actual allocations done
 * will be much smaller than the number of items needed.
 *
 * For examples of how to set up a `git3_pool` see `git3_pool_init`.
 */
typedef struct {
	git3_pool_page *pages; /* allocated pages */
	size_t item_size;  /* size of single alloc unit in bytes */
	size_t page_size;  /* size of page in bytes */
} git3_pool;

#define GIT3_POOL_INIT { NULL, 0, 0 }

#else

/**
 * Debug chunked allocator.
 *
 * Acts just like `git3_pool` but instead of actually pooling allocations it
 * passes them through to `git3__malloc`. This makes it possible to easily debug
 * systems that use `git3_pool` using valgrind.
 *
 * In order to track allocations during the lifetime of the pool we use a
 * `git3_vector`. When the pool is deallocated everything in the vector is
 * freed.
 *
 * `API is exactly the same as the standard `git3_pool` with one exception.
 * Since we aren't allocating pages to hand out in chunks we can't easily
 * implement `git3_pool__open_pages`.
 */
typedef struct {
	git3_vector allocations;
	size_t item_size;
	size_t page_size;
} git3_pool;

#define GIT3_POOL_INIT { GIT3_VECTOR_INIT, 0, 0 }

#endif

/**
 * Initialize a pool.
 *
 * To allocation strings, use like this:
 *
 *     git3_pool_init(&string_pool, 1);
 *     my_string = git3_pool_strdup(&string_pool, your_string);
 *
 * To allocate items of fixed size, use like this:
 *
 *     git3_pool_init(&pool, sizeof(item));
 *     my_item = git3_pool_malloc(&pool, 1);
 *
 * Of course, you can use this in other ways, but those are the
 * two most common patterns.
 */
extern int git3_pool_init(git3_pool *pool, size_t item_size);

GIT3_INLINE(bool) git3_pool_is_initialized(git3_pool *pool)
{
	return (pool->item_size > 0);
}

/**
 * Free all items in pool
 */
extern void git3_pool_clear(git3_pool *pool);

/**
 * Swap two pools with one another
 */
extern void git3_pool_swap(git3_pool *a, git3_pool *b);

/**
 * Allocate space for one or more items from a pool.
 */
extern void *git3_pool_malloc(git3_pool *pool, size_t items);
extern void *git3_pool_mallocz(git3_pool *pool, size_t items);

/**
 * Allocate space and duplicate string data into it.
 *
 * This is allowed only for pools with item_size == sizeof(char)
 */
extern char *git3_pool_strndup(git3_pool *pool, const char *str, size_t n);

/**
 * Allocate space and duplicate a string into it.
 *
 * This is allowed only for pools with item_size == sizeof(char)
 */
extern char *git3_pool_strdup(git3_pool *pool, const char *str);

/**
 * Allocate space and duplicate a string into it, NULL is no error.
 *
 * This is allowed only for pools with item_size == sizeof(char)
 */
extern char *git3_pool_strdup_safe(git3_pool *pool, const char *str);

/**
 * Allocate space for the concatenation of two strings.
 *
 * This is allowed only for pools with item_size == sizeof(char)
 */
extern char *git3_pool_strcat(git3_pool *pool, const char *a, const char *b);

/*
 * Misc utilities
 */
#ifndef GIT3_DEBUG_POOL
extern uint32_t git3_pool__open_pages(git3_pool *pool);
#endif
extern bool git3_pool__ptr_in_pool(git3_pool *pool, void *ptr);

/**
 * This function is being called by our global setup routines to
 * initialize the system pool size.
 *
 * @return 0 on success, <0 on failure
 */
extern int git3_pool_global_init(void);

#endif
