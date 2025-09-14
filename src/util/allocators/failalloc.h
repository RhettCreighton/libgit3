/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_allocators_failalloc_h__
#define INCLUDE_allocators_failalloc_h__

#include "git3_util.h"

extern void *git3_failalloc_malloc(size_t len, const char *file, int line);
extern void *git3_failalloc_realloc(void *ptr, size_t size, const char *file, int line);
extern void git3_failalloc_free(void *ptr);

#endif
