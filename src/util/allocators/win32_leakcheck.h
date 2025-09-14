/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_allocators_win32_leakcheck_h
#define INCLUDE_allocators_win32_leakcheck_h

#include "git3_util.h"

#include "alloc.h"

int git3_win32_leakcheck_init_allocator(git3_allocator *allocator);

#endif
