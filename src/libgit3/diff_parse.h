/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_diff_parse_h__
#define INCLUDE_diff_parse_h__

#include "common.h"

#include "diff.h"

typedef struct {
	struct git3_diff base;

	git3_vector patches;
} git3_diff_parsed;

#endif
