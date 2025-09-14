/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_diff_stats_h__
#define INCLUDE_diff_stats_h__

#include "common.h"

int git3_diff__stats_to_buf(
	git3_str *out,
	const git3_diff_stats *stats,
	git3_diff_stats_format_t format,
	size_t width);

#endif
