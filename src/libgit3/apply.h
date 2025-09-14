/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_apply_h__
#define INCLUDE_apply_h__

#include "common.h"

#include "git3/patch.h"
#include "git3/apply.h"
#include "str.h"

extern int git3_apply__patch(
	git3_str *out,
	char **filename,
	unsigned int *mode,
	const char *source,
	size_t source_len,
	git3_patch *patch,
	const git3_apply_options *opts);

#endif
