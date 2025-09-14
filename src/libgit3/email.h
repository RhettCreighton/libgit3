/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_email_h__
#define INCLUDE_email_h__

#include "common.h"

#include "git3/email.h"

extern int git3_email__append_from_diff(
	git3_str *out,
	git3_diff *diff,
	size_t patch_idx,
	size_t patch_count,
	const git3_oid *commit_id,
	const char *summary,
	const char *body,
	const git3_signature *author,
	const git3_email_create_options *given_opts);

#endif
