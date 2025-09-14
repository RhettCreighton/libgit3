/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_branch_h__
#define INCLUDE_branch_h__

#include "common.h"

#include "str.h"

int git3_branch__remote_name(
	git3_str *out,
	git3_repository *repo,
	const char *refname);
int git3_branch__upstream_remote(
	git3_str *out,
	git3_repository *repo,
	const char *refname);
int git3_branch__upstream_merge(
	git3_str *out,
	git3_repository *repo,
	const char *refname);
int git3_branch__upstream_name(
	git3_str *tracking_name,
	git3_repository *repo,
	const char *canonical_branch_name);

#endif
