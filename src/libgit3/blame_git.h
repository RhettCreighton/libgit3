/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_blame_git__
#define INCLUDE_blame_git__

#include "common.h"

#include "blame.h"

int git3_blame__get_origin(
		git3_blame__origin **out,
		git3_blame *sb,
		git3_commit *commit,
		const char *path);
void git3_blame__free_entry(git3_blame__entry *ent);
int git3_blame__like_git(git3_blame *sb, uint32_t flags);

#endif
