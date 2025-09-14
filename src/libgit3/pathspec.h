/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_pathspec_h__
#define INCLUDE_pathspec_h__

#include "common.h"

#include "git3/pathspec.h"
#include "str.h"
#include "vector.h"
#include "pool.h"
#include "array.h"

/* public compiled pathspec */
struct git3_pathspec {
	git3_refcount rc;
	char *prefix;
	git3_vector pathspec;
	git3_pool pool;
};

enum {
	PATHSPEC_DATATYPE_STRINGS = 0,
	PATHSPEC_DATATYPE_DIFF = 1
};

typedef git3_array_t(char *) git3_pathspec_string_array_t;

/* public interface to pathspec matching */
struct git3_pathspec_match_list {
	git3_pathspec *pathspec;
	git3_array_t(void *) matches;
	git3_pathspec_string_array_t failures;
	git3_pool pool;
	int datatype;
};

/* what is the common non-wildcard prefix for all items in the pathspec */
extern char *git3_pathspec_prefix(const git3_strarray *pathspec);

/* is there anything in the spec that needs to be filtered on */
extern bool git3_pathspec_is_empty(const git3_strarray *pathspec);

/* build a vector of fnmatch patterns to evaluate efficiently */
extern int git3_pathspec__vinit(
	git3_vector *vspec, const git3_strarray *strspec, git3_pool *strpool);

/* free data from the pathspec vector */
extern void git3_pathspec__vfree(git3_vector *vspec);

#define GIT3_PATHSPEC_NOMATCH ((size_t)-1)

/*
 * Match a path against the vectorized pathspec.
 * The matched pathspec is passed back into the `matched_pathspec` parameter,
 * unless it is passed as NULL by the caller.
 */
extern bool git3_pathspec__match(
	const git3_vector *vspec,
	const char *path,
	bool disable_fnmatch,
	bool casefold,
	const char **matched_pathspec,
	size_t *matched_at);

/* easy pathspec setup */

extern int git3_pathspec__init(git3_pathspec *ps, const git3_strarray *paths);

extern void git3_pathspec__clear(git3_pathspec *ps);

#endif
