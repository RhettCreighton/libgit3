/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_ignore_h__
#define INCLUDE_ignore_h__

#include "common.h"

#include "repository.h"
#include "vector.h"
#include "attr_file.h"

#define GIT3_IGNORE_FILE			".gitignore"
#define GIT3_IGNORE_FILE_INREPO	"exclude"
#define GIT3_IGNORE_FILE_XDG		"ignore"

/* The git3_ignores structure maintains three sets of ignores:
 * - internal ignores
 * - per directory ignores
 * - global ignores (at lower priority than the others)
 * As you traverse from one directory to another, you can push and pop
 * directories onto git3_ignores list efficiently.
 */
typedef struct {
	git3_repository *repo;
	git3_str dir; /* current directory reflected in ign_path */
	git3_attr_file *ign_internal;
	git3_vector ign_path;
	git3_vector ign_global;
	size_t dir_root; /* offset in dir to repo root */
	int ignore_case;
	int depth;
} git3_ignores;

extern int git3_ignore__for_path(
	git3_repository *repo, const char *path, git3_ignores *ign);

extern int git3_ignore__push_dir(git3_ignores *ign, const char *dir);

extern int git3_ignore__pop_dir(git3_ignores *ign);

extern void git3_ignore__free(git3_ignores *ign);

enum {
	GIT3_IGNORE_UNCHECKED = -2,
	GIT3_IGNORE_NOTFOUND = -1,
	GIT3_IGNORE_FALSE = 0,
	GIT3_IGNORE_TRUE = 1
};

extern int git3_ignore__lookup(int *out, git3_ignores *ign, const char *path, git3_dir_flag dir_flag);

/* command line Git sometimes generates an error message if given a
 * pathspec that contains an exact match to an ignored file (provided
 * --force isn't also given).  This makes it easy to check it that has
 * happened.  Returns GIT3_EINVALIDSPEC if the pathspec contains ignored
 * exact matches (that are not already present in the index).
 */
extern int git3_ignore__check_pathspec_for_exact_ignores(
	git3_repository *repo, git3_vector *pathspec, bool no_fnmatch);

#endif
