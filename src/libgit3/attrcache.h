/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_attrcache_h__
#define INCLUDE_attrcache_h__

#include "common.h"

#include "attr_file.h"

#define GIT3_ATTR_CONFIG       "core.attributesfile"
#define GIT3_IGNORE_CONFIG     "core.excludesfile"

typedef struct git3_attr_cache git3_attr_cache;

extern int git3_attr_cache__init(git3_repository *repo);

extern const char *git3_attr_cache_attributesfile(git3_attr_cache *ac);
extern const char *git3_attr_cache_excludesfile(git3_attr_cache *ac);
extern git3_pool *git3_attr_cache_pool(git3_attr_cache *ac);

/* get file - loading and reload as needed */
extern int git3_attr_cache__get(
	git3_attr_file **file,
	git3_repository *repo,
	git3_attr_session *attr_session,
	git3_attr_file_source *source,
	git3_attr_file_parser parser,
	bool allow_macros);

extern bool git3_attr_cache__is_cached(
	git3_repository *repo,
	git3_attr_file_source_t source_type,
	const char *filename);

extern int git3_attr_cache__alloc_file_entry(
	git3_attr_file_entry **out,
	git3_repository *repo,
	const char *base,
	const char *path,
	git3_pool *pool);

extern int git3_attr_cache__insert_macro(
	git3_repository *repo, git3_attr_rule *macro);

extern git3_attr_rule *git3_attr_cache__lookup_macro(
	git3_repository *repo, const char *name);

#endif
