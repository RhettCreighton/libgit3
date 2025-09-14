/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_diff_h__
#define INCLUDE_diff_h__

#include "common.h"

#include "git3/diff.h"
#include "git3/patch.h"
#include "git3/sys/diff.h"
#include "git3/oid.h"

#include "vector.h"
#include "iterator.h"
#include "repository.h"
#include "pool.h"
#include "odb.h"

#define DIFF_OLD_PREFIX_DEFAULT "a/"
#define DIFF_NEW_PREFIX_DEFAULT "b/"

typedef enum {
	GIT3_DIFF_TYPE_UNKNOWN = 0,
	GIT3_DIFF_TYPE_GENERATED = 1,
	GIT3_DIFF_TYPE_PARSED = 2
} git3_diff_origin_t;

struct git3_diff {
	git3_refcount      rc;
	git3_repository   *repo;
	git3_attr_session  attrsession;
	git3_diff_origin_t type;
	git3_diff_options  opts;
	git3_vector        deltas;    /* vector of git3_diff_delta */
	git3_pool pool;
	git3_iterator_t    old_src;
	git3_iterator_t    new_src;
	git3_diff_perfdata perf;

	int (*strcomp)(const char *, const char *);
	int (*strncomp)(const char *, const char *, size_t);
	int (*pfxcomp)(const char *str, const char *pfx);
	int (*entrycomp)(const void *a, const void *b);

	int (*patch_fn)(git3_patch **out, git3_diff *diff, size_t idx);
	void (*free_fn)(git3_diff *diff);
};

extern int git3_diff_delta__format_file_header(
	git3_str *out,
	const git3_diff_delta *delta,
	const char *oldpfx,
	const char *newpfx,
	int oid_strlen,
	bool print_index);

extern int git3_diff_delta__cmp(const void *a, const void *b);
extern int git3_diff_delta__casecmp(const void *a, const void *b);

extern int git3_diff__entry_cmp(const void *a, const void *b);
extern int git3_diff__entry_icmp(const void *a, const void *b);

#ifndef GIT3_EXPERIMENTAL_SHA256

int git3_diff_from_buffer_ext(
	git3_diff **out,
	const char *content,
	size_t content_len,
	git3_diff_parse_options *opts);

#endif

#endif
