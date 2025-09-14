/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_fetchhead_h__
#define INCLUDE_fetchhead_h__

#include "common.h"

#include "oid.h"
#include "vector.h"

typedef struct git3_fetchhead_ref {
	git3_oid oid;
	unsigned int is_merge;
	char *ref_name;
	char *remote_url;
} git3_fetchhead_ref;

int git3_fetchhead_ref_create(
	git3_fetchhead_ref **fetchhead_ref_out,
	git3_oid *oid,
	unsigned int is_merge,
	const char *ref_name,
	const char *remote_url);

int git3_fetchhead_ref_cmp(const void *a, const void *b);

int git3_fetchhead_write(git3_repository *repo, git3_vector *fetchhead_refs);

void git3_fetchhead_ref_free(git3_fetchhead_ref *fetchhead_ref);

#endif
