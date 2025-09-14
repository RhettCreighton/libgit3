/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_blob_h__
#define INCLUDE_blob_h__

#include "common.h"

#include "git3/blob.h"
#include "repository.h"
#include "odb.h"
#include "futils.h"

struct git3_blob {
	git3_object object;

	union {
		git3_odb_object *odb;
		struct {
			const char *data;
			git3_object_size_t size;
		} raw;
	} data;
	unsigned int raw:1;
};

#define GIT3_ERROR_CHECK_BLOBSIZE(n) \
	do { \
		if (!git3__is_sizet(n)) { \
			git3_error_set(GIT3_ERROR_NOMEMORY, "blob contents too large to fit in memory"); \
			return -1; \
		} \
	} while(0)

void git3_blob__free(void *blob);
int git3_blob__parse(void *blob, git3_odb_object *obj, git3_oid_t oid_type);
int git3_blob__parse_raw(void *blob, const char *data, size_t size, git3_oid_t oid_type);
int git3_blob__getbuf(git3_str *buffer, git3_blob *blob);

extern int git3_blob__create_from_paths(
	git3_oid *out_oid,
	struct stat *out_st,
	git3_repository *repo,
	const char *full_path,
	const char *hint_path,
	mode_t hint_mode,
	bool apply_filters);

#endif
