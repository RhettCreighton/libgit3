/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_object_h__
#define INCLUDE_object_h__

#include "common.h"

#include "repository.h"

#define GIT3_OBJECT_SIZE_MAX UINT64_MAX

extern bool git3_object__strict_input_validation;

/** Base git object for inheritance */
struct git3_object {
	git3_cached_obj cached;
	git3_repository *repo;
};

/* fully free the object; internal method, DO NOT EXPORT */
void git3_object__free(void *object);

/*
 * Parse object from raw data. Note that the resulting object is
 * tied to the lifetime of the data, as some objects simply point
 * into it.
 */
int git3_object__from_raw(
	git3_object **object_out,
	const char *data,
	size_t size,
	git3_object_t object_type,
	git3_oid_t oid_type);

int git3_object__init_from_odb_object(
	git3_object **object_out,
	git3_repository *repo,
	git3_odb_object *odb_obj,
	git3_object_t type);

int git3_object__from_odb_object(
	git3_object **object_out,
	git3_repository *repo,
	git3_odb_object *odb_obj,
	git3_object_t type);

int git3_object__resolve_to_type(git3_object **obj, git3_object_t type);

git3_object_t git3_object_stringn2type(const char *str, size_t len);

int git3_object__parse_oid_header(
	git3_oid *oid,
	const char **buffer_out,
	const char *buffer_end,
	const char *header,
	git3_oid_t oid_type);

int git3_object__write_oid_header(
	git3_str *buf,
	const char *header,
	const git3_oid *oid);

bool git3_object__is_valid(
	git3_repository *repo, const git3_oid *id, git3_object_t expected_type);

GIT3_INLINE(git3_object_t) git3_object__type_from_filemode(git3_filemode_t mode)
{
	switch (mode) {
	case GIT3_FILEMODE_TREE:
		return GIT3_OBJECT_TREE;
	case GIT3_FILEMODE_COMMIT:
		return GIT3_OBJECT_COMMIT;
	case GIT3_FILEMODE_BLOB:
	case GIT3_FILEMODE_BLOB_EXECUTABLE:
	case GIT3_FILEMODE_LINK:
		return GIT3_OBJECT_BLOB;
	default:
		return GIT3_OBJECT_INVALID;
	}
}

#endif
