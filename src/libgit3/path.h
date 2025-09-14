/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_path_h__
#define INCLUDE_path_h__

#include "common.h"

#include "fs_path.h"
#include <git3/sys/path.h>

#define GIT3_PATH_REJECT_DOT_GIT            (GIT3_FS_PATH_REJECT_MAX << 1)
#define GIT3_PATH_REJECT_DOT_GIT3_LITERAL    (GIT3_FS_PATH_REJECT_MAX << 2)
#define GIT3_PATH_REJECT_DOT_GIT3_HFS        (GIT3_FS_PATH_REJECT_MAX << 3)
#define GIT3_PATH_REJECT_DOT_GIT3_NTFS       (GIT3_FS_PATH_REJECT_MAX << 4)

/* Paths that should never be written into the working directory. */
#define GIT3_PATH_REJECT_WORKDIR_DEFAULTS \
	GIT3_FS_PATH_REJECT_FILESYSTEM_DEFAULTS | GIT3_PATH_REJECT_DOT_GIT

/* Paths that should never be written to the index. */
#define GIT3_PATH_REJECT_INDEX_DEFAULTS \
	GIT3_FS_PATH_REJECT_TRAVERSAL | GIT3_PATH_REJECT_DOT_GIT

extern bool git3_path_str_is_valid(
	git3_repository *repo,
	const git3_str *path,
	uint16_t file_mode,
	unsigned int flags);

GIT3_INLINE(bool) git3_path_is_valid(
	git3_repository *repo,
	const char *path,
	uint16_t file_mode,
	unsigned int flags)
{
	git3_str str = GIT3_STR_INIT_CONST(path, SIZE_MAX);
	return git3_path_str_is_valid(repo, &str, file_mode, flags);
}

GIT3_INLINE(int) git3_path_validate_str_length(
	git3_repository *repo,
	const git3_str *path)
{
	if (!git3_path_str_is_valid(repo, path, 0, GIT3_FS_PATH_REJECT_LONG_PATHS)) {
		if (path->size == SIZE_MAX)
			git3_error_set(GIT3_ERROR_FILESYSTEM, "path too long: '%s'", path->ptr);
		else
			git3_error_set(GIT3_ERROR_FILESYSTEM, "path too long: '%.*s'", (int)path->size, path->ptr);

		return -1;
	}

	return 0;
}

GIT3_INLINE(int) git3_path_validate_length(
	git3_repository *repo,
	const char *path)
{
	git3_str str = GIT3_STR_INIT_CONST(path, SIZE_MAX);
	return git3_path_validate_str_length(repo, &str);
}

#endif
