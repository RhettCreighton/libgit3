/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "dir.h"

#define GIT3__WIN32_NO_WRAP_DIR
#include "posix.h"

git3__DIR *git3__opendir(const char *dir)
{
	git3_win32_path filter_w;
	git3__DIR *new = NULL;
	size_t dirlen, alloclen;

	if (!dir || !git3_win32__findfirstfile_filter(filter_w, dir))
		return NULL;

	dirlen = strlen(dir);

	if (GIT3_ADD_SIZET_OVERFLOW(&alloclen, sizeof(*new), dirlen) ||
		GIT3_ADD_SIZET_OVERFLOW(&alloclen, alloclen, 1) ||
		!(new = git3__calloc(1, alloclen)))
		return NULL;

	memcpy(new->dir, dir, dirlen);

	new->h = FindFirstFileW(filter_w, &new->f);

	if (new->h == INVALID_HANDLE_VALUE) {
		git3_error_set(GIT3_ERROR_OS, "could not open directory '%s'", dir);
		git3__free(new);
		return NULL;
	}

	new->first = 1;
	return new;
}

int git3__readdir_ext(
	git3__DIR *d,
	struct git3__dirent *entry,
	struct git3__dirent **result,
	int *is_dir)
{
	if (!d || !entry || !result || d->h == INVALID_HANDLE_VALUE)
		return -1;

	*result = NULL;

	if (d->first)
		d->first = 0;
	else if (!FindNextFileW(d->h, &d->f)) {
		if (GetLastError() == ERROR_NO_MORE_FILES)
			return 0;
		git3_error_set(GIT3_ERROR_OS, "could not read from directory '%s'", d->dir);
		return -1;
	}

	/* Convert the path to UTF-8 */
	if (git3_win32_path_to_utf8(entry->d_name, d->f.cFileName) < 0)
		return -1;

	entry->d_ino = 0;

	*result = entry;

	if (is_dir != NULL)
		*is_dir = ((d->f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0);

	return 0;
}

struct git3__dirent *git3__readdir(git3__DIR *d)
{
	struct git3__dirent *result;
	if (git3__readdir_ext(d, &d->entry, &result, NULL) < 0)
		return NULL;
	return result;
}

void git3__rewinddir(git3__DIR *d)
{
	git3_win32_path filter_w;

	if (!d)
		return;

	if (d->h != INVALID_HANDLE_VALUE) {
		FindClose(d->h);
		d->h = INVALID_HANDLE_VALUE;
		d->first = 0;
	}

	if (!git3_win32__findfirstfile_filter(filter_w, d->dir))
		return;

	d->h = FindFirstFileW(filter_w, &d->f);

	if (d->h == INVALID_HANDLE_VALUE)
		git3_error_set(GIT3_ERROR_OS, "could not open directory '%s'", d->dir);
	else
		d->first = 1;
}

int git3__closedir(git3__DIR *d)
{
	if (!d)
		return 0;

	if (d->h != INVALID_HANDLE_VALUE) {
		FindClose(d->h);
		d->h = INVALID_HANDLE_VALUE;
	}

	git3__free(d);
	return 0;
}

