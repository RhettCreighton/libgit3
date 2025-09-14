/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git3_util.h"

#if !defined(GIT3_WIN32) && !defined(NO_MMAP)

#include "map.h"
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

int git3__page_size(size_t *page_size)
{
	long sc_page_size = sysconf(_SC_PAGE_SIZE);
	if (sc_page_size < 0) {
		git3_error_set(GIT3_ERROR_OS, "can't determine system page size");
		return -1;
	}
	*page_size = (size_t) sc_page_size;
	return 0;
}

int git3__mmap_alignment(size_t *alignment)
{
  return git3__page_size(alignment);
}

int p_mmap(git3_map *out, size_t len, int prot, int flags, int fd, off64_t offset)
{
	int mprot = PROT_READ;
	int mflag = 0;

	GIT3_MMAP_VALIDATE(out, len, prot, flags);

	out->data = NULL;
	out->len = 0;

	if (prot & GIT3_PROT_WRITE)
		mprot |= PROT_WRITE;

	if ((flags & GIT3_MAP_TYPE) == GIT3_MAP_SHARED)
		mflag = MAP_SHARED;
	else if ((flags & GIT3_MAP_TYPE) == GIT3_MAP_PRIVATE)
		mflag = MAP_PRIVATE;
	else
		mflag = MAP_SHARED;

	out->data = mmap(NULL, len, mprot, mflag, fd, offset);

	if (!out->data || out->data == MAP_FAILED) {
		git3_error_set(GIT3_ERROR_OS, "failed to mmap. Could not write data");
		return -1;
	}

	out->len = len;

	return 0;
}

int p_munmap(git3_map *map)
{
	GIT3_ASSERT_ARG(map);
	munmap(map->data, map->len);
	map->data = NULL;
	map->len = 0;

	return 0;
}

#endif

