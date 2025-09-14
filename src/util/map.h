/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_map_h__
#define INCLUDE_map_h__

#include "git3_util.h"


/* p_mmap() prot values */
#define GIT3_PROT_NONE 0x0
#define GIT3_PROT_READ 0x1
#define GIT3_PROT_WRITE 0x2
#define GIT3_PROT_EXEC 0x4

/* git3__mmmap() flags values */
#define GIT3_MAP_FILE	0
#define GIT3_MAP_SHARED 1
#define GIT3_MAP_PRIVATE 2
#define GIT3_MAP_TYPE	0xf
#define GIT3_MAP_FIXED	0x10

#ifdef __amigaos4__
#define MAP_FAILED 0
#endif

typedef struct { /* memory mapped buffer	*/
	void *data; /* data bytes			*/
	size_t len; /* data length			*/
#ifdef GIT3_WIN32
	HANDLE fmh; /* file mapping handle */
#endif
} git3_map;

#define GIT3_MMAP_VALIDATE(out, len, prot, flags) do { \
	GIT3_ASSERT(out != NULL && len > 0); \
	GIT3_ASSERT((prot & GIT3_PROT_WRITE) || (prot & GIT3_PROT_READ)); \
	GIT3_ASSERT((flags & GIT3_MAP_FIXED) == 0); } while (0)

extern int p_mmap(git3_map *out, size_t len, int prot, int flags, int fd, off64_t offset);
extern int p_munmap(git3_map *map);

#endif
