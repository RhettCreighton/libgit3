/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_filebuf_h__
#define INCLUDE_filebuf_h__

#include "git3_util.h"

#include "futils.h"
#include "hash.h"
#include <zlib.h>

#ifdef GIT3_THREADS
#	define GIT3_FILEBUF_THREADS
#endif

#define GIT3_FILEBUF_HASH_SHA1           (1 << 0)
#define GIT3_FILEBUF_HASH_SHA256         (1 << 1)
#define GIT3_FILEBUF_APPEND              (1 << 2)
#define GIT3_FILEBUF_CREATE_LEADING_DIRS	(1 << 3)
#define GIT3_FILEBUF_TEMPORARY           (1 << 4)
#define GIT3_FILEBUF_DO_NOT_BUFFER       (1 << 5)
#define GIT3_FILEBUF_FSYNC               (1 << 6)
#define GIT3_FILEBUF_DEFLATE_SHIFT       (7)

#define GIT3_FILELOCK_EXTENSION ".lock\0"
#define GIT3_FILELOCK_EXTLENGTH 6

typedef struct git3_filebuf git3_filebuf;
struct git3_filebuf {
	char *path_original;
	char *path_lock;

	int (*write)(git3_filebuf *file, void *source, size_t len);

	bool compute_digest;
	git3_hash_ctx digest;

	unsigned char *buffer;
	unsigned char *z_buf;

	z_stream zs;
	int flush_mode;

	size_t buf_size, buf_pos;
	git3_file fd;
	bool fd_is_open;
	bool created_lock;
	bool did_rename;
	bool do_not_buffer;
	bool do_fsync;
	int last_error;
};

#define GIT3_FILEBUF_INIT {0}

/*
 * The git3_filebuf object lifecycle is:
 * - Allocate git3_filebuf, preferably using GIT3_FILEBUF_INIT.
 *
 * - Call git3_filebuf_open() to initialize the filebuf for use.
 *
 * - Make as many calls to git3_filebuf_write(), git3_filebuf_printf(),
 *   git3_filebuf_reserve() as you like. The error codes for these
 *   functions don't need to be checked. They are stored internally
 *   by the file buffer.
 *
 * - While you are writing, you may call git3_filebuf_hash() to get
 *   the hash of all you have written so far. This function will
 *   fail if any of the previous writes to the buffer failed.
 *
 * - To close the git3_filebuf, you may call git3_filebuf_commit() or
 *   git3_filebuf_commit_at() to save the file, or
 *   git3_filebuf_cleanup() to abandon the file.  All of these will
 *   free the git3_filebuf object. Likewise, all of these will fail
 *   if any of the previous writes to the buffer failed, and set
 *   an error code accordingly.
 */
int git3_filebuf_write(git3_filebuf *lock, const void *buff, size_t len);
int git3_filebuf_reserve(git3_filebuf *file, void **buff, size_t len);
int git3_filebuf_printf(git3_filebuf *file, const char *format, ...) GIT3_FORMAT_PRINTF(2, 3);

int git3_filebuf_open(git3_filebuf *lock, const char *path, int flags, mode_t mode);
int git3_filebuf_open_withsize(git3_filebuf *file, const char *path, int flags, mode_t mode, size_t size);
int git3_filebuf_commit(git3_filebuf *lock);
int git3_filebuf_commit_at(git3_filebuf *lock, const char *path);
void git3_filebuf_cleanup(git3_filebuf *lock);
int git3_filebuf_hash(unsigned char *out, git3_filebuf *file);
int git3_filebuf_flush(git3_filebuf *file);
int git3_filebuf_stats(time_t *mtime, size_t *size, git3_filebuf *file);

GIT3_INLINE(int) git3_filebuf_hash_flags(git3_hash_algorithm_t algorithm)
{
	switch (algorithm) {
	case GIT3_HASH_ALGORITHM_SHA1:
		return GIT3_FILEBUF_HASH_SHA1;
	case GIT3_HASH_ALGORITHM_SHA256:
		return GIT3_FILEBUF_HASH_SHA256;
	default:
		return 0;
	}
}

#endif
