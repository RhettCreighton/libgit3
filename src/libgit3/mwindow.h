/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_mwindow__
#define INCLUDE_mwindow__

#include "common.h"

#include "map.h"
#include "vector.h"
#include "hashmap_str.h"

GIT3_HASHMAP_STR_STRUCT(git3_mwindow_packmap, struct git3_pack_file *);
GIT3_HASHMAP_STR_PROTOTYPES(git3_mwindow_packmap, struct git3_pack_file *);

typedef struct git3_mwindow {
	struct git3_mwindow *next;
	git3_map window_map;
	off64_t offset;
	size_t last_used;
	size_t inuse_cnt;
} git3_mwindow;

typedef struct git3_mwindow_file {
	git3_mutex lock; /* protects updates to fd */
	git3_mwindow *windows;
	int fd;
	off64_t size;
} git3_mwindow_file;

typedef struct git3_mwindow_ctl {
	size_t mapped;
	unsigned int open_windows;
	unsigned int mmap_calls;
	unsigned int peak_open_windows;
	size_t peak_mapped;
	size_t used_ctr;
	git3_vector windowfiles;
} git3_mwindow_ctl;

int git3_mwindow_contains(git3_mwindow *win, off64_t offset, off64_t extra);
int git3_mwindow_free_all(git3_mwindow_file *mwf); /* locks */
unsigned char *git3_mwindow_open(git3_mwindow_file *mwf, git3_mwindow **cursor, off64_t offset, size_t extra, unsigned int *left);
int git3_mwindow_file_register(git3_mwindow_file *mwf);
void git3_mwindow_file_deregister(git3_mwindow_file *mwf);
void git3_mwindow_close(git3_mwindow **w_cursor);

extern int git3_mwindow_global_init(void);

struct git3_pack_file; /* just declaration to avoid cyclical includes */
int git3_mwindow_get_pack(
	struct git3_pack_file **out,
	const char *path,
	git3_oid_t oid_type);
int git3_mwindow_put_pack(struct git3_pack_file *pack);

#endif
