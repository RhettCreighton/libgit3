/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_merge_driver_h__
#define INCLUDE_merge_driver_h__

#include "common.h"

#include "git3/merge.h"
#include "git3/index.h"
#include "git3/sys/merge.h"

struct git3_merge_driver_source {
	git3_repository *repo;
	const char *default_driver;
	const git3_merge_file_options *file_opts;

	const git3_index_entry *ancestor;
	const git3_index_entry *ours;
	const git3_index_entry *theirs;
};

typedef struct git3_merge_driver__builtin {
	git3_merge_driver base;
	git3_merge_file_favor_t favor;
} git3_merge_driver__builtin;

extern int git3_merge_driver_global_init(void);

extern int git3_merge_driver_for_path(
	char **name_out,
	git3_merge_driver **driver_out,
	git3_repository *repo,
	const char *path);

/* Merge driver configuration */
extern int git3_merge_driver_for_source(
	const char **name_out,
	git3_merge_driver **driver_out,
	const git3_merge_driver_source *src);

extern int git3_merge_driver__builtin_apply(
	git3_merge_driver *self,
	const char **path_out,
	uint32_t *mode_out,
	git3_buf *merged_out,
	const char *filter_name,
	const git3_merge_driver_source *src);

/* Merge driver for text files, performs a standard three-way merge */
extern git3_merge_driver__builtin git3_merge_driver__text;

/* Merge driver for union-style merging */
extern git3_merge_driver__builtin git3_merge_driver__union;

/* Merge driver for unmergeable (binary) files: always produces conflicts */
extern git3_merge_driver git3_merge_driver__binary;

#endif
