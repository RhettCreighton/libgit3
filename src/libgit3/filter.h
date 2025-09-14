/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_filter_h__
#define INCLUDE_filter_h__

#include "common.h"

#include "attr_file.h"
#include "git3/filter.h"
#include "git3/sys/filter.h"

/* Amount of file to examine for NUL byte when checking binary-ness */
#define GIT3_FILTER_BYTES_TO_CHECK_NUL 8000

typedef struct {
	git3_filter_options options;
	git3_attr_session *attr_session;
	git3_str *temp_buf;
} git3_filter_session;

#define GIT3_FILTER_SESSION_INIT {GIT3_FILTER_OPTIONS_INIT, 0}

extern int git3_filter_global_init(void);

extern void git3_filter_free(git3_filter *filter);

extern int git3_filter_list__load(
	git3_filter_list **filters,
	git3_repository *repo,
	git3_blob *blob, /* can be NULL */
	const char *path,
	git3_filter_mode_t mode,
	git3_filter_session *filter_session);

int git3_filter_list__apply_to_buffer(
	git3_str *out,
	git3_filter_list *filters,
	const char *in,
	size_t in_len);
int git3_filter_list__apply_to_file(
	git3_str *out,
	git3_filter_list *filters,
	git3_repository *repo,
	const char *path);
int git3_filter_list__apply_to_blob(
	git3_str *out,
	git3_filter_list *filters,
	git3_blob *blob);

/*
 * The given input buffer will be converted to the given output buffer.
 * The input buffer will be freed (_if_ it was allocated).
 */
extern int git3_filter_list__convert_buf(
	git3_str *out,
	git3_filter_list *filters,
	git3_str *in);

extern int git3_filter_list__apply_to_file(
	git3_str *out,
	git3_filter_list *filters,
	git3_repository *repo,
	const char *path);

/*
 * Available filters
 */

extern git3_filter *git3_crlf_filter_new(void);
extern git3_filter *git3_ident_filter_new(void);

extern int git3_filter_buffered_stream_new(
	git3_writestream **out,
	git3_filter *filter,
	int (*write_fn)(git3_filter *, void **, git3_str *, const git3_str *, const git3_filter_source *),
	git3_str *temp_buf,
	void **payload,
	const git3_filter_source *source,
	git3_writestream *target);

#endif
