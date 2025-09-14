/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_zstream_h__
#define INCLUDE_zstream_h__

#include "git3_util.h"

#include <zlib.h>

#include "str.h"

typedef enum {
	GIT3_ZSTREAM_INFLATE,
	GIT3_ZSTREAM_DEFLATE
} git3_zstream_t;

typedef struct {
	z_stream z;
	git3_zstream_t type;
	const char *in;
	size_t in_len;
	int flush;
	int zerr;
} git3_zstream;

#define GIT3_ZSTREAM_INIT {{0}}

int git3_zstream_init(git3_zstream *zstream, git3_zstream_t type);
void git3_zstream_free(git3_zstream *zstream);

int git3_zstream_set_input(git3_zstream *zstream, const void *in, size_t in_len);

size_t git3_zstream_suggest_output_len(git3_zstream *zstream);

/* get as much output as is available in the input buffer */
int git3_zstream_get_output_chunk(
	void *out, size_t *out_len, git3_zstream *zstream);

/* get all the output from the entire input buffer */
int git3_zstream_get_output(void *out, size_t *out_len, git3_zstream *zstream);

bool git3_zstream_done(git3_zstream *zstream);
bool git3_zstream_eos(git3_zstream *zstream);

void git3_zstream_reset(git3_zstream *zstream);

int git3_zstream_deflatebuf(git3_str *out, const void *in, size_t in_len);
int git3_zstream_inflatebuf(git3_str *out, const void *in, size_t in_len);

#endif
