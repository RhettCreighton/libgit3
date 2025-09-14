/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_hash_h__
#define INCLUDE_hash_h__

#include "git3_util.h"

#include "hash/sha.h"
#include "hash/sha3.h"

typedef struct {
	void *data;
	size_t len;
} git3_str_vec;

typedef enum {
	GIT3_HASH_ALGORITHM_NONE = 0,
	GIT3_HASH_ALGORITHM_SHA1,
	GIT3_HASH_ALGORITHM_SHA256,
	GIT3_HASH_ALGORITHM_SHA3_256
} git3_hash_algorithm_t;

#define GIT3_HASH_MAX_SIZE GIT3_HASH_SHA256_SIZE

typedef struct git3_hash_ctx {
	union {
		git3_hash_sha1_ctx sha1;
		git3_hash_sha256_ctx sha256;
		git3_hash_sha3_ctx sha3;
	} ctx;
	git3_hash_algorithm_t algorithm;
} git3_hash_ctx;

int git3_hash_global_init(void);

int git3_hash_ctx_init(git3_hash_ctx *ctx, git3_hash_algorithm_t algorithm);
void git3_hash_ctx_cleanup(git3_hash_ctx *ctx);

int git3_hash_init(git3_hash_ctx *c);
int git3_hash_update(git3_hash_ctx *c, const void *data, size_t len);
int git3_hash_final(unsigned char *out, git3_hash_ctx *c);

int git3_hash_buf(unsigned char *out, const void *data, size_t len, git3_hash_algorithm_t algorithm);
int git3_hash_vec(unsigned char *out, git3_str_vec *vec, size_t n, git3_hash_algorithm_t algorithm);

int git3_hash_fmt(char *out, unsigned char *hash, size_t hash_len);

GIT3_INLINE(size_t) git3_hash_size(git3_hash_algorithm_t algorithm) {
	switch (algorithm) {
		case GIT3_HASH_ALGORITHM_SHA1:
			return GIT3_HASH_SHA1_SIZE;
		case GIT3_HASH_ALGORITHM_SHA256:
			return GIT3_HASH_SHA256_SIZE;
		case GIT3_HASH_ALGORITHM_SHA3_256:
			return GIT3_HASH_SHA3_SIZE;
		default:
			return 0;
	}
}

#endif
