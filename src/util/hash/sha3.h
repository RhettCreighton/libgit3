/*
 * SHA3-256 support for libgit3
 * Copyright (C) 2025 Rhett Creighton
 * Copyright (C) the libgit3 contributors
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_hash_sha3_h__
#define INCLUDE_hash_sha3_h__

#include "git3_util.h"

#define GIT3_HASH_SHA3_SIZE 32
#define GIT3_HASH_SHA3_HEX_SIZE (GIT3_HASH_SHA3_SIZE * 2)

typedef struct git3_hash_sha3_ctx {
    uint64_t state[25];
    uint32_t buf_idx;
    uint8_t buffer[136];  /* SHA3-256 rate is 136 bytes */
} git3_hash_sha3_ctx;

int git3_hash_sha3_global_init(void);
int git3_hash_sha3_ctx_init(git3_hash_sha3_ctx *ctx);
void git3_hash_sha3_ctx_cleanup(git3_hash_sha3_ctx *ctx);

int git3_hash_sha3_init(git3_hash_sha3_ctx *ctx);
int git3_hash_sha3_update(git3_hash_sha3_ctx *ctx, const void *data, size_t len);
int git3_hash_sha3_final(unsigned char *out, git3_hash_sha3_ctx *ctx);

#endif