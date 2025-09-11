/*
 * SHA3-256 block implementation header for libgit3
 * Copyright (C) 2025 Rhett Creighton
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef SHA3_BLOCK_SHA3_H
#define SHA3_BLOCK_SHA3_H

#include <stdint.h>
#include <stddef.h>

#define blk_SHA3_256_BLKSIZE 136  /* SHA3-256 block size (1088 bits / 8) */
#define blk_SHA3_256_DIGESTSIZE 32 /* SHA3-256 digest size (256 bits / 8) */

struct blk_SHA3_CTX {
	uint64_t state[25];     /* Keccak state (5x5 matrix of 64-bit words) */
	uint32_t offset;        /* Current position in buffer */
	uint8_t buf[blk_SHA3_256_BLKSIZE]; /* Input buffer */
};

typedef struct blk_SHA3_CTX blk_SHA3_CTX;

void blk_SHA3_Init(blk_SHA3_CTX *ctx);
void blk_SHA3_Update(blk_SHA3_CTX *ctx, const void *data, size_t len);
void blk_SHA3_Final(unsigned char *digest, blk_SHA3_CTX *ctx);

#define platform_SHA3_CTX blk_SHA3_CTX
#define platform_SHA3_Init blk_SHA3_Init
#define platform_SHA3_Update blk_SHA3_Update
#define platform_SHA3_Final blk_SHA3_Final

#endif