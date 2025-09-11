/*
 * SHA3-256 (Keccak) implementation for libgit3
 * Based on FIPS 202 specification
 * Copyright (C) 2025 Rhett Creighton
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <string.h>
#include <stdint.h>
#include "sha3.h"

/* Keccak round constants */
static const uint64_t keccak_round_constants[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL,
	0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL,
	0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL,
	0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL,
	0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Rotation offsets */
static const unsigned int r[24] = {
	1, 3, 6, 10, 15, 21, 28, 36,
	45, 55, 2, 14, 27, 41, 56, 8,
	25, 43, 62, 18, 39, 61, 20, 44
};

/* Lane position after pi step */
static const unsigned int piln[24] = {
	10, 7, 11, 17, 18, 3, 5, 16,
	8, 21, 24, 4, 15, 23, 19, 13,
	12, 2, 20, 14, 22, 9, 6, 1
};

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static void keccak_f1600(uint64_t st[25])
{
	uint64_t bc[5], t;
	unsigned int i, j, round;

	for (round = 0; round < 24; round++) {
		/* Theta */
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		/* Rho and pi */
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = piln[i];
			bc[0] = st[j];
			st[j] = ROTL64(t, r[i]);
			t = bc[0];
		}

		/* Chi */
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		/* Iota */
		st[0] ^= keccak_round_constants[round];
	}
}

void blk_SHA3_Init(blk_SHA3_CTX *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
}

void blk_SHA3_Update(blk_SHA3_CTX *ctx, const void *data, size_t len)
{
	const uint8_t *src = data;
	size_t remaining = len;

	/* Process any buffered data */
	if (ctx->offset) {
		size_t copy_len = blk_SHA3_256_BLKSIZE - ctx->offset;
		if (copy_len > remaining)
			copy_len = remaining;

		memcpy(ctx->buf + ctx->offset, src, copy_len);
		ctx->offset += copy_len;
		src += copy_len;
		remaining -= copy_len;

		if (ctx->offset == blk_SHA3_256_BLKSIZE) {
			int i;
			/* XOR block into state */
			for (i = 0; i < blk_SHA3_256_BLKSIZE / 8; i++) {
				ctx->state[i] ^= ((uint64_t *)ctx->buf)[i];
			}
			keccak_f1600(ctx->state);
			ctx->offset = 0;
		}
	}

	/* Process full blocks */
	while (remaining >= blk_SHA3_256_BLKSIZE) {
		int i;
		for (i = 0; i < blk_SHA3_256_BLKSIZE / 8; i++) {
			ctx->state[i] ^= ((uint64_t *)src)[i];
		}
		keccak_f1600(ctx->state);
		src += blk_SHA3_256_BLKSIZE;
		remaining -= blk_SHA3_256_BLKSIZE;
	}

	/* Buffer remaining data */
	if (remaining > 0) {
		memcpy(ctx->buf, src, remaining);
		ctx->offset = remaining;
	}
}

void blk_SHA3_Final(unsigned char *digest, blk_SHA3_CTX *ctx)
{
	int i;
	/* Pad the message according to SHA3 padding rules */
	memset(ctx->buf + ctx->offset, 0, blk_SHA3_256_BLKSIZE - ctx->offset);
	ctx->buf[ctx->offset] = 0x06; /* SHA3 domain separation */
	ctx->buf[blk_SHA3_256_BLKSIZE - 1] |= 0x80;

	/* XOR final block into state */
	for (i = 0; i < blk_SHA3_256_BLKSIZE / 8; i++) {
		ctx->state[i] ^= ((uint64_t *)ctx->buf)[i];
	}
	keccak_f1600(ctx->state);

	/* Extract digest */
	memcpy(digest, ctx->state, blk_SHA3_256_DIGESTSIZE);

	/* Clear sensitive data */
	memset(ctx, 0, sizeof(*ctx));
}