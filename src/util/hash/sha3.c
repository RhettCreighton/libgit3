/*
 * SHA3-256 implementation wrapper for libgit3
 * Copyright (C) 2025 Rhett Creighton
 * Copyright (C) the libgit2 contributors
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "sha3.h"
#include "sha3/block/sha3.h"

int git_hash_sha3_global_init(void)
{
    return 0;
}

int git_hash_sha3_ctx_init(git_hash_sha3_ctx *ctx)
{
    memset(ctx, 0, sizeof(git_hash_sha3_ctx));
    return 0;
}

void git_hash_sha3_ctx_cleanup(git_hash_sha3_ctx *ctx)
{
    if (ctx)
        memset(ctx, 0, sizeof(git_hash_sha3_ctx));
}

int git_hash_sha3_init(git_hash_sha3_ctx *ctx)
{
    blk_SHA3_CTX sha3_ctx;
    blk_SHA3_Init(&sha3_ctx);
    /* Copy the initialized state */
    memcpy(ctx->state, sha3_ctx.state, sizeof(ctx->state));
    ctx->buf_idx = sha3_ctx.offset;
    memcpy(ctx->buffer, sha3_ctx.buf, sizeof(ctx->buffer));
    return 0;
}

int git_hash_sha3_update(git_hash_sha3_ctx *ctx, const void *data, size_t len)
{
    blk_SHA3_CTX sha3_ctx;
    /* Restore state */
    memcpy(sha3_ctx.state, ctx->state, sizeof(ctx->state));
    sha3_ctx.offset = ctx->buf_idx;
    memcpy(sha3_ctx.buf, ctx->buffer, sizeof(sha3_ctx.buf));
    
    blk_SHA3_Update(&sha3_ctx, data, len);
    
    /* Save state */
    memcpy(ctx->state, sha3_ctx.state, sizeof(ctx->state));
    ctx->buf_idx = sha3_ctx.offset;
    memcpy(ctx->buffer, sha3_ctx.buf, sizeof(sha3_ctx.buf));
    
    return 0;
}

int git_hash_sha3_final(unsigned char *out, git_hash_sha3_ctx *ctx)
{
    blk_SHA3_CTX sha3_ctx;
    /* Restore state */
    memcpy(sha3_ctx.state, ctx->state, sizeof(ctx->state));
    sha3_ctx.offset = ctx->buf_idx;
    memcpy(sha3_ctx.buf, ctx->buffer, sizeof(sha3_ctx.buf));
    
    blk_SHA3_Final(out, &sha3_ctx);
    return 0;
}