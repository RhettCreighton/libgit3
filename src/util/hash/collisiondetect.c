/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "collisiondetect.h"

int git3_hash_sha1_global_init(void)
{
	return 0;
}

int git3_hash_sha1_ctx_init(git3_hash_sha1_ctx *ctx)
{
	return git3_hash_sha1_init(ctx);
}

void git3_hash_sha1_ctx_cleanup(git3_hash_sha1_ctx *ctx)
{
	GIT3_UNUSED(ctx);
}

int git3_hash_sha1_init(git3_hash_sha1_ctx *ctx)
{
	GIT3_ASSERT_ARG(ctx);
	SHA1DCInit(&ctx->c);
	return 0;
}

int git3_hash_sha1_update(git3_hash_sha1_ctx *ctx, const void *data, size_t len)
{
	GIT3_ASSERT_ARG(ctx);
	SHA1DCUpdate(&ctx->c, data, len);
	return 0;
}

int git3_hash_sha1_final(unsigned char *out, git3_hash_sha1_ctx *ctx)
{
	GIT3_ASSERT_ARG(ctx);
	if (SHA1DCFinal(out, &ctx->c)) {
		git3_error_set(GIT3_ERROR_SHA, "SHA1 collision attack detected");
		return -1;
	}

	return 0;
}
