/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "builtin.h"

int git3_hash_sha256_global_init(void)
{
	return 0;
}

int git3_hash_sha256_ctx_init(git3_hash_sha256_ctx *ctx)
{
	return git3_hash_sha256_init(ctx);
}

void git3_hash_sha256_ctx_cleanup(git3_hash_sha256_ctx *ctx)
{
	GIT3_UNUSED(ctx);
}

int git3_hash_sha256_init(git3_hash_sha256_ctx *ctx)
{
	GIT3_ASSERT_ARG(ctx);
	if (SHA256Reset(&ctx->c)) {
		git3_error_set(GIT3_ERROR_SHA, "SHA256 error");
		return -1;
	}
	return 0;
}

int git3_hash_sha256_update(git3_hash_sha256_ctx *ctx, const void *_data, size_t len)
{
	const unsigned char *data = _data;
	GIT3_ASSERT_ARG(ctx);

	while (len > 0) {
		unsigned int chunk = (len > UINT_MAX) ? UINT_MAX : (unsigned int)len;

		if (SHA256Input(&ctx->c, data, chunk)) {
			git3_error_set(GIT3_ERROR_SHA, "SHA256 error");
			return -1;
		}

		data += chunk;
		len -= chunk;
	}

	return 0;
}

int git3_hash_sha256_final(unsigned char *out, git3_hash_sha256_ctx *ctx)
{
	GIT3_ASSERT_ARG(ctx);
	if (SHA256Result(&ctx->c, out)) {
		git3_error_set(GIT3_ERROR_SHA, "SHA256 error");
		return -1;
	}
	return 0;
}
