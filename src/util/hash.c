/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "hash.h"

int git3_hash_global_init(void)
{
	if (git3_hash_sha1_global_init() < 0 ||
	    git3_hash_sha256_global_init() < 0 ||
	    git3_hash_sha3_global_init() < 0)
		return -1;

	return 0;
}

int git3_hash_ctx_init(git3_hash_ctx *ctx, git3_hash_algorithm_t algorithm)
{
	int error;

	switch (algorithm) {
	case GIT3_HASH_ALGORITHM_SHA1:
		error = git3_hash_sha1_ctx_init(&ctx->ctx.sha1);
		break;
	case GIT3_HASH_ALGORITHM_SHA256:
		error = git3_hash_sha256_ctx_init(&ctx->ctx.sha256);
		break;
	case GIT3_HASH_ALGORITHM_SHA3_256:
		error = git3_hash_sha3_ctx_init(&ctx->ctx.sha3);
		break;
	default:
		git3_error_set(GIT3_ERROR_INTERNAL, "unknown hash algorithm");
		error = -1;
	}

	ctx->algorithm = algorithm;
	return error;
}

void git3_hash_ctx_cleanup(git3_hash_ctx *ctx)
{
	switch (ctx->algorithm) {
	case GIT3_HASH_ALGORITHM_SHA1:
		git3_hash_sha1_ctx_cleanup(&ctx->ctx.sha1);
		return;
	case GIT3_HASH_ALGORITHM_SHA256:
		git3_hash_sha256_ctx_cleanup(&ctx->ctx.sha256);
		return;
	case GIT3_HASH_ALGORITHM_SHA3_256:
		git3_hash_sha3_ctx_cleanup(&ctx->ctx.sha3);
		return;
	default:
		/* unreachable */ ;
	}
}

int git3_hash_init(git3_hash_ctx *ctx)
{
	switch (ctx->algorithm) {
	case GIT3_HASH_ALGORITHM_SHA1:
		return git3_hash_sha1_init(&ctx->ctx.sha1);
	case GIT3_HASH_ALGORITHM_SHA256:
		return git3_hash_sha256_init(&ctx->ctx.sha256);
	case GIT3_HASH_ALGORITHM_SHA3_256:
		return git3_hash_sha3_init(&ctx->ctx.sha3);
	default:
		/* unreachable */ ;
	}

	git3_error_set(GIT3_ERROR_INTERNAL, "unknown hash algorithm");
	return -1;
}

int git3_hash_update(git3_hash_ctx *ctx, const void *data, size_t len)
{
	switch (ctx->algorithm) {
	case GIT3_HASH_ALGORITHM_SHA1:
		return git3_hash_sha1_update(&ctx->ctx.sha1, data, len);
	case GIT3_HASH_ALGORITHM_SHA256:
		return git3_hash_sha256_update(&ctx->ctx.sha256, data, len);
	case GIT3_HASH_ALGORITHM_SHA3_256:
		return git3_hash_sha3_update(&ctx->ctx.sha3, data, len);
	default:
		/* unreachable */ ;
	}

	git3_error_set(GIT3_ERROR_INTERNAL, "unknown hash algorithm");
	return -1;
}

int git3_hash_final(unsigned char *out, git3_hash_ctx *ctx)
{
	switch (ctx->algorithm) {
	case GIT3_HASH_ALGORITHM_SHA1:
		return git3_hash_sha1_final(out, &ctx->ctx.sha1);
	case GIT3_HASH_ALGORITHM_SHA256:
		return git3_hash_sha256_final(out, &ctx->ctx.sha256);
	case GIT3_HASH_ALGORITHM_SHA3_256:
		return git3_hash_sha3_final(out, &ctx->ctx.sha3);
	default:
		/* unreachable */ ;
	}

	git3_error_set(GIT3_ERROR_INTERNAL, "unknown hash algorithm");
	return -1;
}

int git3_hash_buf(
	unsigned char *out,
	const void *data,
	size_t len,
	git3_hash_algorithm_t algorithm)
{
	git3_hash_ctx ctx;
	int error = 0;

	if (git3_hash_ctx_init(&ctx, algorithm) < 0)
		return -1;

	if ((error = git3_hash_update(&ctx, data, len)) >= 0)
		error = git3_hash_final(out, &ctx);

	git3_hash_ctx_cleanup(&ctx);

	return error;
}

int git3_hash_vec(
	unsigned char *out,
	git3_str_vec *vec,
	size_t n,
	git3_hash_algorithm_t algorithm)
{
	git3_hash_ctx ctx;
	size_t i;
	int error = 0;

	if (git3_hash_ctx_init(&ctx, algorithm) < 0)
		return -1;

	for (i = 0; i < n; i++) {
		if ((error = git3_hash_update(&ctx, vec[i].data, vec[i].len)) < 0)
			goto done;
	}

	error = git3_hash_final(out, &ctx);

done:
	git3_hash_ctx_cleanup(&ctx);

	return error;
}

int git3_hash_fmt(char *out, unsigned char *hash, size_t hash_len)
{
	static char hex[] = "0123456789abcdef";
	char *str = out;
	size_t i;

	for (i = 0; i < hash_len; i++) {
		*str++ = hex[hash[i] >> 4];
		*str++ = hex[hash[i] & 0x0f];
	}

	*str++ = '\0';

	return 0;
}
