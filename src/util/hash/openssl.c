/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "openssl.h"

#if defined(GIT3_SHA1_OPENSSL_DYNAMIC) || defined(GIT3_SHA256_OPENSSL_DYNAMIC)
# include <dlfcn.h>

static int handle_count;
static void *openssl_handle;

static int git3_hash_openssl_global_shutdown(void)
{
	if (--handle_count == 0) {
		dlclose(openssl_handle);
		openssl_handle = NULL;
	}

	return 0;
}

static int git3_hash_openssl_global_init(void)
{
	if (!handle_count) {
		if ((openssl_handle = dlopen("libssl.so.1.1", RTLD_NOW)) == NULL &&
		    (openssl_handle = dlopen("libssl.1.1.dylib", RTLD_NOW)) == NULL &&
		    (openssl_handle = dlopen("libssl.so.1.0.0", RTLD_NOW)) == NULL &&
		    (openssl_handle = dlopen("libssl.1.0.0.dylib", RTLD_NOW)) == NULL &&
		    (openssl_handle = dlopen("libssl.so.10", RTLD_NOW)) == NULL &&
		    (openssl_handle = dlopen("libssl.so.3", RTLD_NOW)) == NULL &&
		    (openssl_handle = dlopen("libssl.3.dylib", RTLD_NOW)) == NULL) {
			git3_error_set(GIT3_ERROR_SSL, "could not load ssl libraries");
			return -1;
		}
	}

	if (git3_hash_openssl_global_shutdown() < 0)
		return -1;

	handle_count++;
	return 0;
}

#endif

#ifdef GIT3_SHA1_OPENSSL_DYNAMIC
static int (*SHA1_Init)(SHA_CTX *c);
static int (*SHA1_Update)(SHA_CTX *c, const void *data, size_t len);
static int (*SHA1_Final)(unsigned char *md, SHA_CTX *c);

int git3_hash_sha1_global_init(void)
{
	if (git3_hash_openssl_global_init() < 0)
		return -1;

	if ((SHA1_Init = dlsym(openssl_handle, "SHA1_Init")) == NULL ||
	    (SHA1_Update = dlsym(openssl_handle, "SHA1_Update")) == NULL ||
	    (SHA1_Final = dlsym(openssl_handle, "SHA1_Final")) == NULL) {
		const char *msg = dlerror();
		git3_error_set(GIT3_ERROR_SSL, "could not load hash function: %s", msg ? msg : "unknown error");
		return -1;
	}

	return 0;
}
#elif GIT3_SHA1_OPENSSL
int git3_hash_sha1_global_init(void)
{
	return 0;
}
#endif

#if defined(GIT3_SHA1_OPENSSL) || defined(GIT3_SHA1_OPENSSL_DYNAMIC)

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

	if (SHA1_Init(&ctx->c) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to initialize sha1 context");
		return -1;
	}

	return 0;
}

int git3_hash_sha1_update(git3_hash_sha1_ctx *ctx, const void *data, size_t len)
{
	GIT3_ASSERT_ARG(ctx);

	if (SHA1_Update(&ctx->c, data, len) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to update sha1");
		return -1;
	}

	return 0;
}

int git3_hash_sha1_final(unsigned char *out, git3_hash_sha1_ctx *ctx)
{
	GIT3_ASSERT_ARG(ctx);

	if (SHA1_Final(out, &ctx->c) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to finalize sha1");
		return -1;
	}

	return 0;
}

#endif

#ifdef GIT3_SHA1_OPENSSL_FIPS

static const EVP_MD *SHA1_ENGINE_DIGEST_TYPE = NULL;

int git3_hash_sha1_global_init(void)
{
	SHA1_ENGINE_DIGEST_TYPE = EVP_sha1();
	return SHA1_ENGINE_DIGEST_TYPE != NULL ? 0 : -1;
}

int git3_hash_sha1_ctx_init(git3_hash_sha1_ctx *ctx)
{
	return git3_hash_sha1_init(ctx);
}

void git3_hash_sha1_ctx_cleanup(git3_hash_sha1_ctx *ctx)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_destroy(ctx->c);
#else
	EVP_MD_CTX_free(ctx->c);
#endif
}

int git3_hash_sha1_init(git3_hash_sha1_ctx *ctx)
{
	GIT3_ASSERT_ARG(ctx);
	GIT3_ASSERT(SHA1_ENGINE_DIGEST_TYPE);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ctx->c = EVP_MD_CTX_create();
#else
	ctx->c = EVP_MD_CTX_new();
#endif

	GIT3_ASSERT(ctx->c);

	if (EVP_DigestInit_ex(ctx->c, SHA1_ENGINE_DIGEST_TYPE, NULL) != 1) {
		git3_hash_sha1_ctx_cleanup(ctx);
		git3_error_set(GIT3_ERROR_SHA, "failed to initialize sha1 context");
		return -1;
	}

	return 0;
}

int git3_hash_sha1_update(git3_hash_sha1_ctx *ctx, const void *data, size_t len)
{
	GIT3_ASSERT_ARG(ctx && ctx->c);

	if (EVP_DigestUpdate(ctx->c, data, len) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to update sha1");
		return -1;
	}

	return 0;
}

int git3_hash_sha1_final(unsigned char *out, git3_hash_sha1_ctx *ctx)
{
	unsigned int len = 0;

	GIT3_ASSERT_ARG(ctx && ctx->c);

	if (EVP_DigestFinal(ctx->c, out, &len) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to finalize sha1");
		return -1;
	}

	return 0;
}

#endif

#ifdef GIT3_SHA256_OPENSSL_DYNAMIC
static int (*SHA256_Init)(SHA256_CTX *c);
static int (*SHA256_Update)(SHA256_CTX *c, const void *data, size_t len);
static int (*SHA256_Final)(unsigned char *md, SHA256_CTX *c);

int git3_hash_sha256_global_init(void)
{
	if (git3_hash_openssl_global_init() < 0)
		return -1;

	if ((SHA256_Init = dlsym(openssl_handle, "SHA256_Init")) == NULL ||
	    (SHA256_Update = dlsym(openssl_handle, "SHA256_Update")) == NULL ||
	    (SHA256_Final = dlsym(openssl_handle, "SHA256_Final")) == NULL) {
		const char *msg = dlerror();
		git3_error_set(GIT3_ERROR_SSL, "could not load hash function: %s", msg ? msg : "unknown error");
		return -1;
	}

	return 0;
}
#elif GIT3_SHA256_OPENSSL
int git3_hash_sha256_global_init(void)
{
	return 0;
}
#endif

#if defined(GIT3_SHA256_OPENSSL) || defined(GIT3_SHA256_OPENSSL_DYNAMIC)

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

	if (SHA256_Init(&ctx->c) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to initialize sha256 context");
		return -1;
	}

	return 0;
}

int git3_hash_sha256_update(git3_hash_sha256_ctx *ctx, const void *data, size_t len)
{
	GIT3_ASSERT_ARG(ctx);

	if (SHA256_Update(&ctx->c, data, len) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to update sha256");
		return -1;
	}

	return 0;
}

int git3_hash_sha256_final(unsigned char *out, git3_hash_sha256_ctx *ctx)
{
	GIT3_ASSERT_ARG(ctx);

	if (SHA256_Final(out, &ctx->c) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to finalize sha256");
		return -1;
	}

	return 0;
}

#endif

#ifdef GIT3_SHA256_OPENSSL_FIPS

static const EVP_MD *SHA256_ENGINE_DIGEST_TYPE = NULL;

int git3_hash_sha256_global_init(void)
{
	SHA256_ENGINE_DIGEST_TYPE = EVP_sha256();
	return SHA256_ENGINE_DIGEST_TYPE != NULL ? 0 : -1;
}

int git3_hash_sha256_ctx_init(git3_hash_sha256_ctx *ctx)
{
	return git3_hash_sha256_init(ctx);
}

void git3_hash_sha256_ctx_cleanup(git3_hash_sha256_ctx *ctx)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	EVP_MD_CTX_destroy(ctx->c);
#else
	EVP_MD_CTX_free(ctx->c);
#endif
}

int git3_hash_sha256_init(git3_hash_sha256_ctx *ctx)
{
	GIT3_ASSERT_ARG(ctx);
	GIT3_ASSERT(SHA256_ENGINE_DIGEST_TYPE);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	ctx->c = EVP_MD_CTX_create();
#else
	ctx->c = EVP_MD_CTX_new();
#endif

	GIT3_ASSERT(ctx->c);

	if (EVP_DigestInit_ex(ctx->c, SHA256_ENGINE_DIGEST_TYPE, NULL) != 1) {
		git3_hash_sha256_ctx_cleanup(ctx);
		git3_error_set(GIT3_ERROR_SHA, "failed to initialize sha256 context");
		return -1;
	}

	return 0;
}

int git3_hash_sha256_update(git3_hash_sha256_ctx *ctx, const void *data, size_t len)
{
	GIT3_ASSERT_ARG(ctx && ctx->c);

	if (EVP_DigestUpdate(ctx->c, data, len) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to update sha256");
		return -1;
	}

	return 0;
}

int git3_hash_sha256_final(unsigned char *out, git3_hash_sha256_ctx *ctx)
{
	unsigned int len = 0;

	GIT3_ASSERT_ARG(ctx && ctx->c);

	if (EVP_DigestFinal(ctx->c, out, &len) != 1) {
		git3_error_set(GIT3_ERROR_SHA, "failed to finalize sha256");
		return -1;
	}

	return 0;
}

#endif
