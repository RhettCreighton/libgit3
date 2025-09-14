/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_hash_win32_h__
#define INCLUDE_hash_win32_h__

#include "hash/sha.h"

#include <wincrypt.h>

typedef enum {
	GIT3_HASH_WIN32_INVALID = 0,
	GIT3_HASH_WIN32_CRYPTOAPI,
	GIT3_HASH_WIN32_CNG
} git3_hash_win32_provider_t;

struct git3_hash_win32_cryptoapi_ctx {
	bool valid;
	HCRYPTHASH hash_handle;
};

struct git3_hash_win32_cng_ctx {
	bool updated;
	HANDLE /* BCRYPT_HASH_HANDLE */ hash_handle;
	PBYTE hash_object;
};

typedef struct {
	ALG_ID algorithm;

	union {
		struct git3_hash_win32_cryptoapi_ctx cryptoapi;
		struct git3_hash_win32_cng_ctx cng;
	} ctx;
} git3_hash_win32_ctx;

/*
 * Gets/sets the current hash provider (cng or cryptoapi).  This is only
 * for testing purposes.
 */
git3_hash_win32_provider_t git3_hash_win32_provider(void);
int git3_hash_win32_set_provider(git3_hash_win32_provider_t provider);

#ifdef GIT3_SHA1_WIN32
struct git3_hash_sha1_ctx {
	git3_hash_win32_ctx win32;
};
#endif

#ifdef GIT3_SHA256_WIN32
struct git3_hash_sha256_ctx {
	git3_hash_win32_ctx win32;
};
#endif

#endif
