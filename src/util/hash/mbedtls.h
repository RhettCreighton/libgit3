/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_hash_mbedtls_h__
#define INCLUDE_hash_mbedtls_h__

#include "hash/sha.h"

#ifdef GIT3_SHA1_MBEDTLS
# include <mbedtls/sha1.h>

struct git3_hash_sha1_ctx {
    mbedtls_sha1_context c;
};
#endif

#ifdef GIT3_SHA256_MBEDTLS
# include <mbedtls/sha256.h>

struct git3_hash_sha256_ctx {
    mbedtls_sha256_context c;
};
#endif

#endif /* INCLUDE_hash_sha1_mbedtls_h__ */
