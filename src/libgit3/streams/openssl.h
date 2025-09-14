/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_streams_openssl_h__
#define INCLUDE_streams_openssl_h__

#include "common.h"
#include "streams/openssl_legacy.h"
#include "streams/openssl_dynamic.h"

#include "git3/sys/stream.h"

extern int git3_openssl_stream_global_init(void);

#if defined(GIT3_HTTPS_OPENSSL)
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/x509v3.h>
# include <openssl/bio.h>
# endif

#if defined(GIT3_HTTPS_OPENSSL) || defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
extern int git3_openssl__set_cert_location(const char *file, const char *path);
extern int git3_openssl__add_x509_cert(X509 *cert);
extern int git3_openssl__reset_context(void);
extern int git3_openssl_stream_new(git3_stream **out, const char *host, const char *port);
extern int git3_openssl_stream_wrap(git3_stream **out, git3_stream *in, const char *host);
#endif

#endif
