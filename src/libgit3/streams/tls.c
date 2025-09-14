/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git3/errors.h"

#include "common.h"
#include "streams/registry.h"
#include "streams/tls.h"
#include "streams/mbedtls.h"
#include "streams/openssl.h"
#include "streams/stransport.h"
#include "streams/schannel.h"

int git3_tls_stream_new(git3_stream **out, const char *host, const char *port)
{
	int (*init)(git3_stream **, const char *, const char *) = NULL;
	git3_stream_registration custom = {0};
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(host);
	GIT3_ASSERT_ARG(port);

	if ((error = git3_stream_registry_lookup(&custom, GIT3_STREAM_TLS)) == 0) {
		init = custom.init;
	} else if (error == GIT3_ENOTFOUND) {
#if defined(GIT3_HTTPS_SECURETRANSPORT)
		init = git3_stransport_stream_new;
#elif defined(GIT3_HTTPS_OPENSSL) || \
      defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
		init = git3_openssl_stream_new;
#elif defined(GIT3_HTTPS_MBEDTLS)
		init = git3_mbedtls_stream_new;
#elif defined(GIT3_HTTPS_SCHANNEL)
		init = git3_schannel_stream_new;
#endif
	} else {
		return error;
	}

	if (!init) {
		git3_error_set(GIT3_ERROR_SSL, "there is no TLS stream available");
		return -1;
	}

	return init(out, host, port);
}

int git3_tls_stream_wrap(git3_stream **out, git3_stream *in, const char *host)
{
	int (*wrap)(git3_stream **, git3_stream *, const char *) = NULL;
	git3_stream_registration custom = {0};

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(in);

	if (git3_stream_registry_lookup(&custom, GIT3_STREAM_TLS) == 0) {
		wrap = custom.wrap;
	} else {
#if defined(GIT3_HTTPS_SECURETRANSPORT)
		wrap = git3_stransport_stream_wrap;
#elif defined(GIT3_HTTPS_OPENSSL) || \
      defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
		wrap = git3_openssl_stream_wrap;
#elif defined(GIT3_HTTPS_MBEDTLS)
		wrap = git3_mbedtls_stream_wrap;
#elif defined(GIT3_HTTPS_SCHANNEL)
		wrap = git3_schannel_stream_wrap;
#endif
	}

	if (!wrap) {
		git3_error_set(GIT3_ERROR_SSL, "there is no TLS stream available");
		return -1;
	}

	return wrap(out, in, host);
}
