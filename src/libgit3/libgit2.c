/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <git3.h>
#include "alloc.h"
#include "buf.h"
#include "common.h"
#include "filter.h"
#include "hash.h"
#include "merge_driver.h"
#include "pool.h"
#include "mwindow.h"
#include "oid.h"
#include "rand.h"
#include "runtime.h"
#include "settings.h"
#include "sysdir.h"
#include "thread.h"
#include "git3/global.h"
#include "streams/registry.h"
#include "streams/mbedtls.h"
#include "streams/openssl.h"
#include "streams/socket.h"
#include "transports/ssh_libssh2.h"

#ifdef GIT3_WIN32
# include "win32/w32_leakcheck.h"
#endif

int git3_libgit3_init(void)
{
	static git3_runtime_init_fn init_fns[] = {
#ifdef GIT3_WIN32
		git3_win32_leakcheck_global_init,
#endif
		git3_allocator_global_init,
		git3_error_global_init,
		git3_threads_global_init,
		git3_oid_global_init,
		git3_rand_global_init,
		git3_hash_global_init,
		git3_sysdir_global_init,
		git3_filter_global_init,
		git3_merge_driver_global_init,
		git3_transport_ssh_libssh2_global_init,
		git3_stream_registry_global_init,
		git3_socket_stream_global_init,
		git3_openssl_stream_global_init,
		git3_mbedtls_stream_global_init,
		git3_mwindow_global_init,
		git3_pool_global_init,
		git3_settings_global_init
	};

	return git3_runtime_init(init_fns, ARRAY_SIZE(init_fns));
}

int git3_libgit3_shutdown(void)
{
	return git3_runtime_shutdown();
}

int git3_libgit3_version(int *major, int *minor, int *rev)
{
	*major = LIBGIT3_VERSION_MAJOR;
	*minor = LIBGIT3_VERSION_MINOR;
	*rev = LIBGIT3_VERSION_REVISION;

	return 0;
}

const char *git3_libgit3_prerelease(void)
{
	return LIBGIT3_VERSION_PRERELEASE;
}

int git3_libgit3_features(void)
{
	return 0
#ifdef GIT3_THREADS
		| GIT3_FEATURE_THREADS
#endif
#ifdef GIT3_HTTPS
		| GIT3_FEATURE_HTTPS
#endif
#ifdef GIT3_SSH
		| GIT3_FEATURE_SSH
#endif
#ifdef GIT3_NSEC
		| GIT3_FEATURE_NSEC
#endif
		| GIT3_FEATURE_HTTP_PARSER
		| GIT3_FEATURE_REGEX
#ifdef GIT3_I18N_ICONV
		| GIT3_FEATURE_I18N
#endif
#if defined(GIT3_AUTH_NTLM)
		| GIT3_FEATURE_AUTH_NTLM
#endif
#if defined(GIT3_AUTH_NEGOTIATE)
		| GIT3_FEATURE_AUTH_NEGOTIATE
#endif
		| GIT3_FEATURE_COMPRESSION
		| GIT3_FEATURE_SHA1
#ifdef GIT3_EXPERIMENTAL_SHA256
		| GIT3_FEATURE_SHA256
#endif
	;
}

const char *git3_libgit3_feature_backend(git3_feature_t feature)
{
	switch (feature) {
	case GIT3_FEATURE_THREADS:
#if defined(GIT3_THREADS_PTHREADS)
		return "pthread";
#elif defined(GIT3_THREADS_WIN32)
		return "win32";
#elif defined(GIT3_THREADS)
		GIT3_ASSERT_WITH_RETVAL(!"Unknown threads backend", NULL);
#endif
		break;

	case GIT3_FEATURE_HTTPS:
#if defined(GIT3_HTTPS_OPENSSL)
		return "openssl";
#elif defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
		return "openssl-dynamic";
#elif defined(GIT3_HTTPS_MBEDTLS)
		return "mbedtls";
#elif defined(GIT3_HTTPS_SECURETRANSPORT)
		return "securetransport";
#elif defined(GIT3_HTTPS_SCHANNEL)
		return "schannel";
#elif defined(GIT3_HTTPS_WINHTTP)
		return "winhttp";
#elif defined(GIT3_HTTPS)
		GIT3_ASSERT_WITH_RETVAL(!"Unknown HTTPS backend", NULL);
#endif
		break;

	case GIT3_FEATURE_SSH:
#if defined(GIT3_SSH_EXEC)
		return "exec";
#elif defined(GIT3_SSH_LIBSSH2)
		return "libssh2";
#elif defined(GIT3_SSH)
		GIT3_ASSERT_WITH_RETVAL(!"Unknown SSH backend", NULL);
#endif
		break;

	case GIT3_FEATURE_NSEC:
#if defined(GIT3_NSEC_MTIMESPEC)
		return "mtimespec";
#elif defined(GIT3_NSEC_MTIM)
		return "mtim";
#elif defined(GIT3_NSEC_MTIME_NSEC)
		return "mtime_nsec";
#elif defined(GIT3_NSEC_WIN32)
		return "win32";
#elif defined(GIT3_NSEC)
		GIT3_ASSERT_WITH_RETVAL(!"Unknown high-resolution time backend", NULL);
#endif
		break;

	case GIT3_FEATURE_HTTP_PARSER:
#if defined(GIT3_HTTPPARSER_HTTPPARSER)
		return "httpparser";
#elif defined(GIT3_HTTPPARSER_LLHTTP)
		return "llhttp";
#elif defined(GIT3_HTTPPARSER_BUILTIN)
		return "builtin";
#endif
		GIT3_ASSERT_WITH_RETVAL(!"Unknown HTTP parser backend", NULL);
		break;

	case GIT3_FEATURE_REGEX:
#if defined(GIT3_REGEX_REGCOMP_L)
		return "regcomp_l";
#elif defined(GIT3_REGEX_REGCOMP)
		return "regcomp";
#elif defined(GIT3_REGEX_PCRE)
		return "pcre";
#elif defined(GIT3_REGEX_PCRE2)
		return "pcre2";
#elif defined(GIT3_REGEX_BUILTIN)
		return "builtin";
#endif
		GIT3_ASSERT_WITH_RETVAL(!"Unknown regular expression backend", NULL);
		break;

	case GIT3_FEATURE_I18N:
#if defined(GIT3_I18N_ICONV)
		return "iconv";
#elif defined(GIT3_I18N)
		GIT3_ASSERT_WITH_RETVAL(!"Unknown internationalization backend", NULL);
#endif
		break;

	case GIT3_FEATURE_AUTH_NTLM:
#if defined(GIT3_AUTH_NTLM_BUILTIN)
		return "builtin";
#elif defined(GIT3_AUTH_NTLM_SSPI)
		return "sspi";
#elif defined(GIT3_AUTH_NTLM)
		GIT3_ASSERT_WITH_RETVAL(!"Unknown NTLM backend", NULL);
#endif
		break;

	case GIT3_FEATURE_AUTH_NEGOTIATE:
#if defined(GIT3_AUTH_NEGOTIATE_GSSFRAMEWORK)
		return "gssframework";
#elif defined(GIT3_AUTH_NEGOTIATE_GSSAPI)
		return "gssapi";
#elif defined(GIT3_AUTH_NEGOTIATE_SSPI)
		return "sspi";
#elif defined(GIT3_AUTH_NEGOTIATE)
		GIT3_ASSERT_WITH_RETVAL(!"Unknown Negotiate backend", NULL);
#endif
		break;

	case GIT3_FEATURE_COMPRESSION:
#if defined(GIT3_COMPRESSION_ZLIB)
		return "zlib";
#elif defined(GIT3_COMPRESSION_BUILTIN)
		return "builtin";
#else
		GIT3_ASSERT_WITH_RETVAL(!"Unknown compression backend", NULL);
#endif
		break;

	case GIT3_FEATURE_SHA1:
#if defined(GIT3_SHA1_BUILTIN)
		return "builtin";
#elif defined(GIT3_SHA1_OPENSSL)
		return "openssl";
#elif defined(GIT3_SHA1_OPENSSL_FIPS)
		return "openssl-fips";
#elif defined(GIT3_SHA1_OPENSSL_DYNAMIC)
		return "openssl-dynamic";
#elif defined(GIT3_SHA1_MBEDTLS)
		return "mbedtls";
#elif defined(GIT3_SHA1_COMMON_CRYPTO)
		return "commoncrypto";
#elif defined(GIT3_SHA1_WIN32)
		return "win32";
#else
		GIT3_ASSERT_WITH_RETVAL(!"Unknown SHA1 backend", NULL);
#endif
		break;

	case GIT3_FEATURE_SHA256:
#if defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_BUILTIN)
		return "builtin";
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_OPENSSL)
		return "openssl";
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_OPENSSL_FIPS)
		return "openssl-fips";
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_OPENSSL_DYNAMIC)
		return "openssl-dynamic";
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_MBEDTLS)
		return "mbedtls";
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_COMMON_CRYPTO)
		return "commoncrypto";
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_WIN32)
		return "win32";
#elif defined(GIT3_EXPERIMENTAL_SHA256)
		GIT3_ASSERT_WITH_RETVAL(!"Unknown SHA256 backend", NULL);
#endif
		break;
	}

	return NULL;
}
