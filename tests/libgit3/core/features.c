#include "clar_libgit3.h"

void test_core_features__basic(void)
{
	int caps = git3_libgit3_features();

#ifdef GIT3_THREADS
	cl_assert((caps & GIT3_FEATURE_THREADS) != 0);
#else
	cl_assert((caps & GIT3_FEATURE_THREADS) == 0);
#endif

#ifdef GIT3_HTTPS
	cl_assert((caps & GIT3_FEATURE_HTTPS) != 0);
#endif

#if defined(GIT3_SSH)
	cl_assert((caps & GIT3_FEATURE_SSH) != 0);
#else
	cl_assert((caps & GIT3_FEATURE_SSH) == 0);
#endif

#if defined(GIT3_NSEC)
	cl_assert((caps & GIT3_FEATURE_NSEC) != 0);
#else
	cl_assert((caps & GIT3_FEATURE_NSEC) == 0);
#endif

	cl_assert((caps & GIT3_FEATURE_HTTP_PARSER) != 0);
	cl_assert((caps & GIT3_FEATURE_REGEX) != 0);

#if defined(GIT3_I18N_ICONV)
	cl_assert((caps & GIT3_FEATURE_I18N) != 0);
#endif

#if defined(GIT3_AUTH_NTLM)
	cl_assert((caps & GIT3_FEATURE_AUTH_NTLM) != 0);
#endif
#if defined(GIT3_AUTH_NEGOTIATE)
	cl_assert((caps & GIT3_FEATURE_AUTH_NEGOTIATE) != 0);
#endif

	cl_assert((caps & GIT3_FEATURE_COMPRESSION) != 0);
	cl_assert((caps & GIT3_FEATURE_SHA1) != 0);

#if defined(GIT3_EXPERIMENTAL_SHA256)
	cl_assert((caps & GIT3_FEATURE_SHA256) != 0);
#endif

	/*
	 * Ensure that our tests understand all the features;
	 * this test tries to ensure that if there's a new feature
	 * added that the backends test (below) is updated as well.
	 */
	cl_assert((caps & ~(GIT3_FEATURE_THREADS |
	                    GIT3_FEATURE_HTTPS |
	                    GIT3_FEATURE_SSH |
	                    GIT3_FEATURE_NSEC |
	                    GIT3_FEATURE_HTTP_PARSER |
	                    GIT3_FEATURE_REGEX |
	                    GIT3_FEATURE_I18N |
	                    GIT3_FEATURE_AUTH_NTLM |
	                    GIT3_FEATURE_AUTH_NEGOTIATE |
	                    GIT3_FEATURE_COMPRESSION |
	                    GIT3_FEATURE_SHA1 |
	                    GIT3_FEATURE_SHA256
			    )) == 0);
}

void test_core_features__backends(void)
{
	const char *threads = git3_libgit3_feature_backend(GIT3_FEATURE_THREADS);
	const char *https = git3_libgit3_feature_backend(GIT3_FEATURE_HTTPS);
	const char *ssh = git3_libgit3_feature_backend(GIT3_FEATURE_SSH);
	const char *nsec = git3_libgit3_feature_backend(GIT3_FEATURE_NSEC);
	const char *http_parser = git3_libgit3_feature_backend(GIT3_FEATURE_HTTP_PARSER);
	const char *regex = git3_libgit3_feature_backend(GIT3_FEATURE_REGEX);
	const char *i18n = git3_libgit3_feature_backend(GIT3_FEATURE_I18N);
	const char *ntlm = git3_libgit3_feature_backend(GIT3_FEATURE_AUTH_NTLM);
	const char *negotiate = git3_libgit3_feature_backend(GIT3_FEATURE_AUTH_NEGOTIATE);
	const char *compression = git3_libgit3_feature_backend(GIT3_FEATURE_COMPRESSION);
	const char *sha1 = git3_libgit3_feature_backend(GIT3_FEATURE_SHA1);
	const char *sha256 = git3_libgit3_feature_backend(GIT3_FEATURE_SHA256);

#if defined(GIT3_THREADS_WIN32)
	cl_assert_equal_s("win32", threads);
#elif defined(GIT3_THREADS_PTHREADS)
	cl_assert_equal_s("pthread", threads);
#elif defined(GIT3_THREADS)
	cl_assert(0);
#else
	cl_assert(threads == NULL);
#endif

#if defined(GIT3_HTTPS_OPENSSL)
	cl_assert_equal_s("openssl", https);
#elif defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
	cl_assert_equal_s("openssl-dynamic", https);
#elif defined(GIT3_HTTPS_MBEDTLS)
	cl_assert_equal_s("mbedtls", https);
#elif defined(GIT3_HTTPS_SECURETRANSPORT)
	cl_assert_equal_s("securetransport", https);
#elif defined(GIT3_HTTPS_SCHANNEL)
	cl_assert_equal_s("schannel", https);
#elif defined(GIT3_HTTPS_WINHTTP)
	cl_assert_equal_s("winhttp", https);
#elif defined(GIT3_HTTPS)
	cl_assert(0);
#else
	cl_assert(https == NULL);
#endif

#if defined(GIT3_SSH) && defined(GIT3_SSH_EXEC)
	cl_assert_equal_s("exec", ssh);
#elif defined(GIT3_SSH) && defined(GIT3_SSH_LIBSSH2)
	cl_assert_equal_s("libssh2", ssh);
#elif defined(GIT3_SSH)
	cl_assert(0);
#else
	cl_assert(ssh == NULL);
#endif

#if defined(GIT3_NSEC_MTIMESPEC)
	cl_assert_equal_s("mtimespec", nsec);
#elif defined(GIT3_NSEC_MTIM)
	cl_assert_equal_s("mtim", nsec);
#elif defined(GIT3_NSEC_MTIME_NSEC)
	cl_assert_equal_s("mtime_nsec", nsec);
#elif defined(GIT3_NSEC_WIN32)
	cl_assert_equal_s("win32", nsec);
#elif defined(GIT3_NSEC)
	cl_assert(0);
#else
	cl_assert(nsec == NULL);
#endif

#if defined(GIT3_HTTPPARSER_HTTPPARSER)
	cl_assert_equal_s("httpparser", http_parser);
#elif defined(GIT3_HTTPPARSER_LLHTTP)
	cl_assert_equal_s("llhttp", http_parser);
#elif defined(GIT3_HTTPPARSER_BUILTIN)
	cl_assert_equal_s("builtin", http_parser);
#else
	cl_assert(0);
#endif

#if defined(GIT3_REGEX_REGCOMP_L)
	cl_assert_equal_s("regcomp_l", regex);
#elif defined(GIT3_REGEX_REGCOMP)
	cl_assert_equal_s("regcomp", regex);
#elif defined(GIT3_REGEX_PCRE)
	cl_assert_equal_s("pcre", regex);
#elif defined(GIT3_REGEX_PCRE2)
	cl_assert_equal_s("pcre2", regex);
#elif defined(GIT3_REGEX_BUILTIN)
	cl_assert_equal_s("builtin", regex);
#else
	cl_assert(0);
#endif

#if defined(GIT3_I18N_ICONV)
	cl_assert_equal_s("iconv", i18n);
#elif defined(GIT3_I18N)
	cl_assert(0);
#else
	cl_assert(i18n == NULL);
#endif

#if defined(GIT3_AUTH_NTLM_BUILTIN)
	cl_assert_equal_s("builtin", ntlm);
#elif defined(GIT3_AUTH_NTLM_SSPI)
	cl_assert_equal_s("sspi", ntlm);
#elif defined(GIT3_AUTH_NTLM)
	cl_assert(0);
#else
	cl_assert(ntlm == NULL);
#endif

#if defined(GIT3_AUTH_NEGOTIATE_GSSFRAMEWORK)
	cl_assert_equal_s("gssframework", negotiate);
#elif defined(GIT3_AUTH_NEGOTIATE_GSSAPI)
	cl_assert_equal_s("gssapi", negotiate);
#elif defined(GIT3_AUTH_NEGOTIATE_SSPI)
	cl_assert_equal_s("sspi", negotiate);
#elif defined(GIT3_AUTH_NEGOTIATE)
	cl_assert(0);
#else
	cl_assert(negotiate == NULL);
#endif

#if defined(GIT3_COMPRESSION_BUILTIN)
	cl_assert_equal_s("builtin", compression);
#elif defined(GIT3_COMPRESSION_ZLIB)
	cl_assert_equal_s("zlib", compression);
#else
	cl_assert(0);
#endif

#if defined(GIT3_SHA1_BUILTIN)
	cl_assert_equal_s("builtin", sha1);
#elif defined(GIT3_SHA1_OPENSSL)
	cl_assert_equal_s("openssl", sha1);
#elif defined(GIT3_SHA1_OPENSSL_FIPS)
	cl_assert_equal_s("openssl-fips", sha1);
#elif defined(GIT3_SHA1_OPENSSL_DYNAMIC)
	cl_assert_equal_s("openssl-dynamic", sha1);
#elif defined(GIT3_SHA1_MBEDTLS)
	cl_assert_equal_s("mbedtls", sha1);
#elif defined(GIT3_SHA1_COMMON_CRYPTO)
	cl_assert_equal_s("commoncrypto", sha1);
#elif defined(GIT3_SHA1_WIN32)
	cl_assert_equal_s("win32", sha1);
#else
	cl_assert(0);
#endif

#if defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_BUILTIN)
	cl_assert_equal_s("builtin", sha256);
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_OPENSSL)
	cl_assert_equal_s("openssl", sha256);
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_OPENSSL_FIPS)
	cl_assert_equal_s("openssl-fips", sha256);
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_OPENSSL_DYNAMIC)
	cl_assert_equal_s("openssl-dynamic", sha256);
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_MBEDTLS)
	cl_assert_equal_s("mbedtls", sha256);
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_COMMON_CRYPTO)
	cl_assert_equal_s("commoncrypto", sha256);
#elif defined(GIT3_EXPERIMENTAL_SHA256) && defined(GIT3_SHA256_WIN32)
	cl_assert_equal_s("win32", sha256);
#elif defined(GIT3_EXPERIMENTAL_SHA256)
	cl_assert(0);
#else
	cl_assert(sha256 == NULL);
#endif
}
