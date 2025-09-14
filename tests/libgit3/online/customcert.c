#include "clar.h"
#include "clar_libgit3.h"

#include "path.h"
#include "git3/clone.h"
#include "git3/cred_helpers.h"
#include "remote.h"
#include "futils.h"
#include "refs.h"
#include "str.h"
#include "streams/openssl.h"

#ifdef GIT3_HTTPS_OPENSSL
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/x509v3.h>
#endif

/*
 * Certificates for https://test.libgit3.org/ are in the `certs` folder.
 */
#define CUSTOM_CERT_DIR "certs"

#define CUSTOM_CERT_ONE_URL "https://test.libgit3.org:1443/anonymous/test.git"
#define CUSTOM_CERT_ONE_PATH "one"

#define CUSTOM_CERT_TWO_URL "https://test.libgit3.org:2443/anonymous/test.git"
#define CUSTOM_CERT_TWO_FILE "two.pem"

#define CUSTOM_CERT_THREE_URL "https://test.libgit3.org:3443/anonymous/test.git"
#define CUSTOM_CERT_THREE_FILE "three.pem.raw"

#if (GIT3_HTTPS_OPENSSL || GIT3_HTTPS_OPENSSL_DYNAMIC || GIT3_HTTPS_MBEDTLS)
static git3_repository *g_repo;
#endif

void test_online_customcert__initialize(void)
{
#if (GIT3_HTTPS_OPENSSL || GIT3_HTTPS_OPENSSL_DYNAMIC || GIT3_HTTPS_MBEDTLS)
	git3_str path = GIT3_STR_INIT, file = GIT3_STR_INIT;
	char cwd[GIT3_PATH_MAX];

	g_repo = NULL;

	cl_fixture_sandbox(CUSTOM_CERT_DIR);

	cl_must_pass(p_getcwd(cwd, GIT3_PATH_MAX));
	cl_git_pass(git3_str_join_n(&path, '/', 3, cwd, CUSTOM_CERT_DIR, CUSTOM_CERT_ONE_PATH));
	cl_git_pass(git3_str_join_n(&file, '/', 3, cwd, CUSTOM_CERT_DIR, CUSTOM_CERT_TWO_FILE));

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_SSL_CERT_LOCATIONS,
	                             file.ptr, path.ptr));

	git3_str_dispose(&file);
	git3_str_dispose(&path);
#endif
}

void test_online_customcert__cleanup(void)
{
#if (GIT3_HTTPS_OPENSSL || GIT3_HTTPS_OPENSSL_DYNAMIC || GIT3_HTTPS_MBEDTLS)
	if (g_repo) {
		git3_repository_free(g_repo);
		g_repo = NULL;
	}

	cl_fixture_cleanup("./cloned");
	cl_fixture_cleanup(CUSTOM_CERT_DIR);
#endif

#if (GIT3_HTTPS_OPENSSL || GIT3_HTTPS_OPENSSL_DYNAMIC)
	git3_openssl__reset_context();
#endif
}

void test_online_customcert__file(void)
{
#if (GIT3_HTTPS_OPENSSL || GIT3_HTTPS_OPENSSL_DYNAMIC || GIT3_HTTPS_MBEDTLS)
	cl_git_pass(git3_clone(&g_repo, CUSTOM_CERT_ONE_URL, "./cloned", NULL));
	cl_assert(git3_fs_path_exists("./cloned/master.txt"));
#endif
}

void test_online_customcert__path(void)
{
#if (GIT3_HTTPS_OPENSSL || GIT3_HTTPS_OPENSSL_DYNAMIC || GIT3_HTTPS_MBEDTLS)
	cl_git_pass(git3_clone(&g_repo, CUSTOM_CERT_TWO_URL, "./cloned", NULL));
	cl_assert(git3_fs_path_exists("./cloned/master.txt"));
#endif
}

void test_online_customcert__raw_x509(void)
{
#if GIT3_HTTPS_OPENSSL
	X509* x509_cert = NULL;
	char cwd[GIT3_PATH_MAX];
	git3_str raw_file = GIT3_STR_INIT,
		raw_file_data = GIT3_STR_INIT,
		raw_cert = GIT3_STR_INIT;
	const unsigned char *raw_cert_bytes = NULL;

	cl_must_pass(p_getcwd(cwd, GIT3_PATH_MAX));

	cl_git_pass(git3_str_join_n(&raw_file, '/', 3, cwd, CUSTOM_CERT_DIR, CUSTOM_CERT_THREE_FILE));

	cl_git_pass(git3_futils_readbuffer(&raw_file_data, git3_str_cstr(&raw_file)));
	cl_git_pass(git3_str_decode_base64(&raw_cert, git3_str_cstr(&raw_file_data), git3_str_len(&raw_file_data)));

	raw_cert_bytes = (const unsigned char *)git3_str_cstr(&raw_cert);
	x509_cert = d2i_X509(NULL, &raw_cert_bytes, git3_str_len(&raw_cert));
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_ADD_SSL_X509_CERT, x509_cert));
	X509_free(x509_cert);

	cl_git_pass(git3_clone(&g_repo, CUSTOM_CERT_THREE_URL, "./cloned", NULL));
	cl_assert(git3_fs_path_exists("./cloned/master.txt"));

	git3_str_dispose(&raw_cert);
	git3_str_dispose(&raw_file_data);
	git3_str_dispose(&raw_file);
#endif
}
