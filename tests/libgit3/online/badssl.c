#include "clar_libgit3.h"

#include "git3/clone.h"

static git3_repository *g_repo;

#ifdef GIT3_HTTPS
static bool g_has_ssl = true;
#else
static bool g_has_ssl = false;
#endif

static int cert_check_assert_invalid(git3_cert *cert, int valid, const char* host, void *payload)
{
	GIT3_UNUSED(cert); GIT3_UNUSED(host); GIT3_UNUSED(payload);

	cl_assert_equal_i(0, valid);

	return GIT3_ECERTIFICATE;
}

void test_online_badssl__expired(void)
{
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	opts.fetch_opts.callbacks.certificate_check = cert_check_assert_invalid;

	if (!g_has_ssl)
		cl_skip();

	cl_git_fail_with(GIT3_ECERTIFICATE,
			 git3_clone(&g_repo, "https://expired.badssl.com/fake.git", "./fake", NULL));

	cl_git_fail_with(GIT3_ECERTIFICATE,
			 git3_clone(&g_repo, "https://expired.badssl.com/fake.git", "./fake", &opts));
}

void test_online_badssl__wrong_host(void)
{
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	opts.fetch_opts.callbacks.certificate_check = cert_check_assert_invalid;

	if (!g_has_ssl)
		cl_skip();

	cl_git_fail_with(GIT3_ECERTIFICATE,
			 git3_clone(&g_repo, "https://wrong.host.badssl.com/fake.git", "./fake", NULL));
	cl_git_fail_with(GIT3_ECERTIFICATE,
			 git3_clone(&g_repo, "https://wrong.host.badssl.com/fake.git", "./fake", &opts));
}

void test_online_badssl__self_signed(void)
{
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	opts.fetch_opts.callbacks.certificate_check = cert_check_assert_invalid;

	if (!g_has_ssl)
		cl_skip();

	cl_git_fail_with(GIT3_ECERTIFICATE,
			 git3_clone(&g_repo, "https://self-signed.badssl.com/fake.git", "./fake", NULL));
	cl_git_fail_with(GIT3_ECERTIFICATE,
			 git3_clone(&g_repo, "https://self-signed.badssl.com/fake.git", "./fake", &opts));
}

void test_online_badssl__old_cipher(void)
{
	git3_clone_options opts = GIT3_CLONE_OPTIONS_INIT;
	opts.fetch_opts.callbacks.certificate_check = cert_check_assert_invalid;

	if (!g_has_ssl)
		cl_skip();

	cl_git_fail(git3_clone(&g_repo, "https://rc4.badssl.com/fake.git", "./fake", NULL));
	cl_git_fail(git3_clone(&g_repo, "https://rc4.badssl.com/fake.git", "./fake", &opts));
}

void test_online_badssl__sslv3(void)
{
	if (!g_has_ssl)
		cl_skip();

	cl_git_fail(git3_clone(&g_repo, "https://mailserv.baehal.com/fake.git", "./fake", NULL));
}
