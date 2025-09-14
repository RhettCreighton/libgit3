#include "clar_libgit3.h"
#include "settings.h"

static git3_buf default_ua = GIT3_BUF_INIT;
static git3_buf default_product = GIT3_BUF_INIT;

void test_core_useragent__initialize(void)
{
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_GET_USER_AGENT, &default_ua));
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_GET_USER_AGENT_PRODUCT, &default_product));
}

void test_core_useragent__cleanup(void)
{
	git3_libgit3_opts(GIT3_OPT_SET_USER_AGENT, NULL);
	git3_libgit3_opts(GIT3_OPT_SET_USER_AGENT_PRODUCT, NULL);

	git3_buf_dispose(&default_ua);
	git3_buf_dispose(&default_product);
}

void test_core_useragent__get_default(void)
{
	cl_assert(default_ua.size);
	cl_assert(default_ua.ptr);
	cl_assert(git3__prefixcmp(default_ua.ptr, "libgit3 ") == 0);

	cl_assert(default_product.size);
	cl_assert(default_product.ptr);
	cl_assert(git3__prefixcmp(default_product.ptr, "git/") == 0);
}

void test_core_useragent__set(void)
{
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_USER_AGENT, "foo bar 4.24"));
	cl_assert_equal_s("foo bar 4.24", git3_settings__user_agent());
	cl_assert_equal_s(default_product.ptr, git3_settings__user_agent_product());

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_USER_AGENT_PRODUCT, "baz/2.2.3"));
	cl_assert_equal_s("foo bar 4.24", git3_settings__user_agent());
	cl_assert_equal_s("baz/2.2.3", git3_settings__user_agent_product());

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_USER_AGENT, ""));
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_USER_AGENT_PRODUCT, ""));
	cl_assert_equal_s("", git3_settings__user_agent());
	cl_assert_equal_s("", git3_settings__user_agent_product());

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_USER_AGENT, NULL));
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_USER_AGENT_PRODUCT, NULL));
	cl_assert_equal_s(default_ua.ptr, git3_settings__user_agent());
	cl_assert_equal_s(default_product.ptr, git3_settings__user_agent_product());
}
