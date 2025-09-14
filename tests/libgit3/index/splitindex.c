#include "clar_libgit3.h"
#include "index.h"

static git3_repository *g_repo;

void test_index_splitindex__initialize(void)
{
	g_repo = cl_git_sandbox_init("splitindex");
}

void test_index_splitindex__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_index_splitindex__fail_on_open(void)
{
	git3_index *idx;
	cl_git_fail_with(-1, git3_repository_index(&idx, g_repo));
	cl_assert_equal_s(git3_error_last()->message, "unsupported mandatory extension: 'link'");
}
