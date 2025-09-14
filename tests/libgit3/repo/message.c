#include "clar_libgit3.h"
#include "refs.h"
#include "posix.h"

static git3_repository *_repo;

void test_repo_message__initialize(void)
{
	_repo = cl_git_sandbox_init("testrepo.git");
}

void test_repo_message__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_repo_message__none(void)
{
	git3_buf actual = GIT3_BUF_INIT;
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_repository_message(&actual, _repo));
}

void test_repo_message__message(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_buf actual = GIT3_BUF_INIT;
	const char expected[] = "Test\n\nThis is a test of the emergency broadcast system\n";

	cl_git_pass(git3_str_joinpath(&path, git3_repository_path(_repo), "MERGE_MSG"));
	cl_git_mkfile(git3_str_cstr(&path), expected);

	cl_git_pass(git3_repository_message(&actual, _repo));
	cl_assert_equal_s(expected, actual.ptr);
	git3_buf_dispose(&actual);

	cl_git_pass(p_unlink(git3_str_cstr(&path)));
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_repository_message(&actual, _repo));
	git3_str_dispose(&path);
}
