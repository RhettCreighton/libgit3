#include "clar_libgit3.h"
#include "branch.h"
#include "remote.h"

static git3_repository *g_repo;
static const char *remote_tracking_branch_name = "refs/remotes/test/master";
static const char *expected_remote_name = "test";
static int expected_remote_name_length;

void test_refs_branches_remote__initialize(void)
{
	g_repo = cl_git_sandbox_init("testrepo");

	expected_remote_name_length = (int)strlen(expected_remote_name) + 1;
}

void test_refs_branches_remote__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_refs_branches_remote__can_get_remote_for_branch(void)
{
	git3_buf remotename = {0};

	cl_git_pass(git3_branch_remote_name(&remotename, g_repo, remote_tracking_branch_name));

	cl_assert_equal_s("test", remotename.ptr);
	git3_buf_dispose(&remotename);
}

void test_refs_branches_remote__no_matching_remote_returns_error(void)
{
	const char *unknown = "refs/remotes/nonexistent/master";
	git3_buf buf = GIT3_BUF_INIT;

	git3_error_clear();
	cl_git_fail_with(git3_branch_remote_name(&buf, g_repo, unknown), GIT3_ENOTFOUND);
	cl_assert(git3_error_last() != NULL);
}

void test_refs_branches_remote__local_remote_returns_error(void)
{
	const char *local = "refs/heads/master";
	git3_buf buf = GIT3_BUF_INIT;

	git3_error_clear();
	cl_git_fail_with(git3_branch_remote_name(&buf, g_repo, local), GIT3_ERROR);
	cl_assert(git3_error_last() != NULL);
}

void test_refs_branches_remote__ambiguous_remote_returns_error(void)
{
	git3_remote *remote;
	git3_buf buf = GIT3_BUF_INIT;

	/* Create the remote */
	cl_git_pass(git3_remote_create_with_fetchspec(&remote, g_repo, "addtest", "http://github.com/libgit3/libgit3", "refs/heads/*:refs/remotes/test/*"));

	git3_remote_free(remote);

	git3_error_clear();
	cl_git_fail_with(git3_branch_remote_name(&buf, g_repo, remote_tracking_branch_name), GIT3_EAMBIGUOUS);
	cl_assert(git3_error_last() != NULL);
}
