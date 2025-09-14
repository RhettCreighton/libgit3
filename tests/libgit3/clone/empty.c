#include "clar_libgit3.h"

#include "git3/clone.h"
#include "repository.h"
#include "repo/repo_helpers.h"

static git3_clone_options g_options;
static git3_repository *g_repo;
static git3_repository *g_repo_cloned;

void test_clone_empty__initialize(void)
{
	git3_repository *sandbox = cl_git_sandbox_init("empty_bare.git");
	git3_fetch_options dummy_options = GIT3_FETCH_OPTIONS_INIT;
	cl_git_remove_placeholders(git3_repository_path(sandbox), "dummy-marker.txt");

	g_repo = NULL;

	memset(&g_options, 0, sizeof(git3_clone_options));
	g_options.version = GIT3_CLONE_OPTIONS_VERSION;
	g_options.fetch_opts = dummy_options;
}

void test_clone_empty__cleanup(void)
{
	cl_fixture_cleanup("tmp_global_path");
	cl_git_sandbox_cleanup();
}

static void cleanup_repository(void *path)
{
	cl_fixture_cleanup((const char *)path);

	git3_repository_free(g_repo_cloned);
	g_repo_cloned = NULL;
}

void test_clone_empty__can_clone_an_empty_local_repo_barely(void)
{
	char *local_name = "refs/heads/master";
	const char *expected_tracked_branch_name = "refs/remotes/origin/master";
	const char *expected_remote_name = "origin";
	git3_buf buf = GIT3_BUF_INIT;
	git3_reference *ref;

	cl_set_cleanup(&cleanup_repository, "./empty");

	g_options.bare = true;
	cl_git_pass(git3_clone(&g_repo_cloned, "./empty_bare.git", "./empty", &g_options));

	/* Although the HEAD is unborn... */
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_reference_lookup(&ref, g_repo_cloned, local_name));

	/* ...one can still retrieve the name of the remote tracking reference */
	cl_git_pass(git3_branch_upstream_name(&buf, g_repo_cloned, local_name));

	cl_assert_equal_s(expected_tracked_branch_name, buf.ptr);
	git3_buf_dispose(&buf);

	/* ...and the name of the remote... */
	cl_git_pass(git3_branch_remote_name(&buf, g_repo_cloned, expected_tracked_branch_name));

	cl_assert_equal_s(expected_remote_name, buf.ptr);
	git3_buf_dispose(&buf);

	/* ...even when the remote HEAD is unborn as well */
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_reference_lookup(&ref, g_repo_cloned,
		expected_tracked_branch_name));
}

void test_clone_empty__respects_initialbranch_config(void)
{
	git3_buf buf = GIT3_BUF_INIT;

	create_tmp_global_config("tmp_global_path", "init.defaultbranch", "my_default_branch");

	cl_set_cleanup(&cleanup_repository, "./empty");

	g_options.bare = true;
	cl_git_pass(git3_clone(&g_repo_cloned, "./empty_bare.git", "./empty", &g_options));
	cl_git_pass(git3_branch_upstream_name(&buf, g_repo_cloned, "refs/heads/my_default_branch"));
	cl_assert_equal_s("refs/remotes/origin/my_default_branch", buf.ptr);
	git3_buf_dispose(&buf);
}

void test_clone_empty__can_clone_an_empty_local_repo(void)
{
	cl_set_cleanup(&cleanup_repository, "./empty");

	cl_git_pass(git3_clone(&g_repo_cloned, "./empty_bare.git", "./empty", &g_options));
}

void test_clone_empty__can_clone_an_empty_standard_repo(void)
{
	cl_git_sandbox_cleanup();
	g_repo = cl_git_sandbox_init("empty_standard_repo");
	cl_git_remove_placeholders(git3_repository_path(g_repo), "dummy-marker.txt");

	cl_set_cleanup(&cleanup_repository, "./empty");

	cl_git_pass(git3_clone(&g_repo_cloned, "./empty_standard_repo", "./empty", &g_options));
}
