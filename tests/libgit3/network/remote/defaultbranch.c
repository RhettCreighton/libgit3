#include "clar_libgit3.h"
#include "refspec.h"
#include "remote.h"

static git3_remote *g_remote;
static git3_repository *g_repo_a, *g_repo_b;

void test_network_remote_defaultbranch__initialize(void)
{
	g_repo_a = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(git3_repository_init(&g_repo_b, "repo-b.git", true));
	cl_git_pass(git3_remote_create(&g_remote, g_repo_b, "origin", git3_repository_path(g_repo_a)));
}

void test_network_remote_defaultbranch__cleanup(void)
{
	git3_remote_free(g_remote);
	git3_repository_free(g_repo_b);

	cl_git_sandbox_cleanup();
	cl_fixture_cleanup("repo-b.git");
}

static void assert_default_branch(const char *should)
{
	git3_buf name = GIT3_BUF_INIT;

	cl_git_pass(git3_remote_connect(g_remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_pass(git3_remote_default_branch(&name, g_remote));
	cl_assert_equal_s(should, name.ptr);
	git3_buf_dispose(&name);
}

void test_network_remote_defaultbranch__master(void)
{
	assert_default_branch("refs/heads/master");
}

void test_network_remote_defaultbranch__master_does_not_win(void)
{
	cl_git_pass(git3_repository_set_head(g_repo_a, "refs/heads/not-good"));
	assert_default_branch("refs/heads/not-good");
}

void test_network_remote_defaultbranch__master_on_detached(void)
{
	cl_git_pass(git3_repository_detach_head(g_repo_a));
	assert_default_branch("refs/heads/master");
}

void test_network_remote_defaultbranch__no_default_branch(void)
{
	git3_remote *remote_b;
	const git3_remote_head **heads;
	size_t len;
	git3_buf buf = GIT3_BUF_INIT;

	cl_git_pass(git3_remote_create(&remote_b, g_repo_b, "self", git3_repository_path(g_repo_b)));
	cl_git_pass(git3_remote_connect(remote_b, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_pass(git3_remote_ls(&heads, &len, remote_b));
	cl_assert_equal_i(0, len);

	cl_git_fail_with(GIT3_ENOTFOUND, git3_remote_default_branch(&buf, remote_b));

	git3_remote_free(remote_b);
}

void test_network_remote_defaultbranch__detached_sharing_nonbranch_id(void)
{
	git3_oid id, id_cloned;
	git3_reference *ref;
	git3_buf buf = GIT3_BUF_INIT;
	git3_repository *cloned_repo;

	cl_git_pass(git3_reference_name_to_id(&id, g_repo_a, "HEAD"));
	cl_git_pass(git3_repository_detach_head(g_repo_a));
	cl_git_pass(git3_reference_remove(g_repo_a, "refs/heads/master"));
	cl_git_pass(git3_reference_remove(g_repo_a, "refs/heads/not-good"));
	cl_git_pass(git3_reference_create(&ref, g_repo_a, "refs/foo/bar", &id, 1, NULL));
	git3_reference_free(ref);

	cl_git_pass(git3_remote_connect(g_remote, GIT3_DIRECTION_FETCH, NULL, NULL, NULL));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_remote_default_branch(&buf, g_remote));

	cl_git_pass(git3_clone(&cloned_repo, git3_repository_path(g_repo_a), "./local-detached", NULL));

	cl_assert(git3_repository_head_detached(cloned_repo));
	cl_git_pass(git3_reference_name_to_id(&id_cloned, g_repo_a, "HEAD"));
	cl_assert(git3_oid_equal(&id, &id_cloned));

	git3_repository_free(cloned_repo);
}

void test_network_remote_defaultbranch__unborn_HEAD_with_branches(void)
{
	git3_reference *ref;
	git3_repository *cloned_repo;

	cl_git_pass(git3_reference_symbolic_create(&ref, g_repo_a, "HEAD", "refs/heads/i-dont-exist", 1, NULL));
	git3_reference_free(ref);

	cl_git_pass(git3_clone(&cloned_repo, git3_repository_path(g_repo_a), "./semi-empty", NULL));

	cl_assert(git3_repository_head_unborn(cloned_repo));

	git3_repository_free(cloned_repo);
}
