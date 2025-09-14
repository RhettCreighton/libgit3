#include "clar_libgit3.h"
#include "worktree_helpers.h"
#include "submodule/submodule_helpers.h"

#define COMMON_REPO "testrepo.git"
#define WORKTREE_REPO "worktree"

static git3_repository *g_repo;

void test_worktree_bare__initialize(void)
{
	g_repo = cl_git_sandbox_init(COMMON_REPO);

	cl_assert_equal_i(1, git3_repository_is_bare(g_repo));
	cl_assert_equal_i(0, git3_repository_is_worktree(g_repo));
}

void test_worktree_bare__cleanup(void)
{
	cl_fixture_cleanup(WORKTREE_REPO);
	cl_git_sandbox_cleanup();
}

void test_worktree_bare__list(void)
{
	git3_strarray wts;

	cl_git_pass(git3_worktree_list(&wts, g_repo));
	cl_assert_equal_i(wts.count, 0);

	git3_strarray_dispose(&wts);
}

void test_worktree_bare__add(void)
{
	git3_worktree *wt;
	git3_repository *wtrepo;
	git3_strarray wts;

	cl_git_pass(git3_worktree_add(&wt, g_repo, "name", WORKTREE_REPO, NULL));

	cl_git_pass(git3_worktree_list(&wts, g_repo));
	cl_assert_equal_i(wts.count, 1);

	cl_git_pass(git3_worktree_validate(wt));

	cl_git_pass(git3_repository_open(&wtrepo, WORKTREE_REPO));
	cl_assert_equal_i(0, git3_repository_is_bare(wtrepo));
	cl_assert_equal_i(1, git3_repository_is_worktree(wtrepo));

	git3_strarray_dispose(&wts);
	git3_worktree_free(wt);
	git3_repository_free(wtrepo);
}

void test_worktree_bare__repository_path(void)
{
	git3_worktree *wt;
	git3_repository *wtrepo;

	cl_git_pass(git3_worktree_add(&wt, g_repo, "name", WORKTREE_REPO, NULL));
	cl_assert_equal_s(git3_worktree_path(wt), cl_git_sandbox_path(0, WORKTREE_REPO, NULL));

	cl_git_pass(git3_repository_open(&wtrepo, WORKTREE_REPO));
	cl_assert_equal_s(git3_repository_path(wtrepo), cl_git_sandbox_path(1, COMMON_REPO, "worktrees", "name", NULL));

	cl_assert_equal_s(git3_repository_commondir(g_repo), git3_repository_commondir(wtrepo));
	cl_assert_equal_s(git3_repository_workdir(wtrepo), cl_git_sandbox_path(1, WORKTREE_REPO, NULL));

	git3_repository_free(wtrepo);
	git3_worktree_free(wt);
}
