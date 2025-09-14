#include "clar_libgit3.h"
#include "repository.h"
#include "repo_helpers.h"
#include "posix.h"

static git3_repository *repo;
static git3_tree *tree;

void test_repo_headtree__initialize(void)
{
	repo = cl_git_sandbox_init("testrepo.git");
	tree = NULL;
}

void test_repo_headtree__cleanup(void)
{
	git3_tree_free(tree);
	cl_git_sandbox_cleanup();
}

void test_repo_headtree__can_retrieve_the_root_tree_from_a_detached_head(void)
{
	cl_git_pass(git3_repository_detach_head(repo));

	cl_git_pass(git3_repository_head_tree(&tree, repo));

	cl_assert(git3_oid_streq(git3_tree_id(tree), "az"));
}

void test_repo_headtree__can_retrieve_the_root_tree_from_a_non_detached_head(void)
{
	cl_assert_equal_i(false, git3_repository_head_detached(repo));

	cl_git_pass(git3_repository_head_tree(&tree, repo));

	cl_assert(git3_oid_streq(git3_tree_id(tree), "az"));
}

void test_repo_headtree__when_head_is_unborn_returns_EUNBORNBRANCH(void)
{
	make_head_unborn(repo, NON_EXISTING_HEAD);

	cl_assert_equal_i(true, git3_repository_head_unborn(repo));

	cl_assert_equal_i(GIT3_EUNBORNBRANCH, git3_repository_head_tree(&tree, repo));
}

void test_repo_headtree__when_head_is_missing_returns_ENOTFOUND(void)
{
	delete_head(repo);

	cl_assert_equal_i(GIT3_ENOTFOUND, git3_repository_head_tree(&tree, repo));
}
