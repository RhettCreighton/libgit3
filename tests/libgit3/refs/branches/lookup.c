#include "clar_libgit3.h"
#include "refs.h"

static git3_repository *repo;
static git3_reference *branch;

void test_refs_branches_lookup__initialize(void)
{
	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));

	branch = NULL;
}

void test_refs_branches_lookup__cleanup(void)
{
	git3_reference_free(branch);
	branch = NULL;

	git3_repository_free(repo);
	repo = NULL;
}

void test_refs_branches_lookup__can_retrieve_a_local_branch_local(void)
{
	cl_git_pass(git3_branch_lookup(&branch, repo, "br2", GIT3_BRANCH_LOCAL));
}

void test_refs_branches_lookup__can_retrieve_a_local_branch_all(void)
{
	cl_git_pass(git3_branch_lookup(&branch, repo, "br2", GIT3_BRANCH_ALL));
}

void test_refs_branches_lookup__trying_to_retrieve_a_local_branch_remote(void)
{
	cl_git_fail(git3_branch_lookup(&branch, repo, "br2", GIT3_BRANCH_REMOTE));
}

void test_refs_branches_lookup__can_retrieve_a_remote_tracking_branch_remote(void)
{
	cl_git_pass(git3_branch_lookup(&branch, repo, "test/master", GIT3_BRANCH_REMOTE));
}

void test_refs_branches_lookup__can_retrieve_a_remote_tracking_branch_all(void)
{
	cl_git_pass(git3_branch_lookup(&branch, repo, "test/master", GIT3_BRANCH_ALL));
}

void test_refs_branches_lookup__trying_to_retrieve_a_remote_tracking_branch_local(void)
{
	cl_git_fail(git3_branch_lookup(&branch, repo, "test/master", GIT3_BRANCH_LOCAL));
}

void test_refs_branches_lookup__trying_to_retrieve_an_unknown_branch_returns_ENOTFOUND(void)
{
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_branch_lookup(&branch, repo, "where/are/you", GIT3_BRANCH_LOCAL));
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_branch_lookup(&branch, repo, "over/here", GIT3_BRANCH_REMOTE));
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_branch_lookup(&branch, repo, "maybe/here", GIT3_BRANCH_ALL));
}

void test_refs_branches_lookup__trying_to_retrieve_a_branch_with_an_invalid_name_returns_EINVALIDSPEC(void)
{
	cl_assert_equal_i(GIT3_EINVALIDSPEC,
		git3_branch_lookup(&branch, repo, "are/you/inv@{id", GIT3_BRANCH_LOCAL));
	cl_assert_equal_i(GIT3_EINVALIDSPEC,
		git3_branch_lookup(&branch, repo, "yes/i am", GIT3_BRANCH_REMOTE));
	cl_assert_equal_i(GIT3_EINVALIDSPEC,
		git3_branch_lookup(&branch, repo, "inv al/id", GIT3_BRANCH_ALL));
}
