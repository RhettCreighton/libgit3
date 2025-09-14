#include "clar_libgit3.h"
#include "branch.h"

static git3_repository *repo;
static git3_buf upstream_name;

void test_refs_branches_upstreamname__initialize(void)
{
	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));

}

void test_refs_branches_upstreamname__cleanup(void)
{
	git3_buf_dispose(&upstream_name);

	git3_repository_free(repo);
	repo = NULL;
}

void test_refs_branches_upstreamname__can_retrieve_the_remote_tracking_reference_name_of_a_local_branch(void)
{
	cl_git_pass(git3_branch_upstream_name(
		&upstream_name, repo, "refs/heads/master"));

	cl_assert_equal_s("refs/remotes/test/master", upstream_name.ptr);
}

void test_refs_branches_upstreamname__can_retrieve_the_local_upstream_reference_name_of_a_local_branch(void)
{
	cl_git_pass(git3_branch_upstream_name(
		&upstream_name, repo, "refs/heads/track-local"));

	cl_assert_equal_s("refs/heads/master", upstream_name.ptr);
}
