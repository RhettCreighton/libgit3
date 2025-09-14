#include "clar_libgit3.h"

#include "repository.h"

static void assert_shorthand(git3_repository *repo, const char *refname, const char *shorthand)
{
	git3_reference *ref;

	cl_git_pass(git3_reference_lookup(&ref, repo, refname));
	cl_assert_equal_s(git3_reference_shorthand(ref), shorthand);
	git3_reference_free(ref);
}

void test_refs_shorthand__0(void)
{
	git3_repository *repo;

	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));


	assert_shorthand(repo, "refs/heads/master", "master");
	assert_shorthand(repo, "refs/tags/test", "test");
	assert_shorthand(repo, "refs/remotes/test/master", "test/master");
	assert_shorthand(repo, "refs/notes/fanout", "notes/fanout");

	git3_repository_free(repo);
}
