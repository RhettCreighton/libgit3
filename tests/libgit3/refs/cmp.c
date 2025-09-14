#include "clar_libgit3.h"
#include "refs.h"

static git3_repository *g_repo;

void test_refs_cmp__initialize(void)
{
	g_repo = cl_git_sandbox_init("testrepo2");
}

void test_refs_cmp__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_refs_cmp__symbolic(void)
{
	git3_reference *one, *two;

	cl_git_pass(git3_reference_lookup(&one, g_repo, "refs/heads/symbolic-one"));
	cl_git_pass(git3_reference_lookup(&two, g_repo, "refs/heads/symbolic-two"));

	cl_assert(git3_reference_cmp(one, two) != 0);

	git3_reference_free(one);
	git3_reference_free(two);
}
