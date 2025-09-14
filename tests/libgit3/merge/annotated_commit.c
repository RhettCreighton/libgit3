#include "clar_libgit3.h"


static git3_repository *g_repo;

void test_merge_annotated_commit__initialize(void)
{
	g_repo = cl_git_sandbox_init("testrepo");
}

void test_merge_annotated_commit__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_merge_annotated_commit__lookup_annotated_tag(void)
{
	git3_annotated_commit *commit;
	git3_reference *ref;

	cl_git_pass(git3_reference_lookup(&ref, g_repo, "refs/tags/test"));
	cl_git_pass(git3_annotated_commit_from_ref(&commit, g_repo, ref));

	git3_annotated_commit_free(commit);
	git3_reference_free(ref);
}
