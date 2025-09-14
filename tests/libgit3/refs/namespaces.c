#include "clar_libgit3.h"

#include "repository.h"

static git3_repository *g_repo;

void test_refs_namespaces__initialize(void)
{
	g_repo = cl_git_sandbox_init("testrepo");
}

void test_refs_namespaces__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_refs_namespaces__get_and_set(void)
{
	cl_assert_equal_s(NULL, git3_repository_get_namespace(g_repo));

	cl_git_pass(git3_repository_set_namespace(g_repo, "namespace"));
	cl_assert_equal_s("namespace", git3_repository_get_namespace(g_repo));

	cl_git_pass(git3_repository_set_namespace(g_repo, NULL));
	cl_assert_equal_s(NULL, git3_repository_get_namespace(g_repo));
}

void test_refs_namespaces__namespace_doesnt_show_normal_refs(void)
{
	static git3_strarray ref_list;

	cl_git_pass(git3_repository_set_namespace(g_repo, "namespace"));
	cl_git_pass(git3_reference_list(&ref_list, g_repo));
	cl_assert_equal_i(0, ref_list.count);
	git3_strarray_dispose(&ref_list);
}
