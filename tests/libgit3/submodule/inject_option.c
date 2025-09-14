#include "clar_libgit3.h"
#include "posix.h"
#include "path.h"
#include "submodule_helpers.h"
#include "futils.h"
#include "repository.h"

static git3_repository *g_repo = NULL;

void test_submodule_inject_option__initialize(void)
{
	g_repo = setup_fixture_submodule_simple();
}

void test_submodule_inject_option__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

static int find_naughty(git3_submodule *sm, const char *name, void *payload)
{
	int *foundit = (int *) payload;

	GIT3_UNUSED(sm);

	if (!git3__strcmp("naughty", name))
		*foundit = true;

	return 0;
}

void test_submodule_inject_option__url(void)
{
	int foundit;
	git3_submodule *sm;
	git3_str buf = GIT3_STR_INIT;

	cl_git_pass(git3_str_joinpath(&buf, git3_repository_workdir(g_repo), ".gitmodules"));
	cl_git_rewritefile(buf.ptr,
			   "[submodule \"naughty\"]\n"
			   "    path = testrepo\n"
			   "    url = -u./payload\n");
	git3_str_dispose(&buf);

	/* We do want to find it, but with the appropriate field empty */
	foundit = 0;
	cl_git_pass(git3_submodule_foreach(g_repo, find_naughty, &foundit));
	cl_assert_equal_i(1, foundit);

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "naughty"));
	cl_assert_equal_s("testrepo", git3_submodule_path(sm));
	cl_assert_equal_p(NULL, git3_submodule_url(sm));

	git3_submodule_free(sm);
}

void test_submodule_inject_option__path(void)
{
	int foundit;
	git3_submodule *sm;
	git3_str buf = GIT3_STR_INIT;

	cl_git_pass(git3_str_joinpath(&buf, git3_repository_workdir(g_repo), ".gitmodules"));
	cl_git_rewritefile(buf.ptr,
			   "[submodule \"naughty\"]\n"
			   "    path = --something\n"
			   "    url = blah.git\n");
	git3_str_dispose(&buf);

	/* We do want to find it, but with the appropriate field empty */
	foundit = 0;
	cl_git_pass(git3_submodule_foreach(g_repo, find_naughty, &foundit));
	cl_assert_equal_i(1, foundit);

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, "naughty"));
	cl_assert_equal_s("naughty", git3_submodule_path(sm));
	cl_assert_equal_s("blah.git", git3_submodule_url(sm));

	git3_submodule_free(sm);
}
