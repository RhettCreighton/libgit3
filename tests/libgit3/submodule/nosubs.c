/* test the submodule APIs on repositories where there are no submodules */

#include "clar_libgit3.h"
#include "posix.h"
#include "futils.h"

void test_submodule_nosubs__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_submodule_nosubs__lookup(void)
{
	git3_repository *repo = cl_git_sandbox_init("status");
	git3_submodule *sm = NULL;

	p_mkdir("status/subrepo", 0777);
	cl_git_mkfile("status/subrepo/.git", "gitdir: ../.git");

	cl_assert_equal_i(GIT3_ENOTFOUND, git3_submodule_lookup(&sm, repo, "subdir"));

	cl_assert_equal_i(GIT3_EEXISTS, git3_submodule_lookup(&sm, repo, "subrepo"));

	cl_assert_equal_i(GIT3_ENOTFOUND, git3_submodule_lookup(&sm, repo, "subdir"));

	cl_assert_equal_i(GIT3_EEXISTS, git3_submodule_lookup(&sm, repo, "subrepo"));
}

static int fake_submod_cb(git3_submodule *sm, const char *n, void *p)
{
	GIT3_UNUSED(sm); GIT3_UNUSED(n); GIT3_UNUSED(p);
	return 0;
}

void test_submodule_nosubs__foreach(void)
{
	git3_repository *repo = cl_git_sandbox_init("status");
	cl_git_pass(git3_submodule_foreach(repo, fake_submod_cb, NULL));
}

void test_submodule_nosubs__add(void)
{
	git3_repository *repo = cl_git_sandbox_init("status");
	git3_submodule *sm, *sm2;

	cl_git_pass(git3_submodule_add_setup(&sm, repo, "https://github.com/libgit3/libgit3.git", "submodules/libgit3", 1));

	cl_git_pass(git3_submodule_lookup(&sm2, repo, "submodules/libgit3"));
	git3_submodule_free(sm2);

	cl_git_pass(git3_submodule_foreach(repo, fake_submod_cb, NULL));

	git3_submodule_free(sm);
}

void test_submodule_nosubs__bad_gitmodules(void)
{
	git3_repository *repo = cl_git_sandbox_init("status");

	cl_git_mkfile("status/.gitmodules", "[submodule \"foobar\"]\tpath=blargle\n\turl=\n\tbranch=\n\tupdate=flooble\n\n");

	cl_git_rewritefile("status/.gitmodules", "[submodule \"foobar\"]\tpath=blargle\n\turl=\n\tbranch=\n\tupdate=rebase\n\n");

	cl_git_pass(git3_submodule_lookup(NULL, repo, "foobar"));
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_submodule_lookup(NULL, repo, "subdir"));
}

void test_submodule_nosubs__add_and_delete(void)
{
	git3_repository *repo = cl_git_sandbox_init("status");
	git3_submodule *sm;
	git3_str buf = GIT3_STR_INIT;

	cl_git_fail(git3_submodule_lookup(NULL, repo, "libgit3"));
	cl_git_fail(git3_submodule_lookup(NULL, repo, "submodules/libgit3"));

	/* create */

	cl_git_pass(git3_submodule_add_setup(
		&sm, repo, "https://github.com/libgit3/libgit3.git", "submodules/libgit3", 1));
	cl_assert_equal_s("submodules/libgit3", git3_submodule_name(sm));
	cl_assert_equal_s("submodules/libgit3", git3_submodule_path(sm));
	git3_submodule_free(sm);

	cl_git_pass(git3_futils_readbuffer(&buf, "status/.gitmodules"));
	cl_assert(strstr(buf.ptr, "[submodule \"submodules/libgit3\"]") != NULL);
	cl_assert(strstr(buf.ptr, "path = submodules/libgit3") != NULL);
	git3_str_dispose(&buf);

	/* lookup */

	cl_git_fail(git3_submodule_lookup(&sm, repo, "libgit3"));
	cl_git_pass(git3_submodule_lookup(&sm, repo, "submodules/libgit3"));
	cl_assert_equal_s("submodules/libgit3", git3_submodule_name(sm));
	cl_assert_equal_s("submodules/libgit3", git3_submodule_path(sm));
	git3_submodule_free(sm);

	/* update name */

	cl_git_rewritefile(
		"status/.gitmodules",
		"[submodule \"libgit3\"]\n"
		"  path = submodules/libgit3\n"
		"  url = https://github.com/libgit3/libgit3.git\n");

	cl_git_pass(git3_submodule_lookup(&sm, repo, "libgit3"));
	cl_assert_equal_s("libgit3", git3_submodule_name(sm));
	cl_assert_equal_s("submodules/libgit3", git3_submodule_path(sm));
	git3_submodule_free(sm);
	cl_git_pass(git3_submodule_lookup(&sm, repo, "submodules/libgit3"));
	git3_submodule_free(sm);

	/* revert name update */

	cl_git_rewritefile(
		"status/.gitmodules",
		"[submodule \"submodules/libgit3\"]\n"
		"  path = submodules/libgit3\n"
		"  url = https://github.com/libgit3/libgit3.git\n");

	cl_git_fail(git3_submodule_lookup(&sm, repo, "libgit3"));
	cl_git_pass(git3_submodule_lookup(&sm, repo, "submodules/libgit3"));
	git3_submodule_free(sm);

	/* remove completely */

	cl_must_pass(p_unlink("status/.gitmodules"));
	cl_git_fail(git3_submodule_lookup(&sm, repo, "libgit3"));
	cl_git_fail(git3_submodule_lookup(&sm, repo, "submodules/libgit3"));
}
