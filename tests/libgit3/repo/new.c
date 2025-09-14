#include "clar_libgit3.h"
#include "git3/sys/repository.h"
#include "repository.h"

void test_repo_new__has_nothing(void)
{
	git3_repository *repo;
	git3_repository_new_options repo_opts = GIT3_REPOSITORY_NEW_OPTIONS_INIT;

	repo_opts.oid_type = GIT3_OID_SHA1;

	cl_git_pass(git3_repository_new_ext(&repo, &repo_opts));
	cl_assert_equal_b(true, git3_repository_is_bare(repo));
	cl_assert_equal_p(NULL, git3_repository_path(repo));
	cl_assert_equal_p(NULL, git3_repository_workdir(repo));
	git3_repository_free(repo);
}

void test_repo_new__is_bare_until_workdir_set(void)
{
	git3_repository *repo;

	git3_repository_new_options repo_opts = GIT3_REPOSITORY_NEW_OPTIONS_INIT;

	repo_opts.oid_type = GIT3_OID_SHA1;

	cl_git_pass(git3_repository_new_ext(&repo, &repo_opts));
	cl_assert_equal_b(true, git3_repository_is_bare(repo));

	cl_git_pass(git3_repository_set_workdir(repo, clar_sandbox_path(), 0));
	cl_assert_equal_b(false, git3_repository_is_bare(repo));

	git3_repository_free(repo);
}

void test_repo_new__sha1(void)
{
	git3_repository *repo;
	git3_repository_new_options repo_opts = GIT3_REPOSITORY_NEW_OPTIONS_INIT;

	repo_opts.oid_type = GIT3_OID_SHA1;

	cl_git_pass(git3_repository_new_ext(&repo, &repo_opts));
	cl_assert_equal_i(GIT3_OID_SHA1, git3_repository_oid_type(repo));

	git3_repository_free(repo);
}

void test_repo_new__sha256(void)
{
#ifndef GIT3_EXPERIMENTAL_SHA256
	cl_skip();
#else
	git3_repository *repo;
	git3_repository_new_options repo_opts = GIT3_REPOSITORY_NEW_OPTIONS_INIT;

	repo_opts.oid_type = GIT3_OID_SHA256;

	cl_git_pass(git3_repository_new_ext(&repo, &repo_opts));
	cl_assert_equal_i(GIT3_OID_SHA256, git3_repository_oid_type(repo));

	git3_repository_free(repo);
#endif
}
