#include "clar_libgit3.h"
#include "config/config_helpers.h"

static git3_repository *_repo;

#define TEST_URL "http://github.com/libgit3/libgit3.git"

void test_remote_list__initialize(void)
{
	_repo = cl_git_sandbox_init("testrepo");
}

void test_remote_list__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_remote_list__always_checks_disk_config(void)
{
	git3_repository *repo;
	git3_strarray remotes;
	git3_remote *remote;

	cl_git_pass(git3_repository_open(&repo, git3_repository_path(_repo)));

	cl_git_pass(git3_remote_list(&remotes, _repo));
	cl_assert_equal_sz(remotes.count, 1);
	git3_strarray_dispose(&remotes);

	cl_git_pass(git3_remote_create(&remote, _repo, "valid-name", TEST_URL));

	cl_git_pass(git3_remote_list(&remotes, _repo));
	cl_assert_equal_sz(remotes.count, 2);
	git3_strarray_dispose(&remotes);

	cl_git_pass(git3_remote_list(&remotes, repo));
	cl_assert_equal_sz(remotes.count, 2);
	git3_strarray_dispose(&remotes);

	git3_repository_free(repo);
	git3_remote_free(remote);
}

