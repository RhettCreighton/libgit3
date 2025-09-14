#include "clar_libgit3.h"
#include "path.h"

void test_path_validate__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_path_validate__length(void)
{
	cl_must_pass(git3_path_validate_length(NULL, "/foo/bar"));
	cl_must_pass(git3_path_validate_length(NULL, "C:\\Foo\\Bar"));
	cl_must_pass(git3_path_validate_length(NULL, "\\\\?\\C:\\Foo\\Bar"));
	cl_must_pass(git3_path_validate_length(NULL, "\\\\?\\C:\\Foo\\Bar"));
	cl_must_pass(git3_path_validate_length(NULL, "\\\\?\\UNC\\server\\C$\\folder"));

#ifdef GIT3_WIN32
	/*
	 * In the absence of a repo configuration, 259 character paths
	 * succeed. >= 260 character paths fail.
	 */
	cl_must_pass(git3_path_validate_length(NULL, "C:\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\ok.txt"));
	cl_must_pass(git3_path_validate_length(NULL, "C:\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\260.txt"));
	cl_must_fail(git3_path_validate_length(NULL, "C:\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\longer_than_260.txt"));

	/* count characters, not bytes */
	cl_must_pass(git3_path_validate_length(NULL, "C:\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\\260.txt"));
	cl_must_fail(git3_path_validate_length(NULL, "C:\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\\long.txt"));
#else
	cl_must_pass(git3_path_validate_length(NULL, "/c/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/ok.txt"));
	cl_must_pass(git3_path_validate_length(NULL, "/c/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/260.txt"));
	cl_must_pass(git3_path_validate_length(NULL, "/c/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/longer_than_260.txt"));
	cl_must_pass(git3_path_validate_length(NULL, "C:\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\\260.txt"));
	cl_must_pass(git3_path_validate_length(NULL, "C:\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\aaaaaaaaa\\\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\xc2\xa2\\long.txt"));
#endif
}

void test_path_validate__length_with_core_longpath(void)
{
#ifdef GIT3_WIN32
	git3_repository *repo;
	git3_config *config;

	repo = cl_git_sandbox_init("empty_bare.git");

	cl_git_pass(git3_repository_open(&repo, "empty_bare.git"));
	cl_git_pass(git3_repository_config(&config, repo));

	/* fail by default */
	cl_must_fail(git3_path_validate_length(repo, "/c/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/longer_than_260.txt"));

	/* set core.longpaths explicitly on */
	cl_git_pass(git3_config_set_bool(config, "core.longpaths", 1));
	cl_must_pass(git3_path_validate_length(repo, "/c/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/longer_than_260.txt"));

	/* set core.longpaths explicitly off */
	cl_git_pass(git3_config_set_bool(config, "core.longpaths", 0));
	cl_must_fail(git3_path_validate_length(repo, "/c/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/aaaaaaaaa/longer_than_260.txt"));

	git3_config_free(config);
	git3_repository_free(repo);
#endif
}
