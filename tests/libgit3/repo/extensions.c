#include "clar_libgit3.h"
#include "futils.h"
#include "sysdir.h"
#include <ctype.h>

static git3_repository *repo;

void test_repo_extensions__initialize(void)
{
	git3_config *config;

	repo = cl_git_sandbox_init("empty_bare.git");

	cl_git_pass(git3_repository_config(&config, repo));
	cl_git_pass(git3_config_set_int32(config, "core.repositoryformatversion", 1));
	git3_config_free(config);
}

void test_repo_extensions__cleanup(void)
{
	cl_git_sandbox_cleanup();
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_EXTENSIONS, NULL, 0));
}

void test_repo_extensions__builtin(void)
{
	git3_repository *extended;

	cl_repo_set_string(repo, "extensions.noop", "foobar");

	cl_git_pass(git3_repository_open(&extended, "empty_bare.git"));
	cl_assert(git3_repository_path(extended) != NULL);
	cl_assert(git3__suffixcmp(git3_repository_path(extended), "/") == 0);
	git3_repository_free(extended);
}

void test_repo_extensions__negate_builtin(void)
{
	const char *in[] = { "foo", "!noop", "baz" };
	git3_repository *extended;

	cl_repo_set_string(repo, "extensions.noop", "foobar");

	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_EXTENSIONS, in, ARRAY_SIZE(in)));

	cl_git_fail(git3_repository_open(&extended, "empty_bare.git"));
	git3_repository_free(extended);
}

void test_repo_extensions__unsupported(void)
{
	git3_repository *extended = NULL;

	cl_repo_set_string(repo, "extensions.unknown", "foobar");

	cl_git_fail(git3_repository_open(&extended, "empty_bare.git"));
	git3_repository_free(extended);
}

void test_repo_extensions__adds_extension(void)
{
	const char *in[] = { "foo", "!noop", "newextension", "baz" };
	git3_repository *extended;

	cl_repo_set_string(repo, "extensions.newextension", "foobar");
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_SET_EXTENSIONS, in, ARRAY_SIZE(in)));

	cl_git_pass(git3_repository_open(&extended, "empty_bare.git"));
	cl_assert(git3_repository_path(extended) != NULL);
	cl_assert(git3__suffixcmp(git3_repository_path(extended), "/") == 0);
	git3_repository_free(extended);
}

void test_repo_extensions__preciousobjects(void)
{
	git3_repository *extended = NULL;

	cl_repo_set_string(repo, "extensions.preciousObjects", "true");

	cl_git_pass(git3_repository_open(&extended, "empty_bare.git"));
	git3_repository_free(extended);
}
