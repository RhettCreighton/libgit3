#include "clar_libgit3.h"
#include "git3/attr.h"

void test_attr_flags__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_attr_flags__bare(void)
{
	git3_repository *repo = cl_git_sandbox_init("testrepo.git");
	const char *value;

	cl_assert(git3_repository_is_bare(repo));

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM, "README.md", "diff"));
	cl_assert(GIT3_ATTR_IS_UNSPECIFIED(value));
}

void test_attr_flags__index_vs_workdir(void)
{
	git3_repository *repo = cl_git_sandbox_init("attr_index");
	const char *value;

	cl_assert(!git3_repository_is_bare(repo));

	/* wd then index */
	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_FILE_THEN_INDEX,
		"README.md", "bar"));
	cl_assert(GIT3_ATTR_IS_FALSE(value));

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_FILE_THEN_INDEX,
		"README.md", "blargh"));
	cl_assert_equal_s(value, "goop");

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_FILE_THEN_INDEX,
		"README.txt", "foo"));
	cl_assert(GIT3_ATTR_IS_FALSE(value));

	/* index then wd */
	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_INDEX_THEN_FILE,
		"README.md", "bar"));
	cl_assert(GIT3_ATTR_IS_TRUE(value));

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_INDEX_THEN_FILE,
		"README.md", "blargh"));
	cl_assert_equal_s(value, "garble");

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_INDEX_THEN_FILE,
		"README.txt", "foo"));
	cl_assert(GIT3_ATTR_IS_TRUE(value));
}

void test_attr_flags__subdir(void)
{
	git3_repository *repo = cl_git_sandbox_init("attr_index");
	const char *value;

	/* wd then index */
	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_FILE_THEN_INDEX,
		"sub/sub/README.md", "bar"));
	cl_assert_equal_s(value, "1234");

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_FILE_THEN_INDEX,
		"sub/sub/README.txt", "another"));
	cl_assert_equal_s(value, "one");

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_FILE_THEN_INDEX,
		"sub/sub/README.txt", "again"));
	cl_assert(GIT3_ATTR_IS_TRUE(value));

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_FILE_THEN_INDEX,
		"sub/sub/README.txt", "beep"));
	cl_assert_equal_s(value, "10");

	/* index then wd */
	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_INDEX_THEN_FILE,
		"sub/sub/README.md", "bar"));
	cl_assert_equal_s(value, "1337");

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_INDEX_THEN_FILE,
		"sub/sub/README.txt", "another"));
	cl_assert_equal_s(value, "one");

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_INDEX_THEN_FILE,
		"sub/sub/README.txt", "again"));
	cl_assert(GIT3_ATTR_IS_TRUE(value));

	cl_git_pass(git3_attr_get(
		&value, repo, GIT3_ATTR_CHECK_NO_SYSTEM | GIT3_ATTR_CHECK_INDEX_THEN_FILE,
		"sub/sub/README.txt", "beep"));
	cl_assert_equal_s(value, "5");
}

