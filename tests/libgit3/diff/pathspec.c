#include "clar_libgit3.h"
#include "diff_helpers.h"

static git3_repository *g_repo = NULL;

void test_diff_pathspec__initialize(void)
{
	g_repo = cl_git_sandbox_init("status");
}

void test_diff_pathspec__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_diff_pathspec__0(void)
{
	const char *a_commit = "26a125ee"; /* the current HEAD */
	const char *b_commit = "0017bd4a"; /* the start */
	git3_tree *a = resolve_commit_oid_to_tree(g_repo, a_commit);
	git3_tree *b = resolve_commit_oid_to_tree(g_repo, b_commit);
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff *diff = NULL;
	git3_strarray paths = { NULL, 1 };
	char *path;
	git3_pathspec *ps;
	git3_pathspec_match_list *matches;

	cl_assert(a);
	cl_assert(b);

	path = "*_file";
	paths.strings = &path;
	cl_git_pass(git3_pathspec_new(&ps, &paths));

	cl_git_pass(git3_pathspec_match_tree(&matches, a, GIT3_PATHSPEC_DEFAULT, ps));
	cl_assert_equal_i(7, (int)git3_pathspec_match_list_entrycount(matches));
	cl_assert_equal_s("current_file", git3_pathspec_match_list_entry(matches,0));
	cl_assert(git3_pathspec_match_list_diff_entry(matches,0) == NULL);
	git3_pathspec_match_list_free(matches);

	cl_git_pass(git3_diff_tree_to_tree(&diff, g_repo, NULL, a, &opts));

	cl_git_pass(git3_pathspec_match_diff(
		&matches, diff, GIT3_PATHSPEC_DEFAULT, ps));
	cl_assert_equal_i(7, (int)git3_pathspec_match_list_entrycount(matches));
	cl_assert(git3_pathspec_match_list_diff_entry(matches, 0) != NULL);
	cl_assert(git3_pathspec_match_list_entry(matches, 0) == NULL);
	cl_assert_equal_s("current_file",
		git3_pathspec_match_list_diff_entry(matches,0)->new_file.path);
	cl_assert_equal_i(GIT3_DELTA_ADDED,
		(int)git3_pathspec_match_list_diff_entry(matches,0)->status);
	git3_pathspec_match_list_free(matches);

	git3_diff_free(diff);
	diff = NULL;

	cl_git_pass(git3_diff_tree_to_tree(&diff, g_repo, a, b, &opts));

	cl_git_pass(git3_pathspec_match_diff(
		&matches, diff, GIT3_PATHSPEC_DEFAULT, ps));
	cl_assert_equal_i(3, (int)git3_pathspec_match_list_entrycount(matches));
	cl_assert(git3_pathspec_match_list_diff_entry(matches, 0) != NULL);
	cl_assert(git3_pathspec_match_list_entry(matches, 0) == NULL);
	cl_assert_equal_s("subdir/current_file",
		git3_pathspec_match_list_diff_entry(matches,0)->new_file.path);
	cl_assert_equal_i(GIT3_DELTA_DELETED,
		(int)git3_pathspec_match_list_diff_entry(matches,0)->status);
	git3_pathspec_match_list_free(matches);

	git3_diff_free(diff);
	diff = NULL;

	cl_git_pass(git3_diff_tree_to_workdir(&diff, g_repo, a, &opts));

	cl_git_pass(git3_pathspec_match_diff(
		&matches, diff, GIT3_PATHSPEC_DEFAULT, ps));
	cl_assert_equal_i(4, (int)git3_pathspec_match_list_entrycount(matches));
	cl_assert(git3_pathspec_match_list_diff_entry(matches, 0) != NULL);
	cl_assert(git3_pathspec_match_list_entry(matches, 0) == NULL);
	cl_assert_equal_s("modified_file",
		git3_pathspec_match_list_diff_entry(matches,0)->new_file.path);
	cl_assert_equal_i(GIT3_DELTA_MODIFIED,
		(int)git3_pathspec_match_list_diff_entry(matches,0)->status);
	git3_pathspec_match_list_free(matches);

	git3_diff_free(diff);
	diff = NULL;

	git3_tree_free(a);
	git3_tree_free(b);
	git3_pathspec_free(ps);
}
