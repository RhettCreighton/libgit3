#include "clar_libgit3.h"
#include "../diff/diff_helpers.h"

static git3_repository *g_repo = NULL;

void test_stress_diff__initialize(void)
{
}

void test_stress_diff__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

#define ANOTHER_POEM \
"OH, glorious are the guarded heights\nWhere guardian souls abide—\nSelf-exiled from our gross delights—\nAbove, beyond, outside:\nAn ampler arc their spirit swings—\nCommands a juster view—\nWe have their word for all these things,\nNo doubt their words are true.\n\nYet we, the bond slaves of our day,\nWhom dirt and danger press—\nCo-heirs of insolence, delay,\nAnd leagued unfaithfulness—\nSuch is our need must seek indeed\nAnd, having found, engage\nThe men who merely do the work\nFor which they draw the wage.\n\nFrom forge and farm and mine and bench,\nDeck, altar, outpost lone—\nMill, school, battalion, counter, trench,\nRail, senate, sheepfold, throne—\nCreation's cry goes up on high\nFrom age to cheated age:\n\"Send us the men who do the work\n\"For which they draw the wage!\"\n"

static void test_with_many(int expected_new)
{
	git3_index *index;
	git3_tree *tree, *new_tree;
	git3_diff *diff = NULL;
	diff_expects exp;
	git3_diff_options diffopts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff_find_options opts = GIT3_DIFF_FIND_OPTIONS_INIT;

	cl_git_pass(git3_repository_index(&index, g_repo));
	cl_git_pass(
		git3_revparse_single((git3_object **)&tree, g_repo, "HEAD^{tree}"));

	cl_git_pass(p_rename("renames/ikeepsix.txt", "renames/ikeepsix2.txt"));
	cl_git_pass(git3_index_remove_bypath(index, "ikeepsix.txt"));
	cl_git_pass(git3_index_add_bypath(index, "ikeepsix2.txt"));
	cl_git_pass(git3_index_write(index));

	cl_git_pass(git3_diff_tree_to_index(&diff, g_repo, tree, index, &diffopts));

	memset(&exp, 0, sizeof(exp));
	cl_git_pass(git3_diff_foreach(
		diff, diff_file_cb, NULL, NULL, NULL, &exp));
	cl_assert_equal_i(1, exp.file_status[GIT3_DELTA_DELETED]);
	cl_assert_equal_i(expected_new + 1, exp.file_status[GIT3_DELTA_ADDED]);
	cl_assert_equal_i(expected_new + 2, exp.files);

	opts.flags = GIT3_DIFF_FIND_ALL;
	cl_git_pass(git3_diff_find_similar(diff, &opts));

	memset(&exp, 0, sizeof(exp));
	cl_git_pass(git3_diff_foreach(
		diff, diff_file_cb, NULL, NULL, NULL, &exp));
	cl_assert_equal_i(1, exp.file_status[GIT3_DELTA_RENAMED]);
	cl_assert_equal_i(expected_new, exp.file_status[GIT3_DELTA_ADDED]);
	cl_assert_equal_i(expected_new + 1, exp.files);

	git3_diff_free(diff);

	cl_repo_commit_from_index(NULL, g_repo, NULL, 1372350000, "yoyoyo");
	cl_git_pass(git3_revparse_single(
		(git3_object **)&new_tree, g_repo, "HEAD^{tree}"));

	cl_git_pass(git3_diff_tree_to_tree(
		&diff, g_repo, tree, new_tree, &diffopts));

	memset(&exp, 0, sizeof(exp));
	cl_git_pass(git3_diff_foreach(
		diff, diff_file_cb, NULL, NULL, NULL, &exp));
	cl_assert_equal_i(1, exp.file_status[GIT3_DELTA_DELETED]);
	cl_assert_equal_i(expected_new + 1, exp.file_status[GIT3_DELTA_ADDED]);
	cl_assert_equal_i(expected_new + 2, exp.files);

	opts.flags = GIT3_DIFF_FIND_ALL;
	cl_git_pass(git3_diff_find_similar(diff, &opts));

	memset(&exp, 0, sizeof(exp));
	cl_git_pass(git3_diff_foreach(
		diff, diff_file_cb, NULL, NULL, NULL, &exp));
	cl_assert_equal_i(1, exp.file_status[GIT3_DELTA_RENAMED]);
	cl_assert_equal_i(expected_new, exp.file_status[GIT3_DELTA_ADDED]);
	cl_assert_equal_i(expected_new + 1, exp.files);

	git3_diff_free(diff);

	git3_tree_free(new_tree);
	git3_tree_free(tree);
	git3_index_free(index);
}

void test_stress_diff__rename_big_files(void)
{
	git3_index *index;
	char tmp[64];
	int i, j;
	git3_str b = GIT3_STR_INIT;

	g_repo = cl_git_sandbox_init("renames");

	cl_git_pass(git3_repository_index(&index, g_repo));

	for (i = 0; i < 100; i += 1) {
		p_snprintf(tmp, sizeof(tmp), "renames/newfile%03d", i);
		for (j = i * 256; j > 0; --j)
			git3_str_printf(&b, "more content %d\n", i);
		cl_git_mkfile(tmp, b.ptr);
	}

	for (i = 0; i < 100; i += 1) {
		p_snprintf(tmp, sizeof(tmp), "renames/newfile%03d", i);
		cl_git_pass(git3_index_add_bypath(index, tmp + strlen("renames/")));
	}

	git3_str_dispose(&b);
	git3_index_free(index);

	test_with_many(100);
}

void test_stress_diff__rename_many_files(void)
{
	git3_index *index;
	char tmp[64];
	int i;
	git3_str b = GIT3_STR_INIT;

	g_repo = cl_git_sandbox_init("renames");

	cl_git_pass(git3_repository_index(&index, g_repo));

	git3_str_printf(&b, "%08d\n" ANOTHER_POEM "%08d\n" ANOTHER_POEM ANOTHER_POEM, 0, 0);

	for (i = 0; i < 2500; i += 1) {
		p_snprintf(tmp, sizeof(tmp), "renames/newfile%03d", i);
		p_snprintf(b.ptr, 9, "%08d", i);
		b.ptr[8] = '\n';
		cl_git_mkfile(tmp, b.ptr);
	}
	git3_str_dispose(&b);

	for (i = 0; i < 2500; i += 1) {
		p_snprintf(tmp, sizeof(tmp), "renames/newfile%03d", i);
		cl_git_pass(git3_index_add_bypath(index, tmp + strlen("renames/")));
	}

	git3_index_free(index);

	test_with_many(2500);
}
