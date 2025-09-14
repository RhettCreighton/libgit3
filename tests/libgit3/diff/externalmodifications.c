#include "clar_libgit3.h"
#include "../checkout/checkout_helpers.h"

#include "index.h"
#include "repository.h"

static git3_repository *g_repo;

void test_diff_externalmodifications__initialize(void)
{
	g_repo = cl_git_sandbox_init("testrepo2");
}

void test_diff_externalmodifications__cleanup(void)
{
	cl_git_sandbox_cleanup();
	g_repo = NULL;
}

void test_diff_externalmodifications__file_becomes_smaller(void)
{
	git3_index *index;
	git3_diff *diff;
	git3_patch* patch;
	git3_str path = GIT3_STR_INIT;
	char big_string[500001];

	cl_git_pass(git3_str_joinpath(&path, git3_repository_workdir(g_repo), "README"));

	/* Modify the file with a large string */
	memset(big_string, '\n', sizeof(big_string) - 1);
	big_string[sizeof(big_string) - 1] = '\0';
	cl_git_mkfile(path.ptr, big_string);

	/* Get a diff */
	cl_git_pass(git3_repository_index(&index, g_repo));
	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, index, NULL));
	cl_assert_equal_i(1, git3_diff_num_deltas(diff));
	cl_assert_equal_i(500000, git3_diff_get_delta(diff, 0)->new_file.size);

	/* Simulate file modification after we've gotten the diff.
	 * Write a shorter string to ensure that we don't mmap 500KB from
	 * the previous revision, which would most likely crash. */
	cl_git_mkfile(path.ptr, "hello");

	/* Attempt to get a patch */
	cl_git_fail(git3_patch_from_diff(&patch, diff, 0));

	git3_index_free(index);
	git3_diff_free(diff);
	git3_str_dispose(&path);
}

void test_diff_externalmodifications__file_becomes_empty(void)
{
	git3_index *index;
	git3_diff *diff;
	git3_patch* patch;
	git3_str path = GIT3_STR_INIT;

	cl_git_pass(git3_str_joinpath(&path, git3_repository_workdir(g_repo), "README"));

	/* Modify the file */
	cl_git_mkfile(path.ptr, "hello");

	/* Get a diff */
	cl_git_pass(git3_repository_index(&index, g_repo));
	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, index, NULL));
	cl_assert_equal_i(1, git3_diff_num_deltas(diff));
	cl_assert_equal_i(5, git3_diff_get_delta(diff, 0)->new_file.size);

	/* Empty out the file after we've gotten the diff */
	cl_git_mkfile(path.ptr, "");

	/* Attempt to get a patch */
	cl_git_fail(git3_patch_from_diff(&patch, diff, 0));

	git3_index_free(index);
	git3_diff_free(diff);
	git3_str_dispose(&path);
}

void test_diff_externalmodifications__file_deleted(void)
{
	git3_index *index;
	git3_diff *diff;
	git3_patch* patch;
	git3_str path = GIT3_STR_INIT;

	cl_git_pass(git3_str_joinpath(&path, git3_repository_workdir(g_repo), "README"));

	/* Get a diff */
	cl_git_pass(git3_repository_index(&index, g_repo));
	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, index, NULL));
	cl_assert_equal_i(0, git3_diff_num_deltas(diff));

	/* Delete the file */
	cl_git_rmfile(path.ptr);

	/* Attempt to get a patch */
	cl_git_fail(git3_patch_from_diff(&patch, diff, 0));

	git3_index_free(index);
	git3_diff_free(diff);
	git3_str_dispose(&path);
}

void test_diff_externalmodifications__empty_file_becomes_non_empty(void)
{
	git3_index *index;
	git3_diff *diff;
	git3_patch* patch;
	git3_str path = GIT3_STR_INIT;

	cl_git_pass(git3_str_joinpath(&path, git3_repository_workdir(g_repo), "README"));

	/* Empty out the file */
	cl_git_mkfile(path.ptr, "");

	/* Get a diff */
	cl_git_pass(git3_repository_index(&index, g_repo));
	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, index, NULL));
	cl_assert_equal_i(1, git3_diff_num_deltas(diff));
	cl_assert_equal_i(0, git3_diff_get_delta(diff, 0)->new_file.size);

	/* Simulate file modification after we've gotten the diff */
	cl_git_mkfile(path.ptr, "hello");
	cl_git_fail(git3_patch_from_diff(&patch, diff, 0));

	git3_index_free(index);
	git3_diff_free(diff);
	git3_str_dispose(&path);
}
