#include "clar_libgit3.h"
#include "repository.h"
#include "posix.h"
#include "diff_helpers.h"
#include "../submodule/submodule_helpers.h"

static git3_repository *g_repo = NULL;

void test_diff_submodules__initialize(void)
{
}

void test_diff_submodules__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

#define get_buf_ptr(buf) ((buf)->size ? (buf)->ptr : NULL)

static void check_diff_patches_at_line(
	git3_diff *diff, const char **expected,
	const char *file, const char *func, int line)
{
	const git3_diff_delta *delta;
	git3_patch *patch = NULL;
	size_t d, num_d = git3_diff_num_deltas(diff);
	git3_buf buf = GIT3_BUF_INIT;

	for (d = 0; d < num_d; ++d, git3_patch_free(patch)) {
		cl_git_pass(git3_patch_from_diff(&patch, diff, d));
		cl_assert((delta = git3_patch_get_delta(patch)) != NULL);

		if (delta->status == GIT3_DELTA_UNMODIFIED) {
			cl_assert_at_line(expected[d] == NULL, file, func, line);
			continue;
		}

		if (expected[d] && !strcmp(expected[d], "<SKIP>"))
			continue;
		if (expected[d] && !strcmp(expected[d], "<UNTRACKED>")) {
			cl_assert_at_line(delta->status == GIT3_DELTA_UNTRACKED, file, func, line);
			continue;
		}
		if (expected[d] && !strcmp(expected[d], "<END>")) {
			cl_git_pass(git3_patch_to_buf(&buf, patch));
			cl_assert_at_line(!strcmp(expected[d], "<END>"), file, func, line);
		}

		cl_git_pass(git3_patch_to_buf(&buf, patch));

		clar__assert_equal(
			file, func, line, "expected diff did not match actual diff", 1,
			"%s", expected[d], get_buf_ptr(&buf));
		git3_buf_dispose(&buf);
	}

	cl_assert_at_line(expected[d] && !strcmp(expected[d], "<END>"), file, func, line);
}

#define check_diff_patches(diff, exp) \
	check_diff_patches_at_line(diff, exp, __FILE__, __func__, __LINE__)

void test_diff_submodules__unmodified_submodule(void)
{
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff *diff = NULL;
	static const char *expected[] = {
		"<SKIP>", /* .gitmodules */
		NULL, /* added */
		NULL, /* ignored */
		"diff --git a/modified b/modified\nindex 092bfb9..452216e 100644\n--- a/modified\n+++ b/modified\n@@ -1 +1,2 @@\n-yo\n+changed\n+\n", /* modified */
		NULL, /* testrepo.git */
		NULL, /* unmodified */
		NULL, /* untracked */
		"<END>"
	};

	g_repo = setup_fixture_submodules();

	opts.flags = GIT3_DIFF_INCLUDE_IGNORED |
		GIT3_DIFF_INCLUDE_UNTRACKED |
		GIT3_DIFF_INCLUDE_UNMODIFIED;
	opts.old_prefix = "a"; opts.new_prefix = "b";

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected);
	git3_diff_free(diff);
}

void test_diff_submodules__dirty_submodule(void)
{
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff *diff = NULL;
	static const char *expected[] = {
		"<SKIP>", /* .gitmodules */
		NULL, /* added */
		NULL, /* ignored */
		"diff --git a/modified b/modified\nindex 092bfb9..452216e 100644\n--- a/modified\n+++ b/modified\n@@ -1 +1,2 @@\n-yo\n+changed\n+\n", /* modified */
		"diff --git a/testrepo b/testrepo\nindex a65fedf..a65fedf 160000\n--- a/testrepo\n+++ b/testrepo\n@@ -1 +1 @@\n-Subproject commit a65fedf39aefe402d3bb6e24df4d4f5fe4547750\n+Subproject commit a65fedf39aefe402d3bb6e24df4d4f5fe4547750-dirty\n", /* testrepo.git */
		NULL, /* unmodified */
		NULL, /* untracked */
		"<END>"
	};

	g_repo = setup_fixture_submodules();

	cl_git_rewritefile("submodules/testrepo/README", "heyheyhey");
	cl_git_mkfile("submodules/testrepo/all_new.txt", "never seen before");

	opts.flags = GIT3_DIFF_INCLUDE_IGNORED |
		GIT3_DIFF_INCLUDE_UNTRACKED |
		GIT3_DIFF_INCLUDE_UNMODIFIED;
	opts.old_prefix = "a"; opts.new_prefix = "b";

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected);
	git3_diff_free(diff);
}

void test_diff_submodules__dirty_submodule_2(void)
{
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff *diff = NULL, *diff2 = NULL;
	char *smpath = "testrepo";
	static const char *expected_none[] = {
		"<END>"
	};
	static const char *expected_dirty[] = {
		"diff --git a/testrepo b/testrepo\nindex a65fedf..a65fedf 160000\n--- a/testrepo\n+++ b/testrepo\n@@ -1 +1 @@\n-Subproject commit a65fedf39aefe402d3bb6e24df4d4f5fe4547750\n+Subproject commit a65fedf39aefe402d3bb6e24df4d4f5fe4547750-dirty\n", /* testrepo.git */
		"<END>"
	};

	g_repo = setup_fixture_submodules();

	opts.flags = GIT3_DIFF_INCLUDE_UNTRACKED |
		GIT3_DIFF_SHOW_UNTRACKED_CONTENT |
		GIT3_DIFF_RECURSE_UNTRACKED_DIRS |
		GIT3_DIFF_DISABLE_PATHSPEC_MATCH;
	opts.old_prefix = "a"; opts.new_prefix = "b";
	opts.pathspec.count = 1;
	opts.pathspec.strings = &smpath;

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_none);
	git3_diff_free(diff);

	cl_git_rewritefile("submodules/testrepo/README", "heyheyhey");
	cl_git_mkfile("submodules/testrepo/all_new.txt", "never seen before");

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_dirty);

	{
		git3_tree *head;

		cl_git_pass(git3_repository_head_tree(&head, g_repo));
		cl_git_pass(git3_diff_tree_to_index(&diff2, g_repo, head, NULL, &opts));
		cl_git_pass(git3_diff_merge(diff, diff2));
		git3_diff_free(diff2);
		git3_tree_free(head);

		check_diff_patches(diff, expected_dirty);
	}

	git3_diff_free(diff);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_dirty);
	git3_diff_free(diff);
}

void test_diff_submodules__submod2_index_to_wd(void)
{
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff *diff = NULL;
	static const char *expected[] = {
		"<SKIP>", /* .gitmodules */
		"<UNTRACKED>", /* not-submodule */
		"<UNTRACKED>", /* not */
		"diff --git a/sm_changed_file b/sm_changed_file\nindex 4800958..4800958 160000\n--- a/sm_changed_file\n+++ b/sm_changed_file\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0-dirty\n", /* sm_changed_file */
		"diff --git a/sm_changed_head b/sm_changed_head\nindex 4800958..3d9386c 160000\n--- a/sm_changed_head\n+++ b/sm_changed_head\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 3d9386c507f6b093471a3e324085657a3c2b4247\n", /* sm_changed_head */
		"<UNTRACKED>", /* sm_changed_head- */
		"<UNTRACKED>", /* sm_changed_head_ */
		"diff --git a/sm_changed_index b/sm_changed_index\nindex 4800958..4800958 160000\n--- a/sm_changed_index\n+++ b/sm_changed_index\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0-dirty\n", /* sm_changed_index */
		"diff --git a/sm_changed_untracked_file b/sm_changed_untracked_file\nindex 4800958..4800958 160000\n--- a/sm_changed_untracked_file\n+++ b/sm_changed_untracked_file\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0-dirty\n", /* sm_changed_untracked_file */
		"diff --git a/sm_missing_commits b/sm_missing_commits\nindex 4800958..5e49635 160000\n--- a/sm_missing_commits\n+++ b/sm_missing_commits\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 5e4963595a9774b90524d35a807169049de8ccad\n", /* sm_missing_commits */
		"<END>"
	};

	g_repo = setup_fixture_submod2();

	/* bracket existing submodule with similarly named items */
	cl_git_mkfile("submod2/sm_changed_head-", "hello");
	cl_git_mkfile("submod2/sm_changed_head_", "hello");

	opts.flags = GIT3_DIFF_INCLUDE_UNTRACKED;
	opts.old_prefix = "a"; opts.new_prefix = "b";

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected);
	git3_diff_free(diff);
}

void test_diff_submodules__submod2_head_to_index(void)
{
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_tree *head;
	git3_diff *diff = NULL;
	static const char *expected[] = {
		"<SKIP>", /* .gitmodules */
		"diff --git a/sm_added_and_uncommited b/sm_added_and_uncommited\nnew file mode 160000\nindex 0000000..4800958\n--- /dev/null\n+++ b/sm_added_and_uncommited\n@@ -0,0 +1 @@\n+Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n", /* sm_added_and_uncommited */
		"<END>"
	};

	g_repo = setup_fixture_submod2();

	cl_git_pass(git3_repository_head_tree(&head, g_repo));

	opts.flags = GIT3_DIFF_INCLUDE_UNTRACKED;
	opts.old_prefix = "a"; opts.new_prefix = "b";

	cl_git_pass(git3_diff_tree_to_index(&diff, g_repo, head, NULL, &opts));
	check_diff_patches(diff, expected);
	git3_diff_free(diff);

	git3_tree_free(head);
}

void test_diff_submodules__invalid_cache(void)
{
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff *diff = NULL;
	git3_submodule *sm;
	char *smpath = "sm_changed_head";
	git3_repository *smrepo;
	git3_index *smindex;
	static const char *expected_baseline[] = {
		"diff --git a/sm_changed_head b/sm_changed_head\nindex 4800958..3d9386c 160000\n--- a/sm_changed_head\n+++ b/sm_changed_head\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 3d9386c507f6b093471a3e324085657a3c2b4247\n", /* sm_changed_head */
		"<END>"
	};
	static const char *expected_unchanged[] = { "<END>" };
	static const char *expected_dirty[] = {
		"diff --git a/sm_changed_head b/sm_changed_head\nindex 3d9386c..3d9386c 160000\n--- a/sm_changed_head\n+++ b/sm_changed_head\n@@ -1 +1 @@\n-Subproject commit 3d9386c507f6b093471a3e324085657a3c2b4247\n+Subproject commit 3d9386c507f6b093471a3e324085657a3c2b4247-dirty\n",
		"<END>"
	};
	static const char *expected_moved[] = {
		"diff --git a/sm_changed_head b/sm_changed_head\nindex 3d9386c..7002348 160000\n--- a/sm_changed_head\n+++ b/sm_changed_head\n@@ -1 +1 @@\n-Subproject commit 3d9386c507f6b093471a3e324085657a3c2b4247\n+Subproject commit 700234833f6ccc20d744b238612646be071acaae\n",
		"<END>"
	};
	static const char *expected_moved_dirty[] = {
		"diff --git a/sm_changed_head b/sm_changed_head\nindex 3d9386c..7002348 160000\n--- a/sm_changed_head\n+++ b/sm_changed_head\n@@ -1 +1 @@\n-Subproject commit 3d9386c507f6b093471a3e324085657a3c2b4247\n+Subproject commit 700234833f6ccc20d744b238612646be071acaae-dirty\n",
		"<END>"
	};

	g_repo = setup_fixture_submod2();

	opts.flags = GIT3_DIFF_INCLUDE_UNTRACKED;
	opts.old_prefix = "a"; opts.new_prefix = "b";
	opts.pathspec.count = 1;
	opts.pathspec.strings = &smpath;

	/* baseline */
	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_baseline);
	git3_diff_free(diff);

	/* update index with new HEAD */
	cl_git_pass(git3_submodule_lookup(&sm, g_repo, smpath));
	cl_git_pass(git3_submodule_add_to_index(sm, 1));

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_unchanged);
	git3_diff_free(diff);

	/* create untracked file in submodule working directory */
	cl_git_mkfile("submod2/sm_changed_head/new_around_here", "hello");
	git3_submodule_set_ignore(g_repo, git3_submodule_name(sm), GIT3_SUBMODULE_IGNORE_NONE);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_dirty);
	git3_diff_free(diff);

	git3_submodule_set_ignore(g_repo, git3_submodule_name(sm), GIT3_SUBMODULE_IGNORE_UNTRACKED);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_unchanged);
	git3_diff_free(diff);

	/* modify tracked file in submodule working directory */
	cl_git_append2file(
		"submod2/sm_changed_head/file_to_modify", "\nmore stuff\n");

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_dirty);
	git3_diff_free(diff);

	git3_submodule_free(sm);

	cl_git_pass(git3_submodule_lookup(&sm, g_repo, smpath));

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_dirty);
	git3_diff_free(diff);

	git3_submodule_set_ignore(g_repo, git3_submodule_name(sm), GIT3_SUBMODULE_IGNORE_DIRTY);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_unchanged);
	git3_diff_free(diff);

	/* add file to index in submodule */
	cl_git_pass(git3_submodule_open(&smrepo, sm));
	cl_git_pass(git3_repository_index(&smindex, smrepo));
	cl_git_pass(git3_index_add_bypath(smindex, "file_to_modify"));

	git3_submodule_set_ignore(g_repo, git3_submodule_name(sm), GIT3_SUBMODULE_IGNORE_UNTRACKED);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_dirty);
	git3_diff_free(diff);

	git3_submodule_set_ignore(g_repo, git3_submodule_name(sm), GIT3_SUBMODULE_IGNORE_DIRTY);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_unchanged);
	git3_diff_free(diff);

	/* commit changed index of submodule */
	cl_repo_commit_from_index(NULL, smrepo, NULL, 1372350000, "Move it");

	git3_submodule_set_ignore(g_repo, git3_submodule_name(sm), GIT3_SUBMODULE_IGNORE_DIRTY);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_moved);
	git3_diff_free(diff);

	git3_submodule_set_ignore(g_repo, git3_submodule_name(sm), GIT3_SUBMODULE_IGNORE_ALL);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_unchanged);
	git3_diff_free(diff);

	git3_submodule_set_ignore(g_repo, git3_submodule_name(sm), GIT3_SUBMODULE_IGNORE_NONE);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_moved_dirty);
	git3_diff_free(diff);

	p_unlink("submod2/sm_changed_head/new_around_here");

	git3_submodule_free(sm);

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_moved);
	git3_diff_free(diff);

	git3_index_free(smindex);
	git3_repository_free(smrepo);
}

void test_diff_submodules__diff_ignore_options(void)
{
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff *diff = NULL;
	git3_config *cfg;
	static const char *expected_normal[] = {
		"<SKIP>", /* .gitmodules */
		"<UNTRACKED>", /* not-submodule */
		"<UNTRACKED>", /* not */
		"diff --git a/sm_changed_file b/sm_changed_file\nindex 4800958..4800958 160000\n--- a/sm_changed_file\n+++ b/sm_changed_file\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0-dirty\n", /* sm_changed_file */
		"diff --git a/sm_changed_head b/sm_changed_head\nindex 4800958..3d9386c 160000\n--- a/sm_changed_head\n+++ b/sm_changed_head\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 3d9386c507f6b093471a3e324085657a3c2b4247\n", /* sm_changed_head */
		"diff --git a/sm_changed_index b/sm_changed_index\nindex 4800958..4800958 160000\n--- a/sm_changed_index\n+++ b/sm_changed_index\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0-dirty\n", /* sm_changed_index */
		"diff --git a/sm_changed_untracked_file b/sm_changed_untracked_file\nindex 4800958..4800958 160000\n--- a/sm_changed_untracked_file\n+++ b/sm_changed_untracked_file\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0-dirty\n", /* sm_changed_untracked_file */
		"diff --git a/sm_missing_commits b/sm_missing_commits\nindex 4800958..5e49635 160000\n--- a/sm_missing_commits\n+++ b/sm_missing_commits\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 5e4963595a9774b90524d35a807169049de8ccad\n", /* sm_missing_commits */
		"<END>"
	};
	static const char *expected_ignore_all[] = {
		"<SKIP>", /* .gitmodules */
		"<UNTRACKED>", /* not-submodule */
		"<UNTRACKED>", /* not */
		"<END>"
	};
	static const char *expected_ignore_dirty[] = {
		"<SKIP>", /* .gitmodules */
		"<UNTRACKED>", /* not-submodule */
		"<UNTRACKED>", /* not */
		"diff --git a/sm_changed_head b/sm_changed_head\nindex 4800958..3d9386c 160000\n--- a/sm_changed_head\n+++ b/sm_changed_head\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 3d9386c507f6b093471a3e324085657a3c2b4247\n", /* sm_changed_head */
		"diff --git a/sm_missing_commits b/sm_missing_commits\nindex 4800958..5e49635 160000\n--- a/sm_missing_commits\n+++ b/sm_missing_commits\n@@ -1 +1 @@\n-Subproject commit 480095882d281ed676fe5b863569520e54a7d5c0\n+Subproject commit 5e4963595a9774b90524d35a807169049de8ccad\n", /* sm_missing_commits */
		"<END>"
	};

	g_repo = setup_fixture_submod2();

	opts.flags = GIT3_DIFF_INCLUDE_UNTRACKED;
	opts.old_prefix = "a"; opts.new_prefix = "b";

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_normal);
	git3_diff_free(diff);

	opts.flags |= GIT3_DIFF_IGNORE_SUBMODULES;

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_ignore_all);
	git3_diff_free(diff);

	opts.flags &= ~GIT3_DIFF_IGNORE_SUBMODULES;
	opts.ignore_submodules = GIT3_SUBMODULE_IGNORE_ALL;

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_ignore_all);
	git3_diff_free(diff);

	opts.ignore_submodules = GIT3_SUBMODULE_IGNORE_DIRTY;

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_ignore_dirty);
	git3_diff_free(diff);

	opts.ignore_submodules = 0;
	cl_git_pass(git3_repository_config(&cfg, g_repo));
	cl_git_pass(git3_config_set_bool(cfg, "diff.ignoreSubmodules", false));

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_normal);
	git3_diff_free(diff);

	cl_git_pass(git3_config_set_bool(cfg, "diff.ignoreSubmodules", true));

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_ignore_all);
	git3_diff_free(diff);

	cl_git_pass(git3_config_set_string(cfg, "diff.ignoreSubmodules", "none"));

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_normal);
	git3_diff_free(diff);

	cl_git_pass(git3_config_set_string(cfg, "diff.ignoreSubmodules", "dirty"));

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	check_diff_patches(diff, expected_ignore_dirty);
	git3_diff_free(diff);

	git3_config_free(cfg);
}

void test_diff_submodules__skips_empty_includes_used(void)
{
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	git3_diff *diff = NULL;
	diff_expects exp;

	/* A side effect of of Git's handling of untracked directories and
	 * auto-ignoring of ".git" entries is that a newly initialized Git
	 * repo inside another repo will be skipped by diff, but one that
	 * actually has a commit it in will show as an untracked directory.
	 * Let's make sure that works.
	 */

	g_repo = cl_git_sandbox_init("empty_standard_repo");

	opts.flags |= GIT3_DIFF_INCLUDE_IGNORED | GIT3_DIFF_INCLUDE_UNTRACKED;

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	memset(&exp, 0, sizeof(exp));
	cl_git_pass(git3_diff_foreach(
		diff, diff_file_cb, diff_binary_cb, diff_hunk_cb, diff_line_cb, &exp));
	cl_assert_equal_i(0, exp.files);
	git3_diff_free(diff);

	{
		git3_repository *r2;
		cl_git_pass(git3_repository_init(&r2, "empty_standard_repo/subrepo", 0));
		git3_repository_free(r2);
	}

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	memset(&exp, 0, sizeof(exp));
	cl_git_pass(git3_diff_foreach(
		diff, diff_file_cb, diff_binary_cb, diff_hunk_cb, diff_line_cb, &exp));
	cl_assert_equal_i(1, exp.files);
	cl_assert_equal_i(1, exp.file_status[GIT3_DELTA_IGNORED]);
	git3_diff_free(diff);

	cl_git_mkfile("empty_standard_repo/subrepo/README.txt", "hello\n");

	cl_git_pass(git3_diff_index_to_workdir(&diff, g_repo, NULL, &opts));
	memset(&exp, 0, sizeof(exp));
	cl_git_pass(git3_diff_foreach(
		diff, diff_file_cb, diff_binary_cb, diff_hunk_cb, diff_line_cb, &exp));
	cl_assert_equal_i(1, exp.files);
	cl_assert_equal_i(1, exp.file_status[GIT3_DELTA_UNTRACKED]);
	git3_diff_free(diff);
}

static void ensure_submodules_found(
	git3_repository *repo,
	const char **paths,
	size_t cnt)
{
	git3_diff *diff = NULL;
	git3_diff_options opts = GIT3_DIFF_OPTIONS_INIT;
	const git3_diff_delta *delta;
	size_t i, pathlen;

	opts.pathspec.strings = (char **)paths;
	opts.pathspec.count = cnt;

	git3_diff_index_to_workdir(&diff, repo, NULL, &opts);

	cl_assert_equal_i(cnt, git3_diff_num_deltas(diff));

	for (i = 0; i < cnt; i++) {
		delta = git3_diff_get_delta(diff, i);

		/* ensure that the given path is returned w/o trailing slashes. */
		pathlen = strlen(opts.pathspec.strings[i]);

		while (pathlen && opts.pathspec.strings[i][pathlen - 1] == '/')
			pathlen--;

		cl_assert_equal_strn(opts.pathspec.strings[i], delta->new_file.path, pathlen);
	}

	git3_diff_free(diff);
}

void test_diff_submodules__can_be_identified_by_trailing_slash_in_pathspec(void)
{
	const char *one_path_without_slash[] = { "sm_changed_head" };
	const char *one_path_with_slash[] = { "sm_changed_head/" };
	const char *many_paths_without_slashes[] = { "sm_changed_head", "sm_changed_index" };
	const char *many_paths_with_slashes[] = { "sm_changed_head/", "sm_changed_index/" };

	g_repo = setup_fixture_submod2();

	ensure_submodules_found(g_repo, one_path_without_slash, ARRAY_SIZE(one_path_without_slash));
	ensure_submodules_found(g_repo, one_path_with_slash, ARRAY_SIZE(one_path_with_slash));
	ensure_submodules_found(g_repo, many_paths_without_slashes, ARRAY_SIZE(many_paths_without_slashes));
	ensure_submodules_found(g_repo, many_paths_with_slashes, ARRAY_SIZE(many_paths_with_slashes));
}
