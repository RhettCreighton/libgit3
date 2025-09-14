#include "clar_libgit3.h"
#include "patch.h"
#include "patch_parse.h"

#include "patch_common.h"

static void ensure_patch_validity(git3_patch *patch)
{
	const git3_diff_delta *delta;
	char idstr[GIT3_OID_SHA1_HEXSIZE+1] = {0};

	cl_assert((delta = git3_patch_get_delta(patch)) != NULL);
	cl_assert_equal_i(2, delta->nfiles);

	cl_assert_equal_s(delta->old_file.path, "file.txt");
	cl_assert(delta->old_file.mode == GIT3_FILEMODE_BLOB);
	cl_assert_equal_i(7, delta->old_file.id_abbrev);
	git3_oid_nfmt(idstr, delta->old_file.id_abbrev, &delta->old_file.id);
	cl_assert_equal_s(idstr, "9432026");
	cl_assert_equal_i(0, delta->old_file.size);

	cl_assert_equal_s(delta->new_file.path, "file.txt");
	cl_assert(delta->new_file.mode == GIT3_FILEMODE_BLOB);
	cl_assert_equal_i(7, delta->new_file.id_abbrev);
	git3_oid_nfmt(idstr, delta->new_file.id_abbrev, &delta->new_file.id);
	cl_assert_equal_s(idstr, "cd8fd12");
	cl_assert_equal_i(0, delta->new_file.size);
}

static void ensure_identical_patch_inout(const char *content)
{
	git3_buf buf = GIT3_BUF_INIT;
	git3_patch *patch;

	cl_git_pass(git3_patch_from_buffer(&patch, content, strlen(content), NULL));
	cl_git_pass(git3_patch_to_buf(&buf, patch));
	cl_assert_equal_strn(buf.ptr, content, strlen(content));

	git3_patch_free(patch);
	git3_buf_dispose(&buf);
}

void test_patch_parse__original_to_change_middle(void)
{
	git3_patch *patch;

	cl_git_pass(git3_patch_from_buffer(
		&patch, PATCH_ORIGINAL_TO_CHANGE_MIDDLE,
		strlen(PATCH_ORIGINAL_TO_CHANGE_MIDDLE), NULL));
	ensure_patch_validity(patch);
	git3_patch_free(patch);
}

void test_patch_parse__leading_and_trailing_garbage(void)
{
	git3_patch *patch;
	const char *leading = "This is some leading garbage.\n"
		"Maybe it's email headers?\n"
		"\n"
		PATCH_ORIGINAL_TO_CHANGE_MIDDLE;
	const char *trailing = PATCH_ORIGINAL_TO_CHANGE_MIDDLE
		"\n"
		"This is some trailing garbage.\n"
		"Maybe it's an email signature?\n";
	const char *both = "Here's some leading garbage\n"
		PATCH_ORIGINAL_TO_CHANGE_MIDDLE
		"And here's some trailing.\n";

	cl_git_pass(git3_patch_from_buffer(&patch, leading, strlen(leading),
		NULL));
	ensure_patch_validity(patch);
	git3_patch_free(patch);

	cl_git_pass(git3_patch_from_buffer(&patch, trailing, strlen(trailing),
		NULL));
	ensure_patch_validity(patch);
	git3_patch_free(patch);

	cl_git_pass(git3_patch_from_buffer(&patch, both, strlen(both),
		NULL));
	ensure_patch_validity(patch);
	git3_patch_free(patch);
}

void test_patch_parse__nonpatches_fail_with_notfound(void)
{
	git3_patch *patch;

	cl_git_fail_with(GIT3_ENOTFOUND,
		git3_patch_from_buffer(&patch, PATCH_NOT_A_PATCH,
		strlen(PATCH_NOT_A_PATCH), NULL));
}

void test_patch_parse__invalid_patches_fails(void)
{
	git3_patch *patch;

	cl_git_fail_with(GIT3_ERROR,
		git3_patch_from_buffer(&patch, PATCH_CORRUPT_GIT3_HEADER,
		strlen(PATCH_CORRUPT_GIT3_HEADER), NULL));
	cl_git_fail_with(GIT3_ERROR,
		git3_patch_from_buffer(&patch,
		PATCH_CORRUPT_MISSING_NEW_FILE,
		strlen(PATCH_CORRUPT_MISSING_NEW_FILE), NULL));
	cl_git_fail_with(GIT3_ERROR,
		git3_patch_from_buffer(&patch,
		PATCH_CORRUPT_MISSING_OLD_FILE,
		strlen(PATCH_CORRUPT_MISSING_OLD_FILE), NULL));
	cl_git_fail_with(GIT3_ERROR,
		git3_patch_from_buffer(&patch, PATCH_CORRUPT_NO_CHANGES,
		strlen(PATCH_CORRUPT_NO_CHANGES), NULL));
	cl_git_fail_with(GIT3_ERROR,
		git3_patch_from_buffer(&patch,
		PATCH_CORRUPT_MISSING_HUNK_HEADER,
		strlen(PATCH_CORRUPT_MISSING_HUNK_HEADER), NULL));
}

void test_patch_parse__no_newline_at_end_of_new_file(void)
{
	ensure_identical_patch_inout(PATCH_APPEND_NO_NL);
}

void test_patch_parse__no_newline_at_end_of_old_file(void)
{
	ensure_identical_patch_inout(PATCH_APPEND_NO_NL_IN_OLD_FILE);
}

void test_patch_parse__files_with_whitespaces_succeeds(void)
{
	ensure_identical_patch_inout(PATCH_NAME_WHITESPACE);
}

void test_patch_parse__lifetime_of_patch_does_not_depend_on_buffer(void)
{
	git3_str diff = GIT3_STR_INIT;
	git3_buf rendered = GIT3_BUF_INIT;
	git3_patch *patch;

	cl_git_pass(git3_str_sets(&diff, PATCH_ORIGINAL_TO_CHANGE_MIDDLE));
	cl_git_pass(git3_patch_from_buffer(&patch, diff.ptr, diff.size, NULL));
	git3_str_dispose(&diff);

	cl_git_pass(git3_patch_to_buf(&rendered, patch));
	cl_assert_equal_s(PATCH_ORIGINAL_TO_CHANGE_MIDDLE, rendered.ptr);
	git3_buf_dispose(&rendered);

	cl_git_pass(git3_patch_to_buf(&rendered, patch));
	cl_assert_equal_s(PATCH_ORIGINAL_TO_CHANGE_MIDDLE, rendered.ptr);
	git3_buf_dispose(&rendered);

	git3_patch_free(patch);
}

void test_patch_parse__binary_file_with_missing_paths(void)
{
	git3_patch *patch;
	cl_git_fail(git3_patch_from_buffer(&patch, PATCH_BINARY_FILE_WITH_MISSING_PATHS,
					  strlen(PATCH_BINARY_FILE_WITH_MISSING_PATHS), NULL));
}

void test_patch_parse__binary_file_with_whitespace_paths(void)
{
	git3_patch *patch;
	cl_git_fail(git3_patch_from_buffer(&patch, PATCH_BINARY_FILE_WITH_WHITESPACE_PATHS,
					  strlen(PATCH_BINARY_FILE_WITH_WHITESPACE_PATHS), NULL));
}

void test_patch_parse__binary_file_with_empty_quoted_paths(void)
{
	git3_patch *patch;
	cl_git_fail(git3_patch_from_buffer(&patch, PATCH_BINARY_FILE_WITH_QUOTED_EMPTY_PATHS,
					  strlen(PATCH_BINARY_FILE_WITH_QUOTED_EMPTY_PATHS), NULL));
}

void test_patch_parse__binary_file_path_with_spaces(void)
{
	git3_patch *patch;
	cl_git_fail(git3_patch_from_buffer(&patch, PATCH_BINARY_FILE_PATH_WITH_SPACES,
					  strlen(PATCH_BINARY_FILE_PATH_WITH_SPACES), NULL));
}

void test_patch_parse__binary_file_path_without_body_paths(void)
{
	git3_patch *patch;
	cl_git_fail(git3_patch_from_buffer(&patch, PATCH_BINARY_FILE_PATH_WITHOUT_BODY_PATHS,
					  strlen(PATCH_BINARY_FILE_PATH_WITHOUT_BODY_PATHS), NULL));
}

void test_patch_parse__binary_file_with_truncated_delta(void)
{
	git3_patch *patch;
	cl_git_fail(git3_patch_from_buffer(&patch, PATCH_BINARY_FILE_WITH_TRUNCATED_DELTA,
					  strlen(PATCH_BINARY_FILE_WITH_TRUNCATED_DELTA), NULL));
	cl_assert_equal_s(git3_error_last()->message, "truncated binary data at line 5");
}

void test_patch_parse__memory_leak_on_multiple_paths(void)
{
	git3_patch *patch;
	cl_git_fail(git3_patch_from_buffer(&patch, PATCH_MULTIPLE_OLD_PATHS, strlen(PATCH_MULTIPLE_OLD_PATHS), NULL));
}

void test_patch_parse__truncated_no_newline_at_end_of_file(void)
{
	size_t len = strlen(PATCH_APPEND_NO_NL) - strlen("at end of file\n");
	const git3_diff_line *line;
	git3_patch *patch;

	cl_git_pass(git3_patch_from_buffer(&patch, PATCH_APPEND_NO_NL, len, NULL));
	cl_git_pass(git3_patch_get_line_in_hunk(&line, patch, 0, 4));
	cl_assert_equal_s(line->content, "\\ No newline ");

	git3_patch_free(patch);
}

void test_patch_parse__line_number_overflow(void)
{
	git3_patch *patch;
	cl_git_fail(git3_patch_from_buffer(&patch, PATCH_INTMAX_NEW_LINES, strlen(PATCH_INTMAX_NEW_LINES), NULL));
	git3_patch_free(patch);
}
