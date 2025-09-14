#include "clar_libgit3.h"
#include "git3/sys/repository.h"

#include "apply.h"
#include "repository.h"

#include "../patch/patch_common.h"

static git3_repository *repo = NULL;

void test_apply_partial__initialize(void)
{
	repo = cl_git_sandbox_init("renames");
}

void test_apply_partial__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

static int skip_addition(
	const git3_diff_hunk *hunk,
	void *payload)
{
	GIT3_UNUSED(payload);

	return (hunk->new_lines > hunk->old_lines) ? 1 : 0;
}

static int skip_deletion(
	const git3_diff_hunk *hunk,
	void *payload)
{
	GIT3_UNUSED(payload);

	return (hunk->new_lines < hunk->old_lines) ? 1 : 0;
}

static int skip_change(
	const git3_diff_hunk *hunk,
	void *payload)
{
	GIT3_UNUSED(payload);

	return (hunk->new_lines == hunk->old_lines) ? 1 : 0;
}

static int abort_addition(
	const git3_diff_hunk *hunk,
	void *payload)
{
	GIT3_UNUSED(payload);

	return (hunk->new_lines > hunk->old_lines) ? GIT3_EUSER : 0;
}

static int abort_deletion(
	const git3_diff_hunk *hunk,
	void *payload)
{
	GIT3_UNUSED(payload);

	return (hunk->new_lines < hunk->old_lines) ? GIT3_EUSER : 0;
}

static int abort_change(
	const git3_diff_hunk *hunk,
	void *payload)
{
	GIT3_UNUSED(payload);

	return (hunk->new_lines == hunk->old_lines) ? GIT3_EUSER : 0;
}

static int apply_buf(
	const char *old,
	const char *oldname,
	const char *new,
	const char *newname,
	const char *expected,
	const git3_diff_options *diff_opts,
	git3_apply_hunk_cb hunk_cb,
	void *payload)
{
	git3_patch *patch;
	git3_str result = GIT3_STR_INIT;
	git3_str patchbuf = GIT3_STR_INIT;
	git3_apply_options opts = GIT3_APPLY_OPTIONS_INIT;
	char *filename;
	unsigned int mode;
	int error;
	size_t oldsize = strlen(old);
	size_t newsize = strlen(new);

	opts.hunk_cb = hunk_cb;
	opts.payload = payload;

	cl_git_pass(git3_patch_from_buffers(&patch, old, oldsize, oldname, new, newsize, newname, diff_opts));
	if ((error = git3_apply__patch(&result, &filename, &mode, old, oldsize, patch, &opts)) == 0) {
		cl_assert_equal_s(expected, result.ptr);
		cl_assert_equal_s(newname, filename);
		cl_assert_equal_i(0100644, mode);
	}

	git3__free(filename);
	git3_str_dispose(&result);
	git3_str_dispose(&patchbuf);
	git3_patch_free(patch);

	return error;
}

void test_apply_partial__prepend_and_change_skip_addition(void)
{
	cl_git_pass(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_PREPEND_AND_CHANGE, "file.txt",
		FILE_ORIGINAL, NULL, skip_addition, NULL));
}

void test_apply_partial__prepend_and_change_nocontext_skip_addition(void)
{
	git3_diff_options diff_opts = GIT3_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_pass(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_PREPEND_AND_CHANGE, "file.txt",
		FILE_CHANGE_MIDDLE, &diff_opts, skip_addition, NULL));
}

void test_apply_partial__prepend_and_change_nocontext_abort_addition(void)
{
	git3_diff_options diff_opts = GIT3_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_fail(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_PREPEND_AND_CHANGE, "file.txt",
		FILE_ORIGINAL, &diff_opts, abort_addition, NULL));
}

void test_apply_partial__prepend_and_change_skip_change(void)
{
	cl_git_pass(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_PREPEND_AND_CHANGE, "file.txt",
		FILE_PREPEND_AND_CHANGE, NULL, skip_change, NULL));
}

void test_apply_partial__prepend_and_change_nocontext_skip_change(void)
{
	git3_diff_options diff_opts = GIT3_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_pass(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_PREPEND_AND_CHANGE, "file.txt",
		FILE_PREPEND, &diff_opts, skip_change, NULL));
}

void test_apply_partial__prepend_and_change_nocontext_abort_change(void)
{
	git3_diff_options diff_opts = GIT3_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_fail(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_PREPEND_AND_CHANGE, "file.txt",
		FILE_PREPEND, &diff_opts, abort_change, NULL));
}

void test_apply_partial__delete_and_change_skip_deletion(void)
{
	cl_git_pass(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_DELETE_AND_CHANGE, "file.txt",
		FILE_ORIGINAL, NULL, skip_deletion, NULL));
}

void test_apply_partial__delete_and_change_nocontext_skip_deletion(void)
{
	git3_diff_options diff_opts = GIT3_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_pass(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_DELETE_AND_CHANGE, "file.txt",
		FILE_CHANGE_MIDDLE, &diff_opts, skip_deletion, NULL));
}

void test_apply_partial__delete_and_change_nocontext_abort_deletion(void)
{
	git3_diff_options diff_opts = GIT3_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_fail(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_DELETE_AND_CHANGE, "file.txt",
		FILE_ORIGINAL, &diff_opts, abort_deletion, NULL));
}

void test_apply_partial__delete_and_change_skip_change(void)
{
	cl_git_pass(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_DELETE_AND_CHANGE, "file.txt",
		FILE_DELETE_AND_CHANGE, NULL, skip_change, NULL));
}

void test_apply_partial__delete_and_change_nocontext_skip_change(void)
{
	git3_diff_options diff_opts = GIT3_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_pass(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_DELETE_AND_CHANGE, "file.txt",
		FILE_DELETE_FIRSTLINE, &diff_opts, skip_change, NULL));
}

void test_apply_partial__delete_and_change_nocontext_abort_change(void)
{
	git3_diff_options diff_opts = GIT3_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_fail(apply_buf(
		FILE_ORIGINAL, "file.txt",
		FILE_DELETE_AND_CHANGE, "file.txt",
		FILE_DELETE_FIRSTLINE, &diff_opts, abort_change, NULL));
}
