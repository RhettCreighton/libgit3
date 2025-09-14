#include "clar_libgit3.h"
#include "crlf.h"
#include "path.h"
#include "futils.h"

static git3_repository *g_repo = NULL;
static git3_str orig_system_path = GIT3_STR_INIT;
static git3_str system_attr_path = GIT3_STR_INIT;

void test_filter_systemattrs__initialize(void)
{
	git3_str new_system_path = GIT3_BUF_INIT;

	g_repo = cl_git_sandbox_init("crlf");
	cl_must_pass(p_unlink("crlf/.gitattributes"));

	cl_git_pass(git3_libgit3_opts(
		GIT3_OPT_GET_SEARCH_PATH, GIT3_CONFIG_LEVEL_SYSTEM, &orig_system_path));

	cl_git_pass(git3_str_joinpath(&new_system_path,
		clar_sandbox_path(), "_system_path"));
	cl_git_pass(git3_futils_mkdir_r(new_system_path.ptr, 0777));
	cl_git_pass(git3_libgit3_opts(
		GIT3_OPT_SET_SEARCH_PATH, GIT3_CONFIG_LEVEL_SYSTEM, new_system_path.ptr));

	cl_git_pass(git3_str_joinpath(&system_attr_path,
		new_system_path.ptr, "gitattributes"));

	cl_git_mkfile(system_attr_path.ptr,
		"*.txt text\n"
		"*.bin binary\n"
		"*.crlf text eol=crlf\n"
		"*.lf text eol=lf\n");

	git3_str_dispose(&new_system_path);
}

void test_filter_systemattrs__cleanup(void)
{
	cl_git_pass(git3_libgit3_opts(
		GIT3_OPT_SET_SEARCH_PATH, GIT3_CONFIG_LEVEL_SYSTEM, orig_system_path.ptr));

	cl_must_pass(p_unlink(system_attr_path.ptr));
	git3_str_dispose(&system_attr_path);
	git3_str_dispose(&orig_system_path);

	cl_git_sandbox_cleanup();
}

void test_filter_systemattrs__reads_system_attributes(void)
{
	git3_blob *blob;
	git3_buf buf = { 0 };

	cl_git_pass(git3_revparse_single(
		(git3_object **)&blob, g_repo, "799770d")); /* all-lf */

	cl_assert_equal_s(ALL_LF_TEXT_RAW, git3_blob_rawcontent(blob));

	cl_git_pass(git3_blob_filter(&buf, blob, "file.bin", NULL));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.crlf", NULL));
	cl_assert_equal_s(ALL_LF_TEXT_AS_CRLF, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.lf", NULL));
	cl_assert_equal_s(ALL_LF_TEXT_AS_LF, buf.ptr);

	git3_buf_dispose(&buf);
	git3_blob_free(blob);
}

void test_filter_systemattrs__disables_system_attributes(void)
{
	git3_blob *blob;
	git3_buf buf = { 0 };
	git3_blob_filter_options opts = GIT3_BLOB_FILTER_OPTIONS_INIT;

	opts.flags |= GIT3_BLOB_FILTER_NO_SYSTEM_ATTRIBUTES;

	cl_git_pass(git3_revparse_single(
		(git3_object **)&blob, g_repo, "799770d")); /* all-lf */

	cl_assert_equal_s(ALL_LF_TEXT_RAW, git3_blob_rawcontent(blob));

	cl_git_pass(git3_blob_filter(&buf, blob, "file.bin", &opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	/* No attributes mean these are all treated literally */
	cl_git_pass(git3_blob_filter(&buf, blob, "file.crlf", &opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.lf", &opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	git3_buf_dispose(&buf);
	git3_blob_free(blob);
}
