#include "clar_libgit3.h"
#include "crlf.h"

static git3_repository *g_repo = NULL;
static git3_blob_filter_options filter_opts = GIT3_BLOB_FILTER_OPTIONS_INIT;

void test_filter_bare__initialize(void)
{
	cl_fixture_sandbox("crlf.git");
	cl_git_pass(git3_repository_open(&g_repo, "crlf.git"));

	filter_opts.flags |= GIT3_BLOB_FILTER_NO_SYSTEM_ATTRIBUTES;
	filter_opts.flags |= GIT3_BLOB_FILTER_ATTRIBUTES_FROM_HEAD;
}

void test_filter_bare__cleanup(void)
{
	git3_repository_free(g_repo);
	cl_fixture_cleanup("crlf.git");
}

void test_filter_bare__all_crlf(void)
{
	git3_blob *blob;
	git3_buf buf = { 0 };

	cl_git_pass(git3_revparse_single(
		(git3_object **)&blob, g_repo, "a9a2e89")); /* all-crlf */

	cl_assert_equal_s(ALL_CRLF_TEXT_RAW, git3_blob_rawcontent(blob));

	cl_git_pass(git3_blob_filter(&buf, blob, "file.bin", &filter_opts));

	cl_assert_equal_s(ALL_CRLF_TEXT_RAW, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.crlf", &filter_opts));

	/* in this case, raw content has crlf in it already */
	cl_assert_equal_s(ALL_CRLF_TEXT_AS_CRLF, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.lf", &filter_opts));

	/* we never convert CRLF -> LF on platforms that have LF */
	cl_assert_equal_s(ALL_CRLF_TEXT_AS_CRLF, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.txt", &filter_opts));

	/* in this case, raw content has crlf in it already */
	cl_assert_equal_s(ALL_CRLF_TEXT_AS_CRLF, buf.ptr);

	git3_buf_dispose(&buf);
	git3_blob_free(blob);
}

void test_filter_bare__from_lf(void)
{
	git3_blob *blob;
	git3_buf buf = { 0 };

	cl_git_pass(git3_revparse_single(
		(git3_object **)&blob, g_repo, "799770d")); /* all-lf */

	cl_assert_equal_s(ALL_LF_TEXT_RAW, git3_blob_rawcontent(blob));

	cl_git_pass(git3_blob_filter(&buf, blob, "file.bin", &filter_opts));

	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.crlf", &filter_opts));

	/* in this case, raw content has crlf in it already */
	cl_assert_equal_s(ALL_LF_TEXT_AS_CRLF, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.lf", &filter_opts));

	/* we never convert CRLF -> LF on platforms that have LF */
	cl_assert_equal_s(ALL_LF_TEXT_AS_LF, buf.ptr);

	git3_buf_dispose(&buf);
	git3_blob_free(blob);
}

void test_filter_bare__nested_attributes(void)
{
	git3_blob *blob;
	git3_buf buf = { 0 };

	cl_git_pass(git3_revparse_single(
		(git3_object **)&blob, g_repo, "799770d")); /* all-lf */

	cl_assert_equal_s(ALL_LF_TEXT_RAW, git3_blob_rawcontent(blob));

	cl_git_pass(git3_blob_filter(&buf, blob, "raw/file.bin", &filter_opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "raw/file.crlf", &filter_opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "raw/file.lf", &filter_opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	git3_buf_dispose(&buf);
	git3_blob_free(blob);
}

void test_filter_bare__sanitizes(void)
{
	git3_blob *blob;
	git3_buf buf = GIT3_BUF_INIT;

	cl_git_pass(git3_revparse_single(
		(git3_object **)&blob, g_repo, "e69de29")); /* zero-byte */

	cl_assert_equal_i(0, git3_blob_rawsize(blob));
	cl_assert_equal_s("", git3_blob_rawcontent(blob));

	cl_git_pass(git3_blob_filter(&buf, blob, "file.bin", &filter_opts));
	cl_assert_equal_sz(0, buf.size);
	cl_assert_equal_s("", buf.ptr);
	git3_buf_dispose(&buf);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.crlf", &filter_opts));
	cl_assert_equal_sz(0, buf.size);
	cl_assert_equal_s("", buf.ptr);
	git3_buf_dispose(&buf);

	cl_git_pass(git3_blob_filter(&buf, blob, "file.lf", &filter_opts));
	cl_assert_equal_sz(0, buf.size);
	cl_assert_equal_s("", buf.ptr);
	git3_buf_dispose(&buf);

	git3_blob_free(blob);
}

void test_filter_bare__from_specific_commit_one(void)
{
	git3_blob_filter_options opts = GIT3_BLOB_FILTER_OPTIONS_INIT;
	git3_blob *blob;
	git3_buf buf = { 0 };

	opts.flags |= GIT3_BLOB_FILTER_NO_SYSTEM_ATTRIBUTES;
	opts.flags |= GIT3_BLOB_FILTER_ATTRIBUTES_FROM_COMMIT;
	cl_git_pass(git3_oid_from_string(&opts.attr_commit_id, "b8986fec0f7bde90f78ac72706e782d82f24f2f0", GIT3_OID_SHA1));

	cl_git_pass(git3_revparse_single(
		(git3_object **)&blob, g_repo, "055c872")); /* ident */

	cl_assert_equal_s("$Id$\n", git3_blob_rawcontent(blob));

	cl_git_pass(git3_blob_filter(&buf, blob, "ident.bin", &opts));
	cl_assert_equal_s("$Id$\n", buf.ptr);

	cl_git_pass(git3_blob_filter(&buf, blob, "ident.identlf", &opts));
	cl_assert_equal_s("$Id: 055c8729cdcc372500a08db659c045e16c4409fb $\n", buf.ptr);

	git3_buf_dispose(&buf);
	git3_blob_free(blob);
}

void test_filter_bare__from_specific_commit_with_no_attributes_file(void)
{
	git3_blob_filter_options opts = GIT3_BLOB_FILTER_OPTIONS_INIT;
	git3_blob *blob;
	git3_buf buf = { 0 };

	opts.flags |= GIT3_BLOB_FILTER_NO_SYSTEM_ATTRIBUTES;
	opts.flags |= GIT3_BLOB_FILTER_ATTRIBUTES_FROM_COMMIT;
	cl_git_pass(git3_oid_from_string(&opts.attr_commit_id, "5afb6a14a864e30787857dd92af837e8cdd2cb1b", GIT3_OID_SHA1));

	cl_git_pass(git3_revparse_single(
		(git3_object **)&blob, g_repo, "799770d")); /* all-lf */

	cl_assert_equal_s(ALL_LF_TEXT_RAW, git3_blob_rawcontent(blob));

	cl_git_pass(git3_blob_filter(&buf, blob, "file.bin", &opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	/* we never convert CRLF -> LF on platforms that have LF */
	cl_git_pass(git3_blob_filter(&buf, blob, "file.lf", &opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	/* we never convert CRLF -> LF on platforms that have LF */
	cl_git_pass(git3_blob_filter(&buf, blob, "file.crlf", &opts));
	cl_assert_equal_s(ALL_LF_TEXT_RAW, buf.ptr);

	git3_buf_dispose(&buf);
	git3_blob_free(blob);
}
