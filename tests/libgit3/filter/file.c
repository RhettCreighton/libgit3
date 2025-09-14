#include "clar_libgit3.h"
#include "git3/sys/filter.h"
#include "crlf.h"

static git3_repository *g_repo = NULL;

void test_filter_file__initialize(void)
{
	git3_reference *head_ref;
	git3_commit *head;

	g_repo = cl_git_sandbox_init("crlf");

	cl_git_mkfile("crlf/.gitattributes",
		"*.txt text\n*.bin binary\n*.crlf text eol=crlf\n*.lf text eol=lf\n");

	cl_repo_set_bool(g_repo, "core.autocrlf", true);

	cl_git_pass(git3_repository_head(&head_ref, g_repo));
	cl_git_pass(git3_reference_peel((git3_object **)&head, head_ref, GIT3_OBJECT_COMMIT));
	cl_git_pass(git3_reset(g_repo, (git3_object *)head, GIT3_RESET_HARD, NULL));

	git3_commit_free(head);
	git3_reference_free(head_ref);
}

void test_filter_file__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_filter_file__apply(void)
{
	git3_filter_list *fl;
	git3_filter *crlf;
	git3_buf buf = GIT3_BUF_INIT;

	cl_git_pass(git3_filter_list_new(
		&fl, g_repo, GIT3_FILTER_TO_ODB, 0));

	crlf = git3_filter_lookup(GIT3_FILTER_CRLF);
	cl_assert(crlf != NULL);

	cl_git_pass(git3_filter_list_push(fl, crlf, NULL));

	cl_git_pass(git3_filter_list_apply_to_file(&buf, fl, g_repo, "all-crlf"));
	cl_assert_equal_s("crlf\ncrlf\ncrlf\ncrlf\n", buf.ptr);

	git3_buf_dispose(&buf);
	git3_filter_list_free(fl);
}

struct buf_writestream {
	git3_writestream base;
	git3_str buf;
};

static int buf_writestream_write(git3_writestream *s, const char *buf, size_t len)
{
	struct buf_writestream *stream = (struct buf_writestream *)s;
	return git3_str_put(&stream->buf, buf, len);
}

static int buf_writestream_close(git3_writestream *s)
{
	GIT3_UNUSED(s);
	return 0;
}

static void buf_writestream_free(git3_writestream *s)
{
	struct buf_writestream *stream = (struct buf_writestream *)s;
	git3_str_dispose(&stream->buf);
}

void test_filter_file__apply_stream(void)
{
	git3_filter_list *fl;
	git3_filter *crlf;
	struct buf_writestream write_target = { {
		buf_writestream_write,
		buf_writestream_close,
		buf_writestream_free } };

	cl_git_pass(git3_filter_list_new(
		&fl, g_repo, GIT3_FILTER_TO_ODB, 0));

	crlf = git3_filter_lookup(GIT3_FILTER_CRLF);
	cl_assert(crlf != NULL);

	cl_git_pass(git3_filter_list_push(fl, crlf, NULL));

	cl_git_pass(git3_filter_list_stream_file(fl, g_repo, "all-crlf", &write_target.base));
	cl_assert_equal_s("crlf\ncrlf\ncrlf\ncrlf\n", write_target.buf.ptr);

	git3_filter_list_free(fl);
	write_target.base.free(&write_target.base);
}
