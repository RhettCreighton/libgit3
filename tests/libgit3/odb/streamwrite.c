#include "clar_libgit3.h"
#include "git3/odb_backend.h"

static git3_repository *repo;
static git3_odb *odb;
static git3_odb_stream *stream;

void test_odb_streamwrite__initialize(void)
{
	repo = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(git3_repository_odb(&odb, repo));

	cl_git_pass(git3_odb_open_wstream(&stream, odb, 14, GIT3_OBJECT_BLOB));
	cl_assert_equal_sz(14, stream->declared_size);
}

void test_odb_streamwrite__cleanup(void)
{
	git3_odb_stream_free(stream);
	git3_odb_free(odb);
	cl_git_sandbox_cleanup();
}

void test_odb_streamwrite__can_accept_chunks(void)
{
	git3_oid oid;

	cl_git_pass(git3_odb_stream_write(stream, "deadbeef", 8));
	cl_assert_equal_sz(8, stream->received_bytes);

	cl_git_pass(git3_odb_stream_write(stream, "deadbeef", 6));
	cl_assert_equal_sz(8 + 6, stream->received_bytes);

	cl_git_pass(git3_odb_stream_finalize_write(&oid, stream));
}

void test_odb_streamwrite__can_detect_missing_bytes(void)
{
	git3_oid oid;

	cl_git_pass(git3_odb_stream_write(stream, "deadbeef", 8));
	cl_assert_equal_sz(8, stream->received_bytes);

	cl_git_pass(git3_odb_stream_write(stream, "deadbeef", 4));
	cl_assert_equal_sz(8 + 4, stream->received_bytes);

	cl_git_fail(git3_odb_stream_finalize_write(&oid, stream));
}

void test_odb_streamwrite__can_detect_additional_bytes(void)
{
	cl_git_pass(git3_odb_stream_write(stream, "deadbeef", 8));
	cl_assert_equal_sz(8, stream->received_bytes);

	cl_git_fail(git3_odb_stream_write(stream, "deadbeef", 7));
}
