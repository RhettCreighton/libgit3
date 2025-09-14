#include "clar_libgit3.h"
#include "posix.h"
#include "path.h"
#include "futils.h"

static git3_repository *repo;
static char textual_content[] = "libgit3\n\r\n\0";

void test_object_blob_fromstream__initialize(void)
{
	repo = cl_git_sandbox_init("testrepo.git");
}

void test_object_blob_fromstream__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_object_blob_fromstream__multiple_write(void)
{
	git3_oid expected_id, id;
	git3_object *blob;
	git3_writestream *stream;
	int i, howmany = 6;

	cl_git_pass(git3_oid_from_string(&expected_id, "321cbdf08803c744082332332838df6bd160f8f9", GIT3_OID_SHA1));

	cl_git_fail_with(GIT3_ENOTFOUND,
			 git3_object_lookup(&blob, repo, &expected_id, GIT3_OBJECT_ANY));

	cl_git_pass(git3_blob_create_from_stream(&stream, repo, NULL));

	for (i = 0; i < howmany; i++)
		cl_git_pass(stream->write(stream, textual_content, strlen(textual_content)));

	cl_git_pass(git3_blob_create_from_stream_commit(&id, stream));
	cl_assert_equal_oid(&expected_id, &id);

	cl_git_pass(git3_object_lookup(&blob, repo, &expected_id, GIT3_OBJECT_BLOB));

	git3_object_free(blob);
}

#define GITATTR "* text=auto\n" \
	"*.txt text\n" \
	"*.data binary\n"

static void write_attributes(git3_repository *repo)
{
	git3_str buf = GIT3_STR_INIT;

	cl_git_pass(git3_str_joinpath(&buf, git3_repository_path(repo), "info"));
	cl_git_pass(git3_str_joinpath(&buf, git3_str_cstr(&buf), "attributes"));

	cl_git_pass(git3_futils_mkpath2file(git3_str_cstr(&buf), 0777));
	cl_git_rewritefile(git3_str_cstr(&buf), GITATTR);

	git3_str_dispose(&buf);
}

static void assert_named_chunked_blob(const char *expected_sha, const char *fake_name)
{
	git3_oid expected_id, id;
	git3_writestream *stream;
	int i, howmany = 6;

	cl_git_pass(git3_oid_from_string(&expected_id, expected_sha, GIT3_OID_SHA1));

	cl_git_pass(git3_blob_create_from_stream(&stream, repo, fake_name));

	for (i = 0; i < howmany; i++)
		cl_git_pass(stream->write(stream, textual_content, strlen(textual_content)));

	cl_git_pass(git3_blob_create_from_stream_commit(&id, stream));

	cl_assert_equal_oid(&expected_id, &id);
}

void test_object_blob_fromstream__creating_a_blob_from_chunks_honors_the_attributes_directives(void)
{
	write_attributes(repo);

	assert_named_chunked_blob("321cbdf08803c744082332332838df6bd160f8f9", "dummy.data");
	assert_named_chunked_blob("e9671e138a780833cb689753570fd10a55be84fb", "dummy.txt");
	assert_named_chunked_blob("e9671e138a780833cb689753570fd10a55be84fb", "dummy.dunno");
}
