#include "clar_libgit3.h"
#include "git3/odb_backend.h"
#include "hash.h"
#include "odb.h"

#define LARGEFILE_SIZE 5368709122

static git3_repository *repo;
static git3_odb *odb;

void test_odb_largefiles__initialize(void)
{
	repo = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(git3_repository_odb(&odb, repo));
}

void test_odb_largefiles__cleanup(void)
{
	git3_odb_free(odb);
	cl_git_sandbox_cleanup();
}

static void writefile(git3_oid *oid)
{
	static git3_odb_stream *stream;
	git3_str buf = GIT3_STR_INIT;
	size_t i;

	for (i = 0; i < 3041; i++)
		cl_git_pass(git3_str_puts(&buf, "Hello, world.\n"));

	cl_git_pass(git3_odb_open_wstream(&stream, odb, LARGEFILE_SIZE, GIT3_OBJECT_BLOB));
	for (i = 0; i < 126103; i++)
		cl_git_pass(git3_odb_stream_write(stream, buf.ptr, buf.size));

	cl_git_pass(git3_odb_stream_finalize_write(oid, stream));

	git3_odb_stream_free(stream);
	git3_str_dispose(&buf);
}

void test_odb_largefiles__write_from_memory(void)
{
	git3_oid expected, oid;
	git3_str buf = GIT3_STR_INIT;
	size_t i;

#ifndef GIT3_ARCH_64
	cl_skip();
#endif

	if (!cl_is_env_set("GITTEST_INVASIVE_FS_SIZE") ||
		!cl_is_env_set("GITTEST_INVASIVE_MEMORY") ||
		!cl_is_env_set("GITTEST_SLOW"))
		cl_skip();

	for (i = 0; i < (3041*126103); i++)
		cl_git_pass(git3_str_puts(&buf, "Hello, world.\n"));

	git3_oid_from_string(&expected, "3fb56989cca483b21ba7cb0a6edb229d10e1c26c", GIT3_OID_SHA1);
	cl_git_pass(git3_odb_write(&oid, odb, buf.ptr, buf.size, GIT3_OBJECT_BLOB));

	cl_assert_equal_oid(&expected, &oid);
}

void test_odb_largefiles__streamwrite(void)
{
	git3_oid expected, oid;

#ifndef GIT3_ARCH_64
	cl_skip();
#endif

	if (!cl_is_env_set("GITTEST_INVASIVE_FS_SIZE") ||
		!cl_is_env_set("GITTEST_SLOW"))
		cl_skip();

	git3_oid_from_string(&expected, "3fb56989cca483b21ba7cb0a6edb229d10e1c26c", GIT3_OID_SHA1);
	writefile(&oid);

	cl_assert_equal_oid(&expected, &oid);
}

void test_odb_largefiles__streamread(void)
{
	git3_oid oid, read_oid;
	git3_odb_stream *stream;
	char buf[10240];
	char hdr[64];
	size_t len, hdr_len, total = 0;
	git3_hash_ctx hash;
	git3_object_t type;
	int ret;

#ifndef GIT3_ARCH_64
	cl_skip();
#endif

	if (!cl_is_env_set("GITTEST_INVASIVE_FS_SIZE") ||
		!cl_is_env_set("GITTEST_SLOW"))
		cl_skip();

	writefile(&oid);

	cl_git_pass(git3_odb_open_rstream(&stream, &len, &type, odb, &oid));

	cl_assert_equal_sz(LARGEFILE_SIZE, len);
	cl_assert_equal_i(GIT3_OBJECT_BLOB, type);

	cl_git_pass(git3_hash_ctx_init(&hash, GIT3_HASH_ALGORITHM_SHA1));
	cl_git_pass(git3_odb__format_object_header(&hdr_len, hdr, sizeof(hdr), len, type));

	cl_git_pass(git3_hash_update(&hash, hdr, hdr_len));

	while ((ret = git3_odb_stream_read(stream, buf, 10240)) > 0) {
		cl_git_pass(git3_hash_update(&hash, buf, ret));
		total += ret;
	}

	cl_assert_equal_sz(LARGEFILE_SIZE, total);

	git3_hash_final(read_oid.id, &hash);

	cl_assert_equal_oid(&oid, &read_oid);

	git3_hash_ctx_cleanup(&hash);
	git3_odb_stream_free(stream);
}

void test_odb_largefiles__read_into_memory(void)
{
	git3_oid oid;
	git3_odb_object *obj;

#ifndef GIT3_ARCH_64
	cl_skip();
#endif

	if (!cl_is_env_set("GITTEST_INVASIVE_FS_SIZE") ||
		!cl_is_env_set("GITTEST_INVASIVE_MEMORY") ||
		!cl_is_env_set("GITTEST_SLOW"))
		cl_skip();

	writefile(&oid);
	cl_git_pass(git3_odb_read(&obj, odb, &oid));

	git3_odb_object_free(obj);
}

void test_odb_largefiles__read_into_memory_rejected_on_32bit(void)
{
	git3_oid oid;
	git3_odb_object *obj = NULL;

#ifdef GIT3_ARCH_64
	cl_skip();
#endif

	if (!cl_is_env_set("GITTEST_INVASIVE_FS_SIZE") ||
		!cl_is_env_set("GITTEST_INVASIVE_MEMORY") ||
		!cl_is_env_set("GITTEST_SLOW"))
		cl_skip();

	writefile(&oid);
	cl_git_fail(git3_odb_read(&obj, odb, &oid));

	git3_odb_object_free(obj);
}

void test_odb_largefiles__read_header(void)
{
	git3_oid oid;
	size_t len;
	git3_object_t type;

#ifndef GIT3_ARCH_64
	cl_skip();
#endif

	if (!cl_is_env_set("GITTEST_INVASIVE_FS_SIZE") ||
		!cl_is_env_set("GITTEST_SLOW"))
		cl_skip();

	writefile(&oid);
	cl_git_pass(git3_odb_read_header(&len, &type, odb, &oid));

	cl_assert_equal_sz(LARGEFILE_SIZE, len);
	cl_assert_equal_i(GIT3_OBJECT_BLOB, type);
}
