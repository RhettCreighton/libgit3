#include "clar_libgit3.h"
#include "odb.h"

static git3_repository *_repo;

void test_repo_hashfile__initialize(void)
{
	_repo = cl_git_sandbox_init("status");
}

void test_repo_hashfile__cleanup(void)
{
	cl_fixture_cleanup("absolute");
	cl_git_sandbox_cleanup();
	_repo = NULL;
}

void test_repo_hashfile__simple(void)
{
	git3_oid a, b;
	git3_str full = GIT3_STR_INIT;

	/* hash with repo relative path */
	cl_git_pass(git3_odb__hashfile(&a, "status/current_file", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, "current_file", GIT3_OBJECT_BLOB, NULL));
	cl_assert_equal_oid(&a, &b);

	cl_git_pass(git3_str_joinpath(&full, git3_repository_workdir(_repo), "current_file"));

	/* hash with full path */
	cl_git_pass(git3_odb__hashfile(&a, full.ptr, GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, full.ptr, GIT3_OBJECT_BLOB, NULL));
	cl_assert_equal_oid(&a, &b);

	/* hash with invalid type */
	cl_git_fail(git3_odb__hashfile(&a, full.ptr, GIT3_OBJECT_ANY, GIT3_OID_SHA1));
	cl_git_fail(git3_repository_hashfile(&b, _repo, full.ptr, 6, NULL));

	git3_str_dispose(&full);
}

void test_repo_hashfile__filtered_in_workdir(void)
{
	git3_str root = GIT3_STR_INIT, txt = GIT3_STR_INIT, bin = GIT3_STR_INIT;
	char cwd[GIT3_PATH_MAX];
	git3_oid a, b;

	cl_must_pass(p_getcwd(cwd, GIT3_PATH_MAX));
	cl_must_pass(p_mkdir("absolute", 0777));
	cl_git_pass(git3_str_joinpath(&root, cwd, "status"));
	cl_git_pass(git3_str_joinpath(&txt, root.ptr, "testfile.txt"));
	cl_git_pass(git3_str_joinpath(&bin, root.ptr, "testfile.bin"));

	cl_repo_set_bool(_repo, "core.autocrlf", true);

	cl_git_append2file("status/.gitattributes", "*.txt text\n*.bin binary\n\n");

	/* create some sample content with CRLF in it */
	cl_git_mkfile("status/testfile.txt", "content\r\n");
	cl_git_mkfile("status/testfile.bin", "other\r\nstuff\r\n");

	/* not equal hashes because of filtering */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.txt", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, "testfile.txt", GIT3_OBJECT_BLOB, NULL));
	cl_assert(git3_oid_cmp(&a, &b));

	/* not equal hashes because of filtering when specified by absolute path */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.txt", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, txt.ptr, GIT3_OBJECT_BLOB, NULL));
	cl_assert(git3_oid_cmp(&a, &b));

	/* equal hashes because filter is binary */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.bin", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, "testfile.bin", GIT3_OBJECT_BLOB, NULL));
	cl_assert_equal_oid(&a, &b);

	/* equal hashes because filter is binary when specified by absolute path */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.bin", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, bin.ptr, GIT3_OBJECT_BLOB, NULL));
	cl_assert_equal_oid(&a, &b);

	/* equal hashes when 'as_file' points to binary filtering */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.txt", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, "testfile.txt", GIT3_OBJECT_BLOB, "foo.bin"));
	cl_assert_equal_oid(&a, &b);

	/* equal hashes when 'as_file' points to binary filtering (absolute path) */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.txt", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, txt.ptr, GIT3_OBJECT_BLOB, "foo.bin"));
	cl_assert_equal_oid(&a, &b);

	/* not equal hashes when 'as_file' points to text filtering */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.bin", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, "testfile.bin", GIT3_OBJECT_BLOB, "foo.txt"));
	cl_assert(git3_oid_cmp(&a, &b));

	/* not equal hashes when 'as_file' points to text filtering */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.bin", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, bin.ptr, GIT3_OBJECT_BLOB, "foo.txt"));
	cl_assert(git3_oid_cmp(&a, &b));

	/* equal hashes when 'as_file' is empty and turns off filtering */
	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.txt", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, "testfile.txt", GIT3_OBJECT_BLOB, ""));
	cl_assert_equal_oid(&a, &b);

	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.bin", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, "testfile.bin", GIT3_OBJECT_BLOB, ""));
	cl_assert_equal_oid(&a, &b);

	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.txt", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, txt.ptr, GIT3_OBJECT_BLOB, ""));
	cl_assert_equal_oid(&a, &b);

	cl_git_pass(git3_odb__hashfile(&a, "status/testfile.bin", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, bin.ptr, GIT3_OBJECT_BLOB, ""));
	cl_assert_equal_oid(&a, &b);

	/* some hash type failures */
	cl_git_fail(git3_odb__hashfile(&a, "status/testfile.txt", 0, GIT3_OID_SHA1));
	cl_git_fail(git3_repository_hashfile(&b, _repo, "testfile.txt", GIT3_OBJECT_ANY, NULL));

	git3_str_dispose(&txt);
	git3_str_dispose(&bin);
	git3_str_dispose(&root);
}

void test_repo_hashfile__filtered_outside_workdir(void)
{
	git3_str root = GIT3_STR_INIT, txt = GIT3_STR_INIT, bin = GIT3_STR_INIT;
	char cwd[GIT3_PATH_MAX];
	git3_oid a, b;

	cl_must_pass(p_getcwd(cwd, GIT3_PATH_MAX));
	cl_must_pass(p_mkdir("absolute", 0777));
	cl_git_pass(git3_str_joinpath(&root, cwd, "absolute"));
	cl_git_pass(git3_str_joinpath(&txt, root.ptr, "testfile.txt"));
	cl_git_pass(git3_str_joinpath(&bin, root.ptr, "testfile.bin"));

	cl_repo_set_bool(_repo, "core.autocrlf", true);
	cl_git_append2file("status/.gitattributes", "*.txt text\n*.bin binary\n\n");

	/* create some sample content with CRLF in it */
	cl_git_mkfile("absolute/testfile.txt", "content\r\n");
	cl_git_mkfile("absolute/testfile.bin", "other\r\nstuff\r\n");

	/* not equal hashes because of filtering */
	cl_git_pass(git3_odb__hashfile(&a, "absolute/testfile.txt", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, txt.ptr, GIT3_OBJECT_BLOB, "testfile.txt"));
	cl_assert(git3_oid_cmp(&a, &b));

	/* equal hashes because filter is binary */
	cl_git_pass(git3_odb__hashfile(&a, "absolute/testfile.bin", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, bin.ptr, GIT3_OBJECT_BLOB, "testfile.bin"));
	cl_assert_equal_oid(&a, &b);

	/*
	 * equal hashes because no filtering occurs for absolute paths outside the working
	 * directory unless as_path is specified
	 */
	cl_git_pass(git3_odb__hashfile(&a, "absolute/testfile.txt", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, txt.ptr, GIT3_OBJECT_BLOB, NULL));
	cl_assert_equal_oid(&a, &b);

	cl_git_pass(git3_odb__hashfile(&a, "absolute/testfile.bin", GIT3_OBJECT_BLOB, GIT3_OID_SHA1));
	cl_git_pass(git3_repository_hashfile(&b, _repo, bin.ptr, GIT3_OBJECT_BLOB, NULL));
	cl_assert_equal_oid(&a, &b);

	git3_str_dispose(&txt);
	git3_str_dispose(&bin);
	git3_str_dispose(&root);
}
