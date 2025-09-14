#include "clar_libgit3.h"

#include "repository.h"

#ifdef GIT3_EXPERIMENTAL_SHA256
static git3_repository *g_repo;
#endif

void test_object_lookup256__initialize(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	g_repo = cl_git_sandbox_init("testrepo_256.git");
#endif
}

void test_object_lookup256__cleanup(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_sandbox_cleanup();
#endif
}

void test_object_lookup256__lookup_wrong_type_returns_enotfound(void)
{
#ifndef GIT3_EXPERIMENTAL_SHA256
	cl_skip();
#else
	const char *commit = "4d46d9719e425ef2dfb5bfba098d0b62e21b2b92d0731892eef70db0870e3744";
	git3_oid oid;
	git3_object *object;

	cl_git_pass(git3_oid_from_string(&oid, commit, GIT3_OID_SHA256));
	cl_assert_equal_i(
		GIT3_ENOTFOUND, git3_object_lookup(&object, g_repo, &oid, GIT3_OBJECT_TAG));
#endif
}

void test_object_lookup256__lookup_nonexisting_returns_enotfound(void)
{
#ifndef GIT3_EXPERIMENTAL_SHA256
	cl_skip();
#else
	const char *unknown = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
	git3_oid oid;
	git3_object *object;

	cl_git_pass(git3_oid_from_string(&oid, unknown, GIT3_OID_SHA256));
	cl_assert_equal_i(
		GIT3_ENOTFOUND, git3_object_lookup(&object, g_repo, &oid, GIT3_OBJECT_ANY));
#endif
}

void test_object_lookup256__lookup_wrong_type_by_abbreviated_id_returns_enotfound(void)
{
#ifndef GIT3_EXPERIMENTAL_SHA256
	cl_skip();
#else
	const char *commit = "4d46d97";
	git3_oid oid;
	git3_object *object;

	cl_git_pass(git3_oid_from_prefix(&oid, commit, strlen(commit), GIT3_OID_SHA256));
	cl_assert_equal_i(
		GIT3_ENOTFOUND, git3_object_lookup_prefix(&object, g_repo, &oid, strlen(commit), GIT3_OBJECT_TAG));
#endif
}

void test_object_lookup256__lookup_wrong_type_eventually_returns_enotfound(void)
{
#ifndef GIT3_EXPERIMENTAL_SHA256
	cl_skip();
#else
	const char *commit = "4d46d9719e425ef2dfb5bfba098d0b62e21b2b92d0731892eef70db0870e3744";
	git3_oid oid;
	git3_object *object;

	cl_git_pass(git3_oid_from_string(&oid, commit, GIT3_OID_SHA256));

	cl_git_pass(git3_object_lookup(&object, g_repo, &oid, GIT3_OBJECT_COMMIT));
	git3_object_free(object);

	cl_assert_equal_i(
		GIT3_ENOTFOUND, git3_object_lookup(&object, g_repo, &oid, GIT3_OBJECT_TAG));
#endif
}

void test_object_lookup256__lookup_corrupt_object_returns_error(void)
{
#ifndef GIT3_EXPERIMENTAL_SHA256
	cl_skip();
#else
	const char *commit = "5ca8959deb2b8327458e0344523eb1ddeeef4bce03e35864640b452f84d26848",
	      *file = "objects/5c/a8959deb2b8327458e0344523eb1ddeeef4bce03e35864640b452f84d26848";
	git3_str path = GIT3_STR_INIT, contents = GIT3_STR_INIT;
	git3_oid oid;
	git3_object *object;
	size_t i;

	cl_git_pass(git3_oid_from_string(&oid, commit, GIT3_OID_SHA256));
	cl_git_pass(git3_str_joinpath(&path, git3_repository_path(g_repo), file));
	cl_git_pass(git3_futils_readbuffer(&contents, path.ptr));

	/* Corrupt and try to read the object */
	for (i = 0; i < contents.size; i++) {
		contents.ptr[i] ^= 0x1;
		cl_git_pass(git3_futils_writebuffer(&contents, path.ptr, O_RDWR, 0644));
		cl_git_fail(git3_object_lookup(&object, g_repo, &oid, GIT3_OBJECT_COMMIT));
		contents.ptr[i] ^= 0x1;
	}

	/* Restore original content and assert we can read the object */
	cl_git_pass(git3_futils_writebuffer(&contents, path.ptr, O_RDWR, 0644));
	cl_git_pass(git3_object_lookup(&object, g_repo, &oid, GIT3_OBJECT_COMMIT));

	git3_object_free(object);
	git3_str_dispose(&path);
	git3_str_dispose(&contents);
#endif
}

void test_object_lookup256__lookup_object_with_wrong_hash_returns_error(void)
{
#ifndef GIT3_EXPERIMENTAL_SHA256
	cl_skip();
#else
	const char *oldloose = "objects/5c/a8959deb2b8327458e0344523eb1ddeeef4bce03e35864640b452f84d26848",
	      *newloose = "objects/5c/a8959deb2b8327458e0344523eb1ddeeef4bce03e35864640b452f84d26840",
	      *commit = "5ca8959deb2b8327458e0344523eb1ddeeef4bce03e35864640b452f84d26840";

	git3_str oldpath = GIT3_STR_INIT, newpath = GIT3_STR_INIT;
	git3_object *object;
	git3_oid oid;

	cl_git_pass(git3_oid_from_string(&oid, commit, GIT3_OID_SHA256));

	/* Copy object to another location with wrong hash */
	cl_git_pass(git3_str_joinpath(&oldpath, git3_repository_path(g_repo), oldloose));
	cl_git_pass(git3_str_joinpath(&newpath, git3_repository_path(g_repo), newloose));
	cl_git_pass(git3_futils_cp(oldpath.ptr, newpath.ptr, 0644));

	/* Verify that lookup fails due to a hashsum mismatch */
	cl_git_fail_with(GIT3_EMISMATCH, git3_object_lookup(&object, g_repo, &oid, GIT3_OBJECT_COMMIT));

	/* Disable verification and try again */
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_ENABLE_STRICT_HASH_VERIFICATION, 0));
	cl_git_pass(git3_object_lookup(&object, g_repo, &oid, GIT3_OBJECT_COMMIT));
	cl_git_pass(git3_libgit3_opts(GIT3_OPT_ENABLE_STRICT_HASH_VERIFICATION, 1));

	git3_object_free(object);
	git3_str_dispose(&oldpath);
	git3_str_dispose(&newpath);
#endif
}
