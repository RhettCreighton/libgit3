#include "clar_libgit3.h"

#include "futils.h"
#include "git3/reflog.h"
#include "git3/refdb.h"
#include "reflog.h"
#include "refs.h"
#include "ref_helpers.h"

static const char *loose_tag_ref_name = "refs/tags/e90810b";

static git3_repository *g_repo;

void test_refs_pack__initialize(void)
{
   g_repo = cl_git_sandbox_init("testrepo");
}

void test_refs_pack__cleanup(void)
{
   cl_git_sandbox_cleanup();
}

static void packall(void)
{
	git3_refdb *refdb;

	cl_git_pass(git3_repository_refdb(&refdb, g_repo));
	cl_git_pass(git3_refdb_compress(refdb));
	git3_refdb_free(refdb);
}

void test_refs_pack__empty(void)
{
	/* create a packfile for an empty folder */
	git3_str temp_path = GIT3_STR_INIT;

	cl_git_pass(git3_str_join_n(&temp_path, '/', 3, git3_repository_path(g_repo), GIT3_REFS_HEADS_DIR, "empty_dir"));
	cl_git_pass(git3_futils_mkdir_r(temp_path.ptr, GIT3_REFS_DIR_MODE));
	git3_str_dispose(&temp_path);

	packall();
}

void test_refs_pack__loose(void)
{
	/* create a packfile from all the loose refs in a repo */
	git3_reference *reference;
	git3_str temp_path = GIT3_STR_INIT;

	/* Ensure a known loose ref can be looked up */
	cl_git_pass(git3_reference_lookup(&reference, g_repo, loose_tag_ref_name));
	cl_assert(reference_is_packed(reference) == 0);
	cl_assert_equal_s(reference->name, loose_tag_ref_name);
	git3_reference_free(reference);

	/*
	 * We are now trying to pack also a loose reference
	 * called `points_to_blob`, to make sure we can properly
	 * pack weak tags
	 */
	packall();

	/* Ensure the packed-refs file exists */
	cl_git_pass(git3_str_joinpath(&temp_path, git3_repository_path(g_repo), GIT3_PACKEDREFS_FILE));
	cl_assert(git3_fs_path_exists(temp_path.ptr));

	/* Ensure the known ref can still be looked up but is now packed */
	cl_git_pass(git3_reference_lookup(&reference, g_repo, loose_tag_ref_name));
	cl_assert(reference_is_packed(reference));
	cl_assert_equal_s(reference->name, loose_tag_ref_name);

	/* Ensure the known ref has been removed from the loose folder structure */
	cl_git_pass(git3_str_joinpath(&temp_path, git3_repository_path(g_repo), loose_tag_ref_name));
	cl_assert(!git3_fs_path_exists(temp_path.ptr));

	git3_reference_free(reference);
	git3_str_dispose(&temp_path);
}

void test_refs_pack__symbolic(void)
{
	/* create a packfile from loose refs skipping symbolic refs */
	int i;
	git3_oid head;
	git3_reference *ref;
	char name[128];

	cl_git_pass(git3_reference_name_to_id(&head, g_repo, "HEAD"));

	/* make a bunch of references */

	for (i = 0; i < 100; ++i) {
		p_snprintf(name, sizeof(name), "refs/heads/symbolic-%03d", i);
		cl_git_pass(git3_reference_symbolic_create(
			&ref, g_repo, name, "refs/heads/master", 0, NULL));
		git3_reference_free(ref);

		p_snprintf(name, sizeof(name), "refs/heads/direct-%03d", i);
		cl_git_pass(git3_reference_create(&ref, g_repo, name, &head, 0, NULL));
		git3_reference_free(ref);
	}

	packall();
}
