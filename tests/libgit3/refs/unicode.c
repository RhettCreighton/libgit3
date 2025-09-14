#include "clar_libgit3.h"

static git3_repository *repo;

void test_refs_unicode__initialize(void)
{
	repo = cl_git_sandbox_init("testrepo.git");
}

void test_refs_unicode__cleanup(void)
{
	cl_git_sandbox_cleanup();
	repo = NULL;
}

void test_refs_unicode__create_and_lookup(void)
{
	git3_reference *ref0, *ref1, *ref2;
	git3_repository *repo2;

	const char *REFNAME = "refs/heads/" "\303\205" "ngstr" "\303\266" "m";
	const char *master = "refs/heads/master";

	/* Create the reference */
	cl_git_pass(git3_reference_lookup(&ref0, repo, master));
	cl_git_pass(git3_reference_create(
		&ref1, repo, REFNAME, git3_reference_target(ref0), 0, NULL));
	cl_assert_equal_s(REFNAME, git3_reference_name(ref1));
	git3_reference_free(ref0);

	/* Lookup the reference in a different instance of the repository */
	cl_git_pass(git3_repository_open(&repo2, "testrepo.git"));

	cl_git_pass(git3_reference_lookup(&ref2, repo2, REFNAME));
	cl_assert_equal_oid(git3_reference_target(ref1), git3_reference_target(ref2));
	cl_assert_equal_s(REFNAME, git3_reference_name(ref2));
	git3_reference_free(ref2);

#if GIT3_I18N_ICONV
	/* Lookup reference by decomposed unicode name */

#define REFNAME_DECOMPOSED "refs/heads/" "A" "\314\212" "ngstro" "\314\210" "m"

	cl_git_pass(git3_reference_lookup(&ref2, repo2, REFNAME_DECOMPOSED));
	cl_assert_equal_oid(git3_reference_target(ref1), git3_reference_target(ref2));
	cl_assert_equal_s(REFNAME, git3_reference_name(ref2));
	git3_reference_free(ref2);
#endif

	/* Cleanup */

	git3_reference_free(ref1);
	git3_repository_free(repo2);
}
