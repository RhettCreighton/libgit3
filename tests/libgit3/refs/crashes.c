#include "clar_libgit3.h"
#include "refs.h"

void test_refs_crashes__double_free(void)
{
	git3_repository *repo;
	git3_reference *ref, *ref2;
	const char *REFNAME = "refs/heads/xxx";

	repo = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(git3_reference_symbolic_create(&ref, repo, REFNAME, "refs/heads/master", 0, NULL));
	cl_git_pass(git3_reference_lookup(&ref2, repo, REFNAME));
	cl_git_pass(git3_reference_delete(ref));
	git3_reference_free(ref);
	git3_reference_free(ref2);

	/* reference is gone from disk, so reloading it will fail */
	cl_git_fail(git3_reference_lookup(&ref2, repo, REFNAME));

	cl_git_sandbox_cleanup();
}

void test_refs_crashes__empty_packedrefs(void)
{
	git3_repository *repo;
	git3_reference *ref;
	const char *REFNAME = "refs/heads/xxx";
	git3_str temp_path = GIT3_STR_INIT;
	int fd = 0;

	repo = cl_git_sandbox_init("empty_bare.git");

	/* create zero-length packed-refs file */
	cl_git_pass(git3_str_joinpath(&temp_path, git3_repository_path(repo), GIT3_PACKEDREFS_FILE));
	cl_git_pass(((fd = p_creat(temp_path.ptr, 0644)) < 0));
	cl_git_pass(p_close(fd));

	/* should fail gracefully */
	cl_git_fail_with(
	        GIT3_ENOTFOUND, git3_reference_lookup(&ref, repo, REFNAME));

	cl_git_sandbox_cleanup();
	git3_str_dispose(&temp_path);
}
