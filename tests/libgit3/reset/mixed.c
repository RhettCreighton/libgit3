#include "clar_libgit3.h"
#include "posix.h"
#include "reset_helpers.h"
#include "path.h"

static git3_repository *repo;
static git3_object *target;

void test_reset_mixed__initialize(void)
{
	repo = cl_git_sandbox_init("attr");
	target = NULL;
}

void test_reset_mixed__cleanup(void)
{
	git3_object_free(target);
	target = NULL;

	cl_git_sandbox_cleanup();
}

void test_reset_mixed__cannot_reset_in_a_bare_repository(void)
{
	git3_repository *bare;

	cl_git_pass(git3_repository_open(&bare, cl_fixture("testrepo.git")));
	cl_assert(git3_repository_is_bare(bare) == true);

	cl_git_pass(git3_revparse_single(&target, bare, KNOWN_COMMIT_IN_BARE_REPO));

	cl_assert_equal_i(GIT3_EBAREREPO, git3_reset(bare, target, GIT3_RESET_MIXED, NULL));

	git3_repository_free(bare);
}

void test_reset_mixed__resetting_refreshes_the_index_to_the_commit_tree(void)
{
	unsigned int status;

	cl_git_pass(git3_status_file(&status, repo, "macro_bad"));
	cl_assert(status == GIT3_STATUS_CURRENT);
	cl_git_pass(git3_revparse_single(&target, repo, "605812a"));

	cl_git_pass(git3_reset(repo, target, GIT3_RESET_MIXED, NULL));

	cl_git_pass(git3_status_file(&status, repo, "macro_bad"));
	cl_assert(status == GIT3_STATUS_WT_NEW);
}

void test_reset_mixed__reflog_is_correct(void)
{
	git3_str buf = GIT3_STR_INIT;
	git3_annotated_commit *annotated;
	const char *exp_msg = "commit: Updating test data so we can test inter-hunk-context";

	reflog_check(repo, "HEAD", 9, "yoram.harmelin@gmail.com", exp_msg);
	reflog_check(repo, "refs/heads/master", 9, "yoram.harmelin@gmail.com", exp_msg);

	/* Branch not moving, no reflog entry */
	cl_git_pass(git3_revparse_single(&target, repo, "HEAD^{commit}"));
	cl_git_pass(git3_reset(repo, target, GIT3_RESET_MIXED, NULL));
	reflog_check(repo, "HEAD", 9, "yoram.harmelin@gmail.com", exp_msg);
	reflog_check(repo, "refs/heads/master", 9, "yoram.harmelin@gmail.com", exp_msg);

	git3_object_free(target);
	target = NULL;

	/* Moved branch, expect id in message */
	cl_git_pass(git3_revparse_single(&target, repo, "HEAD~^{commit}"));
	git3_str_clear(&buf);
	cl_git_pass(git3_str_printf(&buf, "reset: moving to %s", git3_oid_tostr_s(git3_object_id(target))));
	cl_git_pass(git3_reset(repo, target, GIT3_RESET_MIXED, NULL));
	reflog_check(repo, "HEAD", 10, NULL, git3_str_cstr(&buf));
	reflog_check(repo, "refs/heads/master", 10, NULL, git3_str_cstr(&buf));
	git3_str_dispose(&buf);

	/* Moved branch, expect revspec in message */
	exp_msg = "reset: moving to HEAD~^{commit}";
	cl_git_pass(git3_annotated_commit_from_revspec(&annotated, repo, "HEAD~^{commit}"));
	cl_git_pass(git3_reset_from_annotated(repo, annotated, GIT3_RESET_MIXED, NULL));
	reflog_check(repo, "HEAD", 11, NULL, exp_msg);
	reflog_check(repo, "refs/heads/master", 11, NULL, exp_msg);
	git3_annotated_commit_free(annotated);
}
