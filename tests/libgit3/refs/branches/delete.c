#include "clar_libgit3.h"
#include "refs.h"
#include "repo/repo_helpers.h"
#include "config/config_helpers.h"
#include "futils.h"
#include "reflog.h"

static git3_repository *repo;
static git3_reference *fake_remote;

void test_refs_branches_delete__initialize(void)
{
	git3_oid id;

	repo = cl_git_sandbox_init("testrepo.git");

	cl_git_pass(git3_oid_from_string(&id, "be3563ae3f795b2b4353bcce3a527ad0a4f7f644", GIT3_OID_SHA1));
	cl_git_pass(git3_reference_create(&fake_remote, repo, "refs/remotes/nulltoken/master", &id, 0, NULL));
}

void test_refs_branches_delete__cleanup(void)
{
	git3_reference_free(fake_remote);
	fake_remote = NULL;

	cl_git_sandbox_cleanup();
	repo = NULL;
}

void test_refs_branches_delete__can_not_delete_a_branch_pointed_at_by_HEAD(void)
{
	git3_reference *head;
	git3_reference *branch;

	/* Ensure HEAD targets the local master branch */
	cl_git_pass(git3_reference_lookup(&head, repo, GIT3_HEAD_FILE));
	cl_assert_equal_s("refs/heads/master", git3_reference_symbolic_target(head));
	git3_reference_free(head);

	cl_git_pass(git3_branch_lookup(&branch, repo, "master", GIT3_BRANCH_LOCAL));
	cl_git_fail(git3_branch_delete(branch));
	git3_reference_free(branch);
}

void test_refs_branches_delete__can_delete_a_branch_even_if_HEAD_is_missing(void)
{
	git3_reference *head;
	git3_reference *branch;

	cl_git_pass(git3_reference_lookup(&head, repo, GIT3_HEAD_FILE));
	git3_reference_delete(head);
	git3_reference_free(head);

	cl_git_pass(git3_branch_lookup(&branch, repo, "br2", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);
}

void test_refs_branches_delete__can_delete_a_branch_when_HEAD_is_unborn(void)
{
	git3_reference *branch;

	make_head_unborn(repo, NON_EXISTING_HEAD);

	cl_git_pass(git3_branch_lookup(&branch, repo, "br2", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);
}

void test_refs_branches_delete__can_delete_a_branch_pointed_at_by_detached_HEAD(void)
{
	git3_reference *head, *branch;

	cl_git_pass(git3_reference_lookup(&head, repo, GIT3_HEAD_FILE));
	cl_assert_equal_i(GIT3_REFERENCE_SYMBOLIC, git3_reference_type(head));
	cl_assert_equal_s("refs/heads/master", git3_reference_symbolic_target(head));
	git3_reference_free(head);

	/* Detach HEAD and make it target the commit that "master" points to */
	git3_repository_detach_head(repo);

	cl_git_pass(git3_branch_lookup(&branch, repo, "master", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);
}

void test_refs_branches_delete__can_delete_a_local_branch(void)
{
	git3_reference *branch;
	cl_git_pass(git3_branch_lookup(&branch, repo, "br2", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);
}

void test_refs_branches_delete__can_delete_a_local_branch_with_multivar(void)
{
	git3_reference *branch;
	git3_config *cfg;

	cl_git_pass(git3_repository_config(&cfg, repo));
	cl_git_pass(git3_config_set_multivar(
	        cfg, "branch.br2.gitpublishto", "^$", "example1@example.com"));
	cl_git_pass(git3_config_set_multivar(
	        cfg, "branch.br2.gitpublishto", "^$", "example2@example.com"));
	cl_git_pass(git3_branch_lookup(&branch, repo, "br2", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);
}

void test_refs_branches_delete__can_delete_a_remote_branch(void)
{
	git3_reference *branch;
	cl_git_pass(git3_branch_lookup(&branch, repo, "nulltoken/master", GIT3_BRANCH_REMOTE));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);
}

void test_refs_branches_delete__deleting_a_branch_removes_related_configuration_data(void)
{
	git3_reference *branch;

	assert_config_entry_existence(repo, "branch.track-local.remote", true);
	assert_config_entry_existence(repo, "branch.track-local.merge", true);

	cl_git_pass(git3_branch_lookup(&branch, repo, "track-local", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);

	assert_config_entry_existence(repo, "branch.track-local.remote", false);
	assert_config_entry_existence(repo, "branch.track-local.merge", false);
}

void test_refs_branches_delete__removes_reflog(void)
{
	git3_reference *branch;
	git3_reflog *log;
	git3_oid oidzero = GIT3_OID_SHA1_ZERO;
	git3_signature *sig;

	/* Ensure the reflog has at least one entry */
	cl_git_pass(git3_signature_now(&sig, "Me", "user@example.com"));
	cl_git_pass(git3_reflog_read(&log, repo, "refs/heads/track-local"));
	cl_git_pass(git3_reflog_append(log, &oidzero, sig, "message"));
	cl_assert(git3_reflog_entrycount(log) > 0);
	git3_signature_free(sig);
	git3_reflog_free(log);

	cl_git_pass(git3_branch_lookup(&branch, repo, "track-local", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);

	cl_assert_equal_i(false, git3_reference_has_log(repo, "refs/heads/track-local"));

	/* Reading a non-existent reflog creates it, but it should be empty */
	cl_git_pass(git3_reflog_read(&log, repo, "refs/heads/track-local"));
	cl_assert_equal_i(0, git3_reflog_entrycount(log));
	git3_reflog_free(log);
}

void test_refs_branches_delete__removes_empty_folders(void)
{
	const char *commondir = git3_repository_commondir(repo);
	git3_oid commit_id;
	git3_commit *commit;
	git3_reference *branch;

	git3_reflog *log;
	git3_oid oidzero = GIT3_OID_SHA1_ZERO;
	git3_signature *sig;

	git3_str ref_folder = GIT3_STR_INIT;
	git3_str reflog_folder = GIT3_STR_INIT;

	/* Create a new branch with a nested name */
	cl_git_pass(git3_oid_from_string(&commit_id, "a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OID_SHA1));
	cl_git_pass(git3_commit_lookup(&commit, repo, &commit_id));
	cl_git_pass(git3_branch_create(&branch, repo, "some/deep/ref", commit, 0));
	git3_commit_free(commit);

	/* Ensure the reflog has at least one entry */
	cl_git_pass(git3_signature_now(&sig, "Me", "user@example.com"));
	cl_git_pass(git3_reflog_read(&log, repo, "refs/heads/some/deep/ref"));
	cl_git_pass(git3_reflog_append(log, &oidzero, sig, "message"));
	cl_assert(git3_reflog_entrycount(log) > 0);
	git3_signature_free(sig);
	git3_reflog_free(log);

	cl_git_pass(git3_str_joinpath(&ref_folder, commondir, "refs/heads/some/deep"));
	cl_git_pass(git3_str_join3(&reflog_folder, '/', commondir, GIT3_REFLOG_DIR, "refs/heads/some/deep"));

	cl_assert(git3_fs_path_exists(git3_str_cstr(&ref_folder)) == true);
	cl_assert(git3_fs_path_exists(git3_str_cstr(&reflog_folder)) == true);

	cl_git_pass(git3_branch_delete(branch));

	cl_assert(git3_fs_path_exists(git3_str_cstr(&ref_folder)) == false);
	cl_assert(git3_fs_path_exists(git3_str_cstr(&reflog_folder)) == false);

	git3_reference_free(branch);
	git3_str_dispose(&ref_folder);
	git3_str_dispose(&reflog_folder);
}

