#include "clar_libgit3.h"
#include "git3/rebase.h"
#include "merge.h"
#include "posix.h"
#include "annotated_commit.h"

#include <fcntl.h>

static git3_repository *repo;

/* Fixture setup and teardown */
void test_rebase_abort__initialize(void)
{
	repo = cl_git_sandbox_init("rebase");
}

void test_rebase_abort__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

static void ensure_aborted(
	git3_annotated_commit *branch,
	git3_annotated_commit *onto)
{
	git3_reference *head_ref, *branch_ref = NULL;
	git3_status_list *statuslist;
	git3_reflog *reflog;
	const git3_reflog_entry *reflog_entry;

	cl_assert_equal_i(GIT3_REPOSITORY_STATE_NONE, git3_repository_state(repo));

	/* Make sure the refs are updated appropriately */
	cl_git_pass(git3_reference_lookup(&head_ref, repo, "HEAD"));

	if (branch->ref_name == NULL)
		cl_assert_equal_oid(git3_annotated_commit_id(branch), git3_reference_target(head_ref));
	else {
		cl_assert_equal_s("refs/heads/beef", git3_reference_symbolic_target(head_ref));
		cl_git_pass(git3_reference_lookup(&branch_ref, repo, git3_reference_symbolic_target(head_ref)));
		cl_assert_equal_oid(git3_annotated_commit_id(branch), git3_reference_target(branch_ref));
	}

	git3_status_list_new(&statuslist, repo, NULL);
	cl_assert_equal_i(0, git3_status_list_entrycount(statuslist));
	git3_status_list_free(statuslist);

	/* Make sure the reflogs are updated appropriately */
	cl_git_pass(git3_reflog_read(&reflog, repo, "HEAD"));

	cl_assert(reflog_entry = git3_reflog_entry_byindex(reflog, 0));
	cl_assert_equal_oid(git3_annotated_commit_id(onto), git3_reflog_entry_id_old(reflog_entry));
	cl_assert_equal_oid(git3_annotated_commit_id(branch), git3_reflog_entry_id_new(reflog_entry));
	cl_assert_equal_s("rebase: aborting", git3_reflog_entry_message(reflog_entry));

	git3_reflog_free(reflog);
	git3_reference_free(head_ref);
	git3_reference_free(branch_ref);
}

static void test_abort(
	git3_annotated_commit *branch, git3_annotated_commit *onto)
{
	git3_rebase *rebase;

	cl_git_pass(git3_rebase_open(&rebase, repo, NULL));
	cl_git_pass(git3_rebase_abort(rebase));

	ensure_aborted(branch, onto);

	git3_rebase_free(rebase);
}

void test_rebase_abort__merge(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *onto_ref;
	git3_annotated_commit *branch_head, *onto_head;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/beef"));
	cl_git_pass(git3_reference_lookup(&onto_ref, repo, "refs/heads/master"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&onto_head, repo, onto_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, NULL, onto_head, NULL));
	cl_assert_equal_i(GIT3_REPOSITORY_STATE_REBASE_MERGE, git3_repository_state(repo));

	test_abort(branch_head, onto_head);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(onto_head);

	git3_reference_free(branch_ref);
	git3_reference_free(onto_ref);
	git3_rebase_free(rebase);
}

void test_rebase_abort__merge_immediately_after_init(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *onto_ref;
	git3_annotated_commit *branch_head, *onto_head;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/beef"));
	cl_git_pass(git3_reference_lookup(&onto_ref, repo, "refs/heads/master"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&onto_head, repo, onto_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, NULL, onto_head, NULL));
	cl_assert_equal_i(GIT3_REPOSITORY_STATE_REBASE_MERGE, git3_repository_state(repo));

	cl_git_pass(git3_rebase_abort(rebase));
	ensure_aborted(branch_head, onto_head);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(onto_head);

	git3_reference_free(branch_ref);
	git3_reference_free(onto_ref);
	git3_rebase_free(rebase);
}

void test_rebase_abort__merge_by_id(void)
{
	git3_rebase *rebase;
	git3_oid branch_id, onto_id;
	git3_annotated_commit *branch_head, *onto_head;

	cl_git_pass(git3_oid_from_string(&branch_id, "b146bd7608eac53d9bf9e1a6963543588b555c64", GIT3_OID_SHA1));
	cl_git_pass(git3_oid_from_string(&onto_id, "efad0b11c47cb2f0220cbd6f5b0f93bb99064b00", GIT3_OID_SHA1));

	cl_git_pass(git3_annotated_commit_lookup(&branch_head, repo, &branch_id));
	cl_git_pass(git3_annotated_commit_lookup(&onto_head, repo, &onto_id));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, NULL, onto_head, NULL));
	cl_assert_equal_i(GIT3_REPOSITORY_STATE_REBASE_MERGE, git3_repository_state(repo));

	test_abort(branch_head, onto_head);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(onto_head);

	git3_rebase_free(rebase);
}

void test_rebase_abort__merge_by_revspec(void)
{
	git3_rebase *rebase;
	git3_annotated_commit *branch_head, *onto_head;

	cl_git_pass(git3_annotated_commit_from_revspec(&branch_head, repo, "b146bd7"));
	cl_git_pass(git3_annotated_commit_from_revspec(&onto_head, repo, "efad0b1"));
	
	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, NULL, onto_head, NULL));
	cl_assert_equal_i(GIT3_REPOSITORY_STATE_REBASE_MERGE, git3_repository_state(repo));

	test_abort(branch_head, onto_head);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(onto_head);

	git3_rebase_free(rebase);
}

void test_rebase_abort__merge_by_id_immediately_after_init(void)
{
	git3_rebase *rebase;
	git3_oid branch_id, onto_id;
	git3_annotated_commit *branch_head, *onto_head;

	cl_git_pass(git3_oid_from_string(&branch_id, "b146bd7608eac53d9bf9e1a6963543588b555c64", GIT3_OID_SHA1));
	cl_git_pass(git3_oid_from_string(&onto_id, "efad0b11c47cb2f0220cbd6f5b0f93bb99064b00", GIT3_OID_SHA1));

	cl_git_pass(git3_annotated_commit_lookup(&branch_head, repo, &branch_id));
	cl_git_pass(git3_annotated_commit_lookup(&onto_head, repo, &onto_id));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, NULL, onto_head, NULL));
	cl_assert_equal_i(GIT3_REPOSITORY_STATE_REBASE_MERGE, git3_repository_state(repo));

	cl_git_pass(git3_rebase_abort(rebase));
	ensure_aborted(branch_head, onto_head);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(onto_head);

	git3_rebase_free(rebase);
}

void test_rebase_abort__detached_head(void)
{
	git3_rebase *rebase;
	git3_oid branch_id, onto_id;
	git3_signature *signature;
	git3_annotated_commit *branch_head, *onto_head;

	git3_oid_from_string(&branch_id, "b146bd7608eac53d9bf9e1a6963543588b555c64", GIT3_OID_SHA1);
    git3_oid_from_string(&onto_id, "efad0b11c47cb2f0220cbd6f5b0f93bb99064b00", GIT3_OID_SHA1);

	cl_git_pass(git3_annotated_commit_lookup(&branch_head, repo, &branch_id));
	cl_git_pass(git3_annotated_commit_lookup(&onto_head, repo, &onto_id));

	cl_git_pass(git3_signature_new(&signature, "Rebaser", "rebaser@example.com", 1404157834, -400));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, NULL, onto_head, NULL));
	cl_assert_equal_i(GIT3_REPOSITORY_STATE_REBASE_MERGE, git3_repository_state(repo));

	test_abort(branch_head, onto_head);

	git3_signature_free(signature);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(onto_head);

	git3_rebase_free(rebase);
}

void test_rebase_abort__old_style_head_file(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *onto_ref;
	git3_signature *signature;
	git3_annotated_commit *branch_head, *onto_head;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/beef"));
	cl_git_pass(git3_reference_lookup(&onto_ref, repo, "refs/heads/master"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&onto_head, repo, onto_ref));

	cl_git_pass(git3_signature_new(&signature, "Rebaser", "rebaser@example.com", 1404157834, -400));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, NULL, onto_head, NULL));
	cl_assert_equal_i(GIT3_REPOSITORY_STATE_REBASE_MERGE, git3_repository_state(repo));

	p_rename("rebase-merge/.git/rebase-merge/orig-head",
		"rebase-merge/.git/rebase-merge/head");

	test_abort(branch_head, onto_head);

	git3_signature_free(signature);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(onto_head);

	git3_reference_free(branch_ref);
	git3_reference_free(onto_ref);
	git3_rebase_free(rebase);
}
