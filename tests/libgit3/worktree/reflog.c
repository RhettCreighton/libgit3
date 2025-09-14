#include "clar_libgit3.h"
#include "worktree_helpers.h"

#include "reflog.h"

#define COMMON_REPO "testrepo"
#define WORKTREE_REPO "testrepo-worktree"

#define REFLOG "refs/heads/testrepo-worktree"
#define REFLOG_MESSAGE "reflog message"

static worktree_fixture fixture =
	WORKTREE_FIXTURE_INIT(COMMON_REPO, WORKTREE_REPO);

void test_worktree_reflog__initialize(void)
{
	setup_fixture_worktree(&fixture);
}

void test_worktree_reflog__cleanup(void)
{
	cleanup_fixture_worktree(&fixture);
}

void test_worktree_reflog__read_worktree_HEAD(void)
{
	git3_reflog *reflog;
	const git3_reflog_entry *entry;

	cl_git_pass(git3_reflog_read(&reflog, fixture.worktree, "HEAD"));
	cl_assert_equal_i(1, git3_reflog_entrycount(reflog));

	entry = git3_reflog_entry_byindex(reflog, 0);
	cl_assert(entry != NULL);
	cl_assert_equal_s("checkout: moving from 099fabac3a9ea935598528c27f866e34089c2eff to testrepo-worktree", git3_reflog_entry_message(entry));

	git3_reflog_free(reflog);
}

void test_worktree_reflog__read_parent_HEAD(void)
{
	git3_reflog *reflog;

	cl_git_pass(git3_reflog_read(&reflog, fixture.repo, "HEAD"));
	/* there is no logs/HEAD in the parent repo */
	cl_assert_equal_i(0, git3_reflog_entrycount(reflog));

	git3_reflog_free(reflog);
}

void test_worktree_reflog__read(void)
{
	git3_reflog *reflog;
	const git3_reflog_entry *entry;

	cl_git_pass(git3_reflog_read(&reflog, fixture.worktree, REFLOG));
	cl_assert_equal_i(git3_reflog_entrycount(reflog), 1);

	entry = git3_reflog_entry_byindex(reflog, 0);
	cl_assert(entry != NULL);
	cl_assert_equal_s(git3_reflog_entry_message(entry), "branch: Created from HEAD");

	git3_reflog_free(reflog);
}

void test_worktree_reflog__append_then_read(void)
{
	git3_reflog *reflog, *parent_reflog;
	const git3_reflog_entry *entry;
	git3_reference *head;
	git3_signature *sig;
	const git3_oid *oid;

	cl_git_pass(git3_repository_head(&head, fixture.worktree));
	cl_assert((oid = git3_reference_target(head)) != NULL);
	cl_git_pass(git3_signature_now(&sig, "foo", "foo@bar"));

	cl_git_pass(git3_reflog_read(&reflog, fixture.worktree, REFLOG));
	cl_git_pass(git3_reflog_append(reflog, oid, sig, REFLOG_MESSAGE));
	git3_reflog_write(reflog);

	cl_git_pass(git3_reflog_read(&parent_reflog, fixture.repo, REFLOG));
	entry = git3_reflog_entry_byindex(parent_reflog, 0);
	cl_assert(git3_oid_cmp(oid, &entry->oid_old) == 0);
	cl_assert(git3_oid_cmp(oid, &entry->oid_cur) == 0);

	git3_reference_free(head);
	git3_signature_free(sig);
	git3_reflog_free(reflog);
	git3_reflog_free(parent_reflog);
}
