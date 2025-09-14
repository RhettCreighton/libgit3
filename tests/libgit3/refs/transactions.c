#include "clar_libgit3.h"
#include "git3/transaction.h"

static git3_repository *g_repo;
static git3_transaction *g_tx;

void test_refs_transactions__initialize(void)
{
   g_repo = cl_git_sandbox_init("testrepo");
   cl_git_pass(git3_transaction_new(&g_tx, g_repo));
}

void test_refs_transactions__cleanup(void)
{
	git3_transaction_free(g_tx);
	cl_git_sandbox_cleanup();
}

void test_refs_transactions__single_ref_oid(void)
{
	git3_reference *ref;
	git3_oid id;

	git3_oid_from_string(&id, "a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OID_SHA1);

	cl_git_pass(git3_transaction_lock_ref(g_tx, "refs/heads/master"));
	cl_git_pass(git3_transaction_set_target(g_tx, "refs/heads/master", &id, NULL, NULL));
	cl_git_pass(git3_transaction_commit(g_tx));

	cl_git_pass(git3_reference_lookup(&ref, g_repo, "refs/heads/master"));

	cl_assert(!git3_oid_cmp(&id, git3_reference_target(ref)));
	git3_reference_free(ref);
}

void test_refs_transactions__single_ref_symbolic(void)
{
	git3_reference *ref;

	cl_git_pass(git3_transaction_lock_ref(g_tx, "HEAD"));
	cl_git_pass(git3_transaction_set_symbolic_target(g_tx, "HEAD", "refs/heads/foo", NULL, NULL));
	cl_git_pass(git3_transaction_commit(g_tx));

	cl_git_pass(git3_reference_lookup(&ref, g_repo, "HEAD"));

	cl_assert_equal_s("refs/heads/foo", git3_reference_symbolic_target(ref));
	git3_reference_free(ref);
}

void test_refs_transactions__single_ref_mix_types(void)
{
	git3_reference *ref;
	git3_oid id;

	git3_oid_from_string(&id, "a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OID_SHA1);

	cl_git_pass(git3_transaction_lock_ref(g_tx, "refs/heads/master"));
	cl_git_pass(git3_transaction_lock_ref(g_tx, "HEAD"));
	cl_git_pass(git3_transaction_set_symbolic_target(g_tx, "refs/heads/master", "refs/heads/foo", NULL, NULL));
	cl_git_pass(git3_transaction_set_target(g_tx, "HEAD", &id, NULL, NULL));
	cl_git_pass(git3_transaction_commit(g_tx));

	cl_git_pass(git3_reference_lookup(&ref, g_repo, "refs/heads/master"));
	cl_assert_equal_s("refs/heads/foo", git3_reference_symbolic_target(ref));
	git3_reference_free(ref);

	cl_git_pass(git3_reference_lookup(&ref, g_repo, "HEAD"));
	cl_assert(!git3_oid_cmp(&id, git3_reference_target(ref)));
	git3_reference_free(ref);
}

void test_refs_transactions__single_ref_delete(void)
{
	git3_reference *ref;

	cl_git_pass(git3_transaction_lock_ref(g_tx, "refs/heads/master"));
	cl_git_pass(git3_transaction_remove(g_tx, "refs/heads/master"));
	cl_git_pass(git3_transaction_commit(g_tx));

	cl_git_fail_with(GIT3_ENOTFOUND, git3_reference_lookup(&ref, g_repo, "refs/heads/master"));
}

void test_refs_transactions__single_create(void)
{
	git3_reference *ref;
	const char *name = "refs/heads/new-branch";
	git3_oid id;

	cl_git_fail_with(GIT3_ENOTFOUND, git3_reference_lookup(&ref, g_repo, name));

	cl_git_pass(git3_transaction_lock_ref(g_tx, name));

	git3_oid_from_string(&id, "a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OID_SHA1);
	cl_git_pass(git3_transaction_set_target(g_tx, name, &id, NULL, NULL));
	cl_git_pass(git3_transaction_commit(g_tx));

	cl_git_pass(git3_reference_lookup(&ref, g_repo, name));
	cl_assert(!git3_oid_cmp(&id, git3_reference_target(ref)));
	git3_reference_free(ref);
}

void test_refs_transactions__unlocked_set(void)
{
	git3_oid id;

	cl_git_pass(git3_transaction_lock_ref(g_tx, "refs/heads/master"));
	git3_oid_from_string(&id, "a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OID_SHA1);
	cl_git_fail_with(GIT3_ENOTFOUND, git3_transaction_set_target(g_tx, "refs/heads/foo", &id, NULL, NULL));
	cl_git_pass(git3_transaction_commit(g_tx));
}

void test_refs_transactions__error_on_locking_locked_ref(void)
{
	git3_oid id;
	git3_transaction *g_tx_with_lock;
	git3_repository *g_repo_with_locking_tx;
	const char *g_repo_path = git3_repository_path(g_repo);
	
	/* prepare a separate transaction in another instance of testrepo and lock master */
	cl_git_pass(git3_repository_open(&g_repo_with_locking_tx, g_repo_path));
	cl_git_pass(git3_transaction_new(&g_tx_with_lock, g_repo_with_locking_tx));
	cl_git_pass(git3_transaction_lock_ref(g_tx_with_lock, "refs/heads/master"));

	/* lock reference for set_target */
	cl_git_pass(git3_oid_from_string(&id, "a65fedf39aefe402d3bb6e24df4d4f5fe4547750", GIT3_OID_SHA1));
	cl_git_fail_with(GIT3_ELOCKED, git3_transaction_lock_ref(g_tx, "refs/heads/master"));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_transaction_set_target(g_tx, "refs/heads/master", &id, NULL, NULL));

	git3_transaction_free(g_tx_with_lock);
	git3_repository_free(g_repo_with_locking_tx);
}

void test_refs_transactions__commit_unlocks_unmodified_ref(void)
{
	git3_transaction *second_tx;

	cl_git_pass(git3_transaction_new(&second_tx, g_repo));
	cl_git_pass(git3_transaction_lock_ref(second_tx, "refs/heads/master"));
	cl_git_pass(git3_transaction_commit(second_tx));

	/* a transaction must now be able to get the lock */
	cl_git_pass(git3_transaction_lock_ref(g_tx, "refs/heads/master"));

	git3_transaction_free(second_tx);
}

void test_refs_transactions__free_unlocks_unmodified_ref(void)
{
	git3_transaction *second_tx;

	cl_git_pass(git3_transaction_new(&second_tx, g_repo));
	cl_git_pass(git3_transaction_lock_ref(second_tx, "refs/heads/master"));
	git3_transaction_free(second_tx);

	/* a transaction must now be able to get the lock */
	cl_git_pass(git3_transaction_lock_ref(g_tx, "refs/heads/master"));
}
