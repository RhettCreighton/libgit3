#include "clar_libgit3.h"
#include "git3/rebase.h"
#include "posix.h"

#include <fcntl.h>

static git3_repository *repo;
static git3_index *_index;
static git3_signature *signature;

/* Fixture setup and teardown */
void test_rebase_iterator__initialize(void)
{
	repo = cl_git_sandbox_init("rebase");
	cl_git_pass(git3_repository_index(&_index, repo));
	cl_git_pass(git3_signature_new(&signature, "Rebaser",
		"rebaser@rebaser.rb", 1405694510, 0));
}

void test_rebase_iterator__cleanup(void)
{
	git3_signature_free(signature);
	git3_index_free(_index);
	cl_git_sandbox_cleanup();
}

static void test_operations(git3_rebase *rebase, size_t expected_current)
{
	size_t i, expected_count = 5;
	git3_oid expected_oid[5];
	git3_rebase_operation *operation;

	git3_oid_from_string(&expected_oid[0], "da9c51a23d02d931a486f45ad18cda05cf5d2b94", GIT3_OID_SHA1);
	git3_oid_from_string(&expected_oid[1], "8d1f13f93c4995760ac07d129246ac1ff64c0be9", GIT3_OID_SHA1);
	git3_oid_from_string(&expected_oid[2], "3069cc907e6294623e5917ef6de663928c1febfb", GIT3_OID_SHA1);
	git3_oid_from_string(&expected_oid[3], "588e5d2f04d49707fe4aab865e1deacaf7ef6787", GIT3_OID_SHA1);
	git3_oid_from_string(&expected_oid[4], "b146bd7608eac53d9bf9e1a6963543588b555c64", GIT3_OID_SHA1);

	cl_assert_equal_i(expected_count, git3_rebase_operation_entrycount(rebase));
	cl_assert_equal_i(expected_current, git3_rebase_operation_current(rebase));

	for (i = 0; i < expected_count; i++) {
		operation = git3_rebase_operation_byindex(rebase, i);
		cl_assert_equal_i(GIT3_REBASE_OPERATION_PICK, operation->type);
		cl_assert_equal_oid(&expected_oid[i], &operation->id);
		cl_assert_equal_p(NULL, operation->exec);
	}
}

static void test_iterator(bool inmemory)
{
	git3_rebase *rebase;
	git3_rebase_options opts = GIT3_REBASE_OPTIONS_INIT;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_oid commit_id, expected_id;
	int error;

	opts.inmemory = inmemory;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/beef"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/master"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &opts));
	test_operations(rebase, GIT3_REBASE_NO_OPERATION);

	if (!inmemory) {
		git3_rebase_free(rebase);
		cl_git_pass(git3_rebase_open(&rebase, repo, NULL));
	}

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));
	test_operations(rebase, 0);

	git3_oid_from_string(&expected_id, "776e4c48922799f903f03f5f6e51da8b01e4cce0", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));
	test_operations(rebase, 1);

	git3_oid_from_string(&expected_id, "ba1f9b4fd5cf8151f7818be2111cc0869f1eb95a", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));
	test_operations(rebase, 2);

	git3_oid_from_string(&expected_id, "948b12fe18b84f756223a61bece4c307787cd5d4", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	if (!inmemory) {
		git3_rebase_free(rebase);
		cl_git_pass(git3_rebase_open(&rebase, repo, NULL));
	}

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));
	test_operations(rebase, 3);

	git3_oid_from_string(&expected_id, "d9d5d59d72c9968687f9462578d79878cd80e781", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));
	test_operations(rebase, 4);

	git3_oid_from_string(&expected_id, "9cf383c0a125d89e742c5dec58ed277dd07588b3", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_id, &commit_id);

	cl_git_fail(error = git3_rebase_next(&rebase_operation, rebase));
	cl_assert_equal_i(GIT3_ITEROVER, error);
	test_operations(rebase, 4);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_rebase_free(rebase);
}

void test_rebase_iterator__iterates(void)
{
	test_iterator(false);
}

void test_rebase_iterator__iterates_inmemory(void)
{
	test_iterator(true);
}
