#include "clar_libgit3.h"
#include "git3/rebase.h"
#include "posix.h"

#include <fcntl.h>

static git3_repository *repo;
static git3_signature *signature;

/* Fixture setup and teardown */
void test_rebase_inmemory__initialize(void)
{
	repo = cl_git_sandbox_init("rebase");

	cl_git_pass(git3_signature_new(&signature,
		"Rebaser", "rebaser@rebaser.rb", 1405694510, 0));
}

void test_rebase_inmemory__cleanup(void)
{
	git3_signature_free(signature);
	cl_git_sandbox_cleanup();
}

void test_rebase_inmemory__not_in_rebase_state(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_options opts = GIT3_REBASE_OPTIONS_INIT;

	opts.inmemory = true;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/beef"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/master"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &opts));

	cl_assert_equal_i(GIT3_REPOSITORY_STATE_NONE, git3_repository_state(repo));

	git3_rebase_free(rebase);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);

	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
}

void test_rebase_inmemory__can_resolve_conflicts(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_status_list *status_list;
	git3_oid pick_id, commit_id, expected_commit_id;
	git3_index *rebase_index, *repo_index;
	git3_index_entry resolution = {{0}};
	git3_rebase_options opts = GIT3_REBASE_OPTIONS_INIT;

	opts.inmemory = true;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/asparagus"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/master"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));

	git3_oid_from_string(&pick_id, "33f915f9e4dbd9f4b24430e48731a59b45b15500", GIT3_OID_SHA1);

	cl_assert_equal_i(GIT3_REBASE_OPERATION_PICK, rebase_operation->type);
	cl_assert_equal_oid(&pick_id, &rebase_operation->id);

	/* ensure that we did not do anything stupid to the workdir or repo index */
	cl_git_pass(git3_repository_index(&repo_index, repo));
	cl_assert(!git3_index_has_conflicts(repo_index));

	cl_git_pass(git3_status_list_new(&status_list, repo, NULL));
	cl_assert_equal_i(0, git3_status_list_entrycount(status_list));

	/* but that the index returned from rebase does have conflicts */
	cl_git_pass(git3_rebase_inmemory_index(&rebase_index, rebase));
	cl_assert(git3_index_has_conflicts(rebase_index));

	cl_git_fail_with(GIT3_EUNMERGED, git3_rebase_commit(&commit_id, rebase, NULL, signature, NULL, NULL));

	/* ensure that we can work with the in-memory index to resolve the conflict */
	resolution.path = "asparagus.txt";
	resolution.mode = GIT3_FILEMODE_BLOB;
	git3_oid_from_string(&resolution.id, "414dfc71ead79c07acd4ea47fecf91f289afc4b9", GIT3_OID_SHA1);
	cl_git_pass(git3_index_conflict_remove(rebase_index, "asparagus.txt"));
	cl_git_pass(git3_index_add(rebase_index, &resolution));

	/* and finally create a commit for the resolved rebase operation */
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature, NULL, NULL));

	cl_git_pass(git3_oid_from_string(&expected_commit_id, "db7af47222181e548810da2ab5fec0e9357c5637", GIT3_OID_SHA1));
	cl_assert_equal_oid(&commit_id, &expected_commit_id);

	git3_status_list_free(status_list);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_index_free(repo_index);
	git3_index_free(rebase_index);
	git3_rebase_free(rebase);
}

void test_rebase_inmemory__no_common_ancestor(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_oid commit_id, expected_final_id;
	git3_rebase_options opts = GIT3_REBASE_OPTIONS_INIT;

	opts.inmemory = true;

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/barley"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/master"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));

	cl_git_pass(git3_rebase_finish(rebase, signature));

	git3_oid_from_string(&expected_final_id, "71e7ee8d4fe7d8bf0d107355197e0a953dfdb7f3", GIT3_OID_SHA1);
	cl_assert_equal_oid(&expected_final_id, &commit_id);

	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_rebase_free(rebase);
}

void test_rebase_inmemory__with_directories(void)
{
	git3_rebase *rebase;
	git3_reference *branch_ref, *upstream_ref;
	git3_annotated_commit *branch_head, *upstream_head;
	git3_rebase_operation *rebase_operation;
	git3_oid commit_id, tree_id;
	git3_commit *commit;
	git3_rebase_options opts = GIT3_REBASE_OPTIONS_INIT;

	opts.inmemory = true;

	git3_oid_from_string(&tree_id, "a4d6d9c3d57308fd8e320cf2525bae8f1adafa57", GIT3_OID_SHA1);

	cl_git_pass(git3_reference_lookup(&branch_ref, repo, "refs/heads/deep_gravy"));
	cl_git_pass(git3_reference_lookup(&upstream_ref, repo, "refs/heads/veal"));

	cl_git_pass(git3_annotated_commit_from_ref(&branch_head, repo, branch_ref));
	cl_git_pass(git3_annotated_commit_from_ref(&upstream_head, repo, upstream_ref));

	cl_git_pass(git3_rebase_init(&rebase, repo, branch_head, upstream_head, NULL, &opts));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));

	cl_git_pass(git3_rebase_next(&rebase_operation, rebase));
	cl_git_pass(git3_rebase_commit(&commit_id, rebase, NULL, signature,
		NULL, NULL));

	cl_git_fail_with(GIT3_ITEROVER, git3_rebase_next(&rebase_operation, rebase));

	cl_git_pass(git3_commit_lookup(&commit, repo, &commit_id));
	cl_assert_equal_oid(&tree_id, git3_commit_tree_id(commit));

	git3_commit_free(commit);
	git3_annotated_commit_free(branch_head);
	git3_annotated_commit_free(upstream_head);
	git3_reference_free(branch_ref);
	git3_reference_free(upstream_ref);
	git3_rebase_free(rebase);
}
