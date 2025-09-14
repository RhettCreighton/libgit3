#include "clar_libgit3.h"
#include "path.h"
#include "refs.h"
#include "worktree.h"
#include "worktree_helpers.h"

#define COMMON_REPO "testrepo"
#define WORKTREE_REPO "testrepo-worktree"

static worktree_fixture fixture =
	WORKTREE_FIXTURE_INIT(COMMON_REPO, WORKTREE_REPO);

void test_worktree_refs__initialize(void)
{
	setup_fixture_worktree(&fixture);
}

void test_worktree_refs__cleanup(void)
{
	cleanup_fixture_worktree(&fixture);
}

void test_worktree_refs__list_no_difference_in_worktree(void)
{
	git3_strarray refs, wtrefs;
	unsigned i, j;
	int error = 0;

	cl_git_pass(git3_reference_list(&refs, fixture.repo));
	cl_git_pass(git3_reference_list(&wtrefs, fixture.worktree));

	if (refs.count != wtrefs.count)
	{
		error = GIT3_ERROR;
		goto exit;
	}

	for (i = 0; i < refs.count; i++)
	{
		int found = 0;

		for (j = 0; j < wtrefs.count; j++)
		{
			if (!strcmp(refs.strings[i], wtrefs.strings[j]))
			{
				found = 1;
				break;
			}
		}

		if (!found)
		{
			error = GIT3_ERROR;
			goto exit;
		}
	}

exit:
	git3_strarray_dispose(&refs);
	git3_strarray_dispose(&wtrefs);
	cl_git_pass(error);
}

void test_worktree_refs__list_worktree_specific(void)
{
	git3_strarray refs, wtrefs;
	git3_reference *ref, *new_branch;
	int error = 0;
	git3_oid oid;

	cl_git_pass(git3_reference_name_to_id(&oid, fixture.repo, "refs/heads/dir"));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_reference_lookup(&ref, fixture.repo, "refs/bisect/a-bisect-ref"));
	cl_git_pass(git3_reference_create(
	        &new_branch, fixture.worktree, "refs/bisect/a-bisect-ref", &oid,
	        0, "test"));

	cl_git_fail_with(GIT3_ENOTFOUND, git3_reference_lookup(&ref, fixture.repo, "refs/bisect/a-bisect-ref"));
	cl_git_pass(git3_reference_lookup(&ref, fixture.worktree, "refs/bisect/a-bisect-ref"));

	cl_git_pass(git3_reference_list(&refs, fixture.repo));
	cl_git_pass(git3_reference_list(&wtrefs, fixture.worktree));

	cl_assert_equal_sz(wtrefs.count, refs.count + 1);

	git3_reference_free(ref);
	git3_reference_free(new_branch);
	git3_strarray_dispose(&refs);
	git3_strarray_dispose(&wtrefs);
	cl_git_pass(error);
}

void test_worktree_refs__list_worktree_specific_hidden_in_main_repo(void)
{
	git3_strarray refs, wtrefs;
	git3_reference *ref, *new_branch;
	int error = 0;
	git3_oid oid;

	cl_git_pass(
	        git3_reference_name_to_id(&oid, fixture.repo, "refs/heads/dir"));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_reference_lookup(
	        &ref, fixture.worktree, "refs/bisect/a-bisect-ref"));
	cl_git_pass(git3_reference_create(
	        &new_branch, fixture.repo, "refs/bisect/a-bisect-ref", &oid,
	        0, "test"));

	cl_git_fail_with(GIT3_ENOTFOUND, git3_reference_lookup(
	        &ref, fixture.worktree, "refs/bisect/a-bisect-ref"));
	cl_git_pass(git3_reference_lookup(
	        &ref, fixture.repo, "refs/bisect/a-bisect-ref"));

	cl_git_pass(git3_reference_list(&refs, fixture.repo));
	cl_git_pass(git3_reference_list(&wtrefs, fixture.worktree));

	cl_assert_equal_sz(refs.count, wtrefs.count + 1);

	git3_reference_free(ref);
	git3_reference_free(new_branch);
	git3_strarray_dispose(&refs);
	git3_strarray_dispose(&wtrefs);
	cl_git_pass(error);
}

void test_worktree_refs__read_head(void)
{
	git3_reference *head;

	cl_git_pass(git3_repository_head(&head, fixture.worktree));

	git3_reference_free(head);
}

void test_worktree_refs__set_head_fails_when_worktree_wants_linked_repos_HEAD(void)
{
	git3_reference *head;

	cl_git_pass(git3_repository_head(&head, fixture.repo));
	cl_git_fail(git3_repository_set_head(fixture.worktree, git3_reference_name(head)));

	git3_reference_free(head);
}

void test_worktree_refs__set_head_fails_when_main_repo_wants_worktree_head(void)
{
	git3_reference *head;

	cl_git_pass(git3_repository_head(&head, fixture.worktree));
	cl_git_fail(git3_repository_set_head(fixture.repo, git3_reference_name(head)));

	git3_reference_free(head);
}

void test_worktree_refs__set_head_works_for_current_HEAD(void)
{
	git3_reference *head;

	cl_git_pass(git3_repository_head(&head, fixture.repo));
	cl_git_pass(git3_repository_set_head(fixture.repo, git3_reference_name(head)));

	git3_reference_free(head);
}

void test_worktree_refs__set_head_fails_when_already_checked_out(void)
{
	cl_git_fail(git3_repository_set_head(fixture.repo, "refs/heads/testrepo-worktree"));
}

void test_worktree_refs__delete_fails_for_checked_out_branch(void)
{
	git3_reference *branch;

	cl_git_pass(git3_branch_lookup(&branch, fixture.repo,
		    "testrepo-worktree", GIT3_BRANCH_LOCAL));
	cl_git_fail(git3_branch_delete(branch));

	git3_reference_free(branch);
}

void test_worktree_refs__delete_succeeds_after_pruning_worktree(void)
{
	git3_worktree_prune_options opts = GIT3_WORKTREE_PRUNE_OPTIONS_INIT;
	git3_reference *branch;
	git3_worktree *worktree;

	opts.flags = GIT3_WORKTREE_PRUNE_VALID;

	cl_git_pass(git3_worktree_lookup(&worktree, fixture.repo, fixture.worktreename));
	cl_git_pass(git3_worktree_prune(worktree, &opts));
	git3_worktree_free(worktree);

	cl_git_pass(git3_branch_lookup(&branch, fixture.repo,
		    "testrepo-worktree", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));
	git3_reference_free(branch);
}

void test_worktree_refs__delete_unrelated_branch_on_worktree(void)
{
	git3_reference *branch;

	cl_git_pass(git3_branch_lookup(&branch, fixture.worktree,
		    "merge-conflict", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));

	git3_reference_free(branch);
}

void test_worktree_refs__delete_unrelated_branch_on_parent(void)
{
	git3_reference *branch;

	cl_git_pass(git3_branch_lookup(&branch, fixture.repo,
		    "merge-conflict", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_branch_delete(branch));

	git3_reference_free(branch);
}

void test_worktree_refs__renaming_reference_updates_worktree_heads(void)
{
	git3_reference *head, *branch, *renamed;

	cl_git_pass(git3_branch_lookup(&branch, fixture.repo,
		    "testrepo-worktree", GIT3_BRANCH_LOCAL));
	cl_git_pass(git3_reference_rename(&renamed, branch, "refs/heads/renamed", 0, NULL));

	cl_git_pass(git3_reference_lookup(&head, fixture.worktree, GIT3_HEAD_FILE));
	cl_assert_equal_i(git3_reference_type(head), GIT3_REFERENCE_SYMBOLIC);
	cl_assert_equal_s(git3_reference_symbolic_target(head), "refs/heads/renamed");

	git3_reference_free(head);
	git3_reference_free(branch);
	git3_reference_free(renamed);
}

void test_worktree_refs__creating_refs_uses_commondir(void)
{
	   git3_reference *head, *branch, *lookup;
	   git3_commit *commit;
	   git3_str refpath = GIT3_STR_INIT;

	   cl_git_pass(git3_str_joinpath(&refpath,
		       git3_repository_commondir(fixture.worktree), "refs/heads/testbranch"));
	   cl_assert(!git3_fs_path_exists(refpath.ptr));

	   cl_git_pass(git3_repository_head(&head, fixture.worktree));
	   cl_git_pass(git3_commit_lookup(&commit, fixture.worktree, git3_reference_target(head)));
	   cl_git_pass(git3_branch_create(&branch, fixture.worktree, "testbranch", commit, 0));
	   cl_git_pass(git3_branch_lookup(&lookup, fixture.worktree, "testbranch", GIT3_BRANCH_LOCAL));
	   cl_assert(git3_reference_cmp(branch, lookup) == 0);
	   cl_assert(git3_fs_path_exists(refpath.ptr));

	   git3_reference_free(lookup);
	   git3_reference_free(branch);
	   git3_reference_free(head);
	   git3_commit_free(commit);
	   git3_str_dispose(&refpath);
}
