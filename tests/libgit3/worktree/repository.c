#include "clar_libgit3.h"
#include "worktree_helpers.h"
#include "submodule/submodule_helpers.h"

#include "repository.h"

#define COMMON_REPO "testrepo"
#define WORKTREE_REPO "testrepo-worktree"

static worktree_fixture fixture =
	WORKTREE_FIXTURE_INIT(COMMON_REPO, WORKTREE_REPO);

void test_worktree_repository__initialize(void)
{
	setup_fixture_worktree(&fixture);
}

void test_worktree_repository__cleanup(void)
{
	cleanup_fixture_worktree(&fixture);
}

void test_worktree_repository__head(void)
{
	git3_reference *ref, *head;

	cl_git_pass(git3_reference_lookup(&ref, fixture.repo, "refs/heads/testrepo-worktree"));
	cl_git_pass(git3_repository_head_for_worktree(&head, fixture.repo, "testrepo-worktree"));
	cl_assert(git3_reference_cmp(ref, head) == 0);
	cl_assert(git3_reference_owner(ref) == fixture.repo);

	git3_reference_free(ref);
	git3_reference_free(head);
}

void test_worktree_repository__head_fails_for_invalid_worktree(void)
{
	git3_reference *head = NULL;

	cl_git_fail(git3_repository_head_for_worktree(&head, fixture.repo, "invalid"));
	cl_assert(head == NULL);
}

void test_worktree_repository__head_detached(void)
{
	git3_reference *ref, *head;

	cl_git_pass(git3_reference_lookup(&ref, fixture.repo, "refs/heads/testrepo-worktree"));
	cl_git_pass(git3_repository_set_head_detached(fixture.worktree, &ref->target.oid));

	cl_assert(git3_repository_head_detached(fixture.worktree));
	cl_assert(git3_repository_head_detached_for_worktree(fixture.repo, "testrepo-worktree"));
	cl_git_pass(git3_repository_head_for_worktree(&head, fixture.repo, "testrepo-worktree"));

	cl_assert_equal_oid(&ref->target.oid, &head->target.oid);

	git3_reference_free(ref);
	git3_reference_free(head);
}

void test_worktree_repository__head_detached_fails_for_invalid_worktree(void)
{
	git3_reference *head = NULL;

	cl_git_fail(git3_repository_head_detached_for_worktree(fixture.repo, "invalid"));
	cl_assert(head == NULL);
}
