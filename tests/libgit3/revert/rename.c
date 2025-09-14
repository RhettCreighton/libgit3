#include "clar.h"
#include "clar_libgit3.h"

#include "git3/revert.h"
#include "../merge/merge_helpers.h"

#define TEST_REPO_PATH "revert-rename.git"

static git3_repository *repo;

/* Fixture setup and teardown */
void test_revert_rename__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
}

void test_revert_rename__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

/* Attempt a revert when there is a file rename AND change of file mode,
 * but the file contents remain the same. Check that the file mode doesn't
 * change following the revert.
 */
void test_revert_rename__automerge(void)
{
  git3_commit *head_commit, *revert_commit;
  git3_oid revert_oid;
  git3_index *index;
  git3_reference *head_ref;

  struct merge_index_entry merge_index_entries[] = {
    { 0100644, "f0f64c618e1646d2948a456ed7c4bcfad5536d68", 0, "goodmode" }};

  cl_git_pass(git3_repository_head(&head_ref, repo));
  cl_git_pass(git3_reference_peel((git3_object **)&head_commit, head_ref, GIT3_OBJECT_COMMIT));

  cl_git_pass(git3_oid_from_string(&revert_oid, "7b4d7c3789b3581973c04087cb774c3c3576de2f", GIT3_OID_SHA1));
  cl_git_pass(git3_commit_lookup(&revert_commit, repo, &revert_oid));

  cl_git_pass(git3_revert_commit(&index, repo, revert_commit, head_commit, 0, NULL));
  cl_assert(merge_test_index(index, merge_index_entries, 1));

  git3_commit_free(revert_commit);
  git3_commit_free(head_commit);
  git3_index_free(index);
  git3_reference_free(head_ref);
}
