#include "clar_libgit3.h"
#include "refs.h"
#include "repo_helpers.h"
#include "posix.h"
#include "git3/annotated_commit.h"

static const char *g_email = "foo@example.com";
static git3_repository *repo;

void test_repo_head__initialize(void)
{
	repo = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(git3_repository_set_ident(repo, "Foo Bar", g_email));
}

void test_repo_head__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

void test_repo_head__unborn_head(void)
{
	git3_reference *ref;

	cl_git_pass(git3_repository_head_detached(repo));

	make_head_unborn(repo, NON_EXISTING_HEAD);

	cl_assert(git3_repository_head_unborn(repo) == 1);


	/* take the repo back to it's original state */
	cl_git_pass(git3_reference_symbolic_create(&ref, repo, "HEAD", "refs/heads/master", 1, NULL));
	cl_assert(git3_repository_head_unborn(repo) == 0);

	git3_reference_free(ref);
}

void test_repo_head__set_head_Attaches_HEAD_to_un_unborn_branch_when_the_branch_doesnt_exist(void)
{
	git3_reference *head;

	cl_git_pass(git3_repository_set_head(repo, "refs/heads/doesnt/exist/yet"));

	cl_assert_equal_i(false, git3_repository_head_detached(repo));

	cl_assert_equal_i(GIT3_EUNBORNBRANCH, git3_repository_head(&head, repo));
}

void test_repo_head__set_head_Returns_ENOTFOUND_when_the_reference_doesnt_exist(void)
{
	cl_assert_equal_i(GIT3_ENOTFOUND, git3_repository_set_head(repo, "refs/tags/doesnt/exist/yet"));
}

void test_repo_head__set_head_Fails_when_the_reference_points_to_a_non_commitish(void)
{
	cl_git_fail(git3_repository_set_head(repo, "refs/tags/point_to_blob"));
}

void test_repo_head__set_head_Attaches_HEAD_when_the_reference_points_to_a_branch(void)
{
	git3_reference *head;

	cl_git_pass(git3_repository_set_head(repo, "refs/heads/br2"));

	cl_assert_equal_i(false, git3_repository_head_detached(repo));

	cl_git_pass(git3_repository_head(&head, repo));
	cl_assert_equal_s("refs/heads/br2", git3_reference_name(head));

	git3_reference_free(head);
}

static void assert_head_is_correctly_detached(void)
{
	git3_reference *head;
	git3_object *commit;

	cl_assert_equal_i(true, git3_repository_head_detached(repo));

	cl_git_pass(git3_repository_head(&head, repo));

	cl_git_pass(git3_object_lookup(&commit, repo, git3_reference_target(head), GIT3_OBJECT_COMMIT));

	git3_object_free(commit);
	git3_reference_free(head);
}

void test_repo_head__set_head_Detaches_HEAD_when_the_reference_doesnt_point_to_a_branch(void)
{
	cl_git_pass(git3_repository_set_head(repo, "refs/tags/test"));

	cl_assert_equal_i(true, git3_repository_head_detached(repo));

	assert_head_is_correctly_detached();
}

void test_repo_head__set_head_detached_Return_ENOTFOUND_when_the_object_doesnt_exist(void)
{
	git3_oid oid;

	cl_git_pass(git3_oid_from_string(&oid, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", GIT3_OID_SHA1));

	cl_assert_equal_i(GIT3_ENOTFOUND, git3_repository_set_head_detached(repo, &oid));
}

void test_repo_head__set_head_detached_Fails_when_the_object_isnt_a_commitish(void)
{
	git3_object *blob;

	cl_git_pass(git3_revparse_single(&blob, repo, "point_to_blob"));

	cl_git_fail(git3_repository_set_head_detached(repo, git3_object_id(blob)));

	git3_object_free(blob);
}

void test_repo_head__set_head_detached_Detaches_HEAD_and_make_it_point_to_the_peeled_commit(void)
{
	git3_object *tag;

	cl_git_pass(git3_revparse_single(&tag, repo, "tags/test"));
	cl_assert_equal_i(GIT3_OBJECT_TAG, git3_object_type(tag));

	cl_git_pass(git3_repository_set_head_detached(repo, git3_object_id(tag)));

	assert_head_is_correctly_detached();

	git3_object_free(tag);
}

void test_repo_head__detach_head_Detaches_HEAD_and_make_it_point_to_the_peeled_commit(void)
{
	cl_assert_equal_i(false, git3_repository_head_detached(repo));

	cl_git_pass(git3_repository_detach_head(repo));

	assert_head_is_correctly_detached();
}

void test_repo_head__detach_head_Fails_if_HEAD_and_point_to_a_non_commitish(void)
{
	git3_reference *head;

	cl_git_pass(git3_reference_symbolic_create(&head, repo, GIT3_HEAD_FILE, "refs/tags/point_to_blob", 1, NULL));

	cl_git_fail(git3_repository_detach_head(repo));

	git3_reference_free(head);
}

void test_repo_head__detaching_an_unborn_branch_returns_GIT3_EUNBORNBRANCH(void)
{
	make_head_unborn(repo, NON_EXISTING_HEAD);

	cl_assert_equal_i(GIT3_EUNBORNBRANCH, git3_repository_detach_head(repo));
}

void test_repo_head__retrieving_an_unborn_branch_returns_GIT3_EUNBORNBRANCH(void)
{
	git3_reference *head;

	make_head_unborn(repo, NON_EXISTING_HEAD);

	cl_assert_equal_i(GIT3_EUNBORNBRANCH, git3_repository_head(&head, repo));
}

void test_repo_head__retrieving_a_missing_head_returns_GIT3_ENOTFOUND(void)
{
	git3_reference *head;

	delete_head(repo);

	cl_assert_equal_i(GIT3_ENOTFOUND, git3_repository_head(&head, repo));
}

void test_repo_head__can_tell_if_an_unborn_head_is_detached(void)
{
	make_head_unborn(repo, NON_EXISTING_HEAD);

	cl_assert_equal_i(false, git3_repository_head_detached(repo));
}
