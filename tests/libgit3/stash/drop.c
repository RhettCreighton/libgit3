#include "clar_libgit3.h"
#include "futils.h"
#include "stash_helpers.h"
#include "refs.h"

static git3_repository *repo;
static git3_signature *signature;

void test_stash_drop__initialize(void)
{
	cl_git_pass(git3_repository_init(&repo, "stash", 0));
	cl_git_pass(git3_signature_new(&signature, "nulltoken", "emeric.fermas@gmail.com", 1323847743, 60)); /* Wed Dec 14 08:29:03 2011 +0100 */
}

void test_stash_drop__cleanup(void)
{
	git3_signature_free(signature);
	signature = NULL;

	git3_repository_free(repo);
	repo = NULL;

	cl_git_pass(git3_futils_rmdir_r("stash", NULL, GIT3_RMDIR_REMOVE_FILES));
}

void test_stash_drop__cannot_drop_from_an_empty_stash(void)
{
	cl_git_fail_with(git3_stash_drop(repo, 0), GIT3_ENOTFOUND);
}

static void push_three_states(void)
{
	git3_oid oid;
	git3_index *index;

	cl_git_mkfile("stash/zero.txt", "content\n");
	cl_git_pass(git3_repository_index(&index, repo));
	cl_git_pass(git3_index_add_bypath(index, "zero.txt"));
	cl_repo_commit_from_index(NULL, repo, signature, 0, "Initial commit");
	cl_assert(git3_fs_path_exists("stash/zero.txt"));
	git3_index_free(index);

	cl_git_mkfile("stash/one.txt", "content\n");
	cl_git_pass(git3_stash_save(
		&oid, repo, signature, "First", GIT3_STASH_INCLUDE_UNTRACKED));
	cl_assert(!git3_fs_path_exists("stash/one.txt"));
	cl_assert(git3_fs_path_exists("stash/zero.txt"));

	cl_git_mkfile("stash/two.txt", "content\n");
	cl_git_pass(git3_stash_save(
		&oid, repo, signature, "Second", GIT3_STASH_INCLUDE_UNTRACKED));
	cl_assert(!git3_fs_path_exists("stash/two.txt"));
	cl_assert(git3_fs_path_exists("stash/zero.txt"));

	cl_git_mkfile("stash/three.txt", "content\n");
	cl_git_pass(git3_stash_save(
		&oid, repo, signature, "Third", GIT3_STASH_INCLUDE_UNTRACKED));
	cl_assert(!git3_fs_path_exists("stash/three.txt"));
	cl_assert(git3_fs_path_exists("stash/zero.txt"));
}

void test_stash_drop__cannot_drop_a_non_existing_stashed_state(void)
{
	push_three_states();

	cl_git_fail_with(git3_stash_drop(repo, 666), GIT3_ENOTFOUND);
	cl_git_fail_with(git3_stash_drop(repo, 42), GIT3_ENOTFOUND);
	cl_git_fail_with(git3_stash_drop(repo, 3), GIT3_ENOTFOUND);
}

void test_stash_drop__can_purge_the_stash_from_the_top(void)
{
	push_three_states();

	cl_git_pass(git3_stash_drop(repo, 0));
	cl_git_pass(git3_stash_drop(repo, 0));
	cl_git_pass(git3_stash_drop(repo, 0));

	cl_git_fail_with(git3_stash_drop(repo, 0), GIT3_ENOTFOUND);
}

void test_stash_drop__can_purge_the_stash_from_the_bottom(void)
{
	push_three_states();

	cl_git_pass(git3_stash_drop(repo, 2));
	cl_git_pass(git3_stash_drop(repo, 1));
	cl_git_pass(git3_stash_drop(repo, 0));

	cl_git_fail_with(git3_stash_drop(repo, 0), GIT3_ENOTFOUND);
}

void test_stash_drop__dropping_an_entry_rewrites_reflog_history(void)
{
	git3_reference *stash;
	git3_reflog *reflog;
	const git3_reflog_entry *entry;
	git3_oid oid;
	size_t count;

	push_three_states();

	cl_git_pass(git3_reference_lookup(&stash, repo, GIT3_REFS_STASH_FILE));

	cl_git_pass(git3_reflog_read(&reflog, repo, GIT3_REFS_STASH_FILE));
	entry = git3_reflog_entry_byindex(reflog, 1);

	git3_oid_cpy(&oid, git3_reflog_entry_id_old(entry));
	count = git3_reflog_entrycount(reflog);

	git3_reflog_free(reflog);

	cl_git_pass(git3_stash_drop(repo, 1));

	cl_git_pass(git3_reflog_read(&reflog, repo, GIT3_REFS_STASH_FILE));
	entry = git3_reflog_entry_byindex(reflog, 0);

	cl_assert_equal_oid(&oid, git3_reflog_entry_id_old(entry));
	cl_assert_equal_sz(count - 1, git3_reflog_entrycount(reflog));

	git3_reflog_free(reflog);

	git3_reference_free(stash);
}

void test_stash_drop__dropping_the_last_entry_removes_the_stash(void)
{
	git3_reference *stash;

	push_three_states();

	cl_git_pass(git3_reference_lookup(&stash, repo, GIT3_REFS_STASH_FILE));
	git3_reference_free(stash);

	cl_git_pass(git3_stash_drop(repo, 0));
	cl_git_pass(git3_stash_drop(repo, 0));
	cl_git_pass(git3_stash_drop(repo, 0));

	cl_git_fail_with(
		git3_reference_lookup(&stash, repo, GIT3_REFS_STASH_FILE), GIT3_ENOTFOUND);
}

static void retrieve_top_stash_id(git3_oid *out)
{
	git3_object *top_stash;

	cl_git_pass(git3_revparse_single(&top_stash, repo, "stash@{0}"));
	cl_git_pass(git3_reference_name_to_id(out, repo, GIT3_REFS_STASH_FILE));

	cl_assert_equal_oid(out, git3_object_id(top_stash));

	git3_object_free(top_stash);
}

void test_stash_drop__dropping_the_top_stash_updates_the_stash_reference(void)
{
	git3_object *next_top_stash;
	git3_oid oid;

	push_three_states();

	retrieve_top_stash_id(&oid);

	cl_git_pass(git3_revparse_single(&next_top_stash, repo, "stash@{1}"));
	cl_assert(git3_oid_cmp(&oid, git3_object_id(next_top_stash)));

	cl_git_pass(git3_stash_drop(repo, 0));

	retrieve_top_stash_id(&oid);

	cl_assert_equal_oid(&oid, git3_object_id(next_top_stash));

	git3_object_free(next_top_stash);
}
