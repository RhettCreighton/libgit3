#include "clar_libgit3.h"
#include "git3/repository.h"
#include "git3/merge.h"
#include "merge.h"
#include "../merge_helpers.h"
#include "refs.h"
#include "futils.h"
#include "git3/sys/index.h"

static git3_repository *repo;

#define TEST_REPO_PATH "merge-resolve"
#define TEST_INDEX_PATH TEST_REPO_PATH "/.git/index"


/* Fixture setup and teardown */
void test_merge_trees_trivial__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
}

void test_merge_trees_trivial__cleanup(void)
{
	cl_git_sandbox_cleanup();
}


static int merge_trivial(git3_index **index, const char *ours, const char *theirs)
{
	git3_commit *our_commit, *their_commit, *ancestor_commit;
	git3_tree *our_tree, *their_tree, *ancestor_tree;
	git3_oid our_oid, their_oid, ancestor_oid;
	git3_str branch_buf = GIT3_STR_INIT;
	git3_merge_options opts = GIT3_MERGE_OPTIONS_INIT;

	git3_str_printf(&branch_buf, "%s%s", GIT3_REFS_HEADS_DIR, ours);
	cl_git_pass(git3_reference_name_to_id(&our_oid, repo, branch_buf.ptr));
	cl_git_pass(git3_commit_lookup(&our_commit, repo, &our_oid));

	git3_str_clear(&branch_buf);
	git3_str_printf(&branch_buf, "%s%s", GIT3_REFS_HEADS_DIR, theirs);
	cl_git_pass(git3_reference_name_to_id(&their_oid, repo, branch_buf.ptr));
	cl_git_pass(git3_commit_lookup(&their_commit, repo, &their_oid));

	cl_git_pass(git3_merge_base(&ancestor_oid, repo, git3_commit_id(our_commit), git3_commit_id(their_commit)));
	cl_git_pass(git3_commit_lookup(&ancestor_commit, repo, &ancestor_oid));

	cl_git_pass(git3_commit_tree(&ancestor_tree, ancestor_commit));
	cl_git_pass(git3_commit_tree(&our_tree, our_commit));
	cl_git_pass(git3_commit_tree(&their_tree, their_commit));

	cl_git_pass(git3_merge_trees(index, repo, ancestor_tree, our_tree, their_tree, &opts));

	git3_str_dispose(&branch_buf);
	git3_tree_free(our_tree);
	git3_tree_free(their_tree);
	git3_tree_free(ancestor_tree);
	git3_commit_free(our_commit);
	git3_commit_free(their_commit);
	git3_commit_free(ancestor_commit);

	return 0;
}

static int merge_trivial_conflict_entrycount(git3_index *index)
{
	const git3_index_entry *entry;
	int count = 0;
	size_t i;

	for (i = 0; i < git3_index_entrycount(index); i++) {
		cl_assert(entry = git3_index_get_byindex(index, i));

		if (git3_index_entry_is_conflict(entry))
			count++;
	}

	return count;
}

/* 2ALT: ancest:(empty)+, head:*empty*, remote:remote = result:remote */
void test_merge_trees_trivial__2alt(void)
{
	git3_index *result;
	const git3_index_entry *entry;

	cl_git_pass(merge_trivial(&result, "trivial-2alt", "trivial-2alt-branch"));

	cl_assert(entry = git3_index_get_bypath(result, "new-in-branch.txt", 0));
	cl_assert(git3_index_reuc_entrycount(result) == 0);
	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 3ALT: ancest:(empty)+, head:head, remote:*empty* = result:head */
void test_merge_trees_trivial__3alt(void)
{
	git3_index *result;
	const git3_index_entry *entry;

	cl_git_pass(merge_trivial(&result, "trivial-3alt", "trivial-3alt-branch"));

	cl_assert(entry = git3_index_get_bypath(result, "new-in-3alt.txt", 0));
	cl_assert(git3_index_reuc_entrycount(result) == 0);
	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 4: ancest:(empty)^, head:head, remote:remote = result:no merge */
void test_merge_trees_trivial__4(void)
{
	git3_index *result;
	const git3_index_entry *entry;

	cl_git_pass(merge_trivial(&result, "trivial-4", "trivial-4-branch"));

	cl_assert((entry = git3_index_get_bypath(result, "new-and-different.txt", 0)) == NULL);
	cl_assert(git3_index_reuc_entrycount(result) == 0);

	cl_assert(merge_trivial_conflict_entrycount(result) == 2);
	cl_assert(entry = git3_index_get_bypath(result, "new-and-different.txt", 2));
	cl_assert(entry = git3_index_get_bypath(result, "new-and-different.txt", 3));

	git3_index_free(result);
}

/* 5ALT: ancest:*, head:head, remote:head = result:head */
void test_merge_trees_trivial__5alt_1(void)
{
	git3_index *result;
	const git3_index_entry *entry;

	cl_git_pass(merge_trivial(&result, "trivial-5alt-1", "trivial-5alt-1-branch"));

	cl_assert(entry = git3_index_get_bypath(result, "new-and-same.txt", 0));
	cl_assert(git3_index_reuc_entrycount(result) == 0);
	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 5ALT: ancest:*, head:head, remote:head = result:head */
void test_merge_trees_trivial__5alt_2(void)
{
	git3_index *result;
	const git3_index_entry *entry;

	cl_git_pass(merge_trivial(&result, "trivial-5alt-2", "trivial-5alt-2-branch"));

	cl_assert(entry = git3_index_get_bypath(result, "modified-to-same.txt", 0));
	cl_assert(git3_index_reuc_entrycount(result) == 0);
	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 6: ancest:ancest+, head:(empty), remote:(empty) = result:no merge */
void test_merge_trees_trivial__6(void)
{
	git3_index *result;
	const git3_index_entry *entry;
	const git3_index_reuc_entry *reuc;

	cl_git_pass(merge_trivial(&result, "trivial-6", "trivial-6-branch"));

	cl_assert((entry = git3_index_get_bypath(result, "removed-in-both.txt", 0)) == NULL);
	cl_assert(git3_index_reuc_entrycount(result) == 1);
	cl_assert(reuc = git3_index_reuc_get_bypath(result, "removed-in-both.txt"));

	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 8: ancest:ancest^, head:(empty), remote:ancest = result:no merge */
void test_merge_trees_trivial__8(void)
{
	git3_index *result;
	const git3_index_entry *entry;
	const git3_index_reuc_entry *reuc;

	cl_git_pass(merge_trivial(&result, "trivial-8", "trivial-8-branch"));

	cl_assert((entry = git3_index_get_bypath(result, "removed-in-8.txt", 0)) == NULL);

	cl_assert(git3_index_reuc_entrycount(result) == 1);
	cl_assert(reuc = git3_index_reuc_get_bypath(result, "removed-in-8.txt"));

	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 7: ancest:ancest+, head:(empty), remote:remote = result:no merge */
void test_merge_trees_trivial__7(void)
{
	git3_index *result;
	const git3_index_entry *entry;

	cl_git_pass(merge_trivial(&result, "trivial-7", "trivial-7-branch"));

	cl_assert((entry = git3_index_get_bypath(result, "removed-in-7.txt", 0)) == NULL);
	cl_assert(git3_index_reuc_entrycount(result) == 0);

	cl_assert(merge_trivial_conflict_entrycount(result) == 2);
	cl_assert(entry = git3_index_get_bypath(result, "removed-in-7.txt", 1));
	cl_assert(entry = git3_index_get_bypath(result, "removed-in-7.txt", 3));

	git3_index_free(result);
}

/* 10: ancest:ancest^, head:ancest, remote:(empty) = result:no merge */
void test_merge_trees_trivial__10(void)
{
	git3_index *result;
	const git3_index_entry *entry;
	const git3_index_reuc_entry *reuc;

	cl_git_pass(merge_trivial(&result, "trivial-10", "trivial-10-branch"));

	cl_assert((entry = git3_index_get_bypath(result, "removed-in-10-branch.txt", 0)) == NULL);

	cl_assert(git3_index_reuc_entrycount(result) == 1);
	cl_assert(reuc = git3_index_reuc_get_bypath(result, "removed-in-10-branch.txt"));

	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 9: ancest:ancest+, head:head, remote:(empty) = result:no merge */
void test_merge_trees_trivial__9(void)
{
	git3_index *result;
	const git3_index_entry *entry;

	cl_git_pass(merge_trivial(&result, "trivial-9", "trivial-9-branch"));

	cl_assert((entry = git3_index_get_bypath(result, "removed-in-9-branch.txt", 0)) == NULL);
	cl_assert(git3_index_reuc_entrycount(result) == 0);

	cl_assert(merge_trivial_conflict_entrycount(result) == 2);
	cl_assert(entry = git3_index_get_bypath(result, "removed-in-9-branch.txt", 1));
	cl_assert(entry = git3_index_get_bypath(result, "removed-in-9-branch.txt", 2));

	git3_index_free(result);
}

/* 13: ancest:ancest+, head:head, remote:ancest = result:head */
void test_merge_trees_trivial__13(void)
{
	git3_index *result;
	const git3_index_entry *entry;
	git3_oid expected_oid;

	cl_git_pass(merge_trivial(&result, "trivial-13", "trivial-13-branch"));

	cl_assert(entry = git3_index_get_bypath(result, "modified-in-13.txt", 0));
	cl_git_pass(git3_oid_from_string(&expected_oid, "1cff9ec6a47a537380dedfdd17c9e76d74259a2b", GIT3_OID_SHA1));
	cl_assert_equal_oid(&expected_oid, &entry->id);

	cl_assert(git3_index_reuc_entrycount(result) == 0);
	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 14: ancest:ancest+, head:ancest, remote:remote = result:remote */
void test_merge_trees_trivial__14(void)
{
	git3_index *result;
	const git3_index_entry *entry;
	git3_oid expected_oid;

	cl_git_pass(merge_trivial(&result, "trivial-14", "trivial-14-branch"));

	cl_assert(entry = git3_index_get_bypath(result, "modified-in-14-branch.txt", 0));
	cl_git_pass(git3_oid_from_string(&expected_oid, "26153a3ff3649b6c2bb652d3f06878c6e0a172f9", GIT3_OID_SHA1));
	cl_assert(git3_oid_cmp(&entry->id, &expected_oid) == 0);

	cl_assert(git3_index_reuc_entrycount(result) == 0);
	cl_assert(merge_trivial_conflict_entrycount(result) == 0);

	git3_index_free(result);
}

/* 11: ancest:ancest+, head:head, remote:remote = result:no merge */
void test_merge_trees_trivial__11(void)
{
	git3_index *result;
	const git3_index_entry *entry;

	cl_git_pass(merge_trivial(&result, "trivial-11", "trivial-11-branch"));

	cl_assert((entry = git3_index_get_bypath(result, "modified-in-both.txt", 0)) == NULL);
	cl_assert(git3_index_reuc_entrycount(result) == 0);

	cl_assert(merge_trivial_conflict_entrycount(result) == 3);
	cl_assert(entry = git3_index_get_bypath(result, "modified-in-both.txt", 1));
	cl_assert(entry = git3_index_get_bypath(result, "modified-in-both.txt", 2));
	cl_assert(entry = git3_index_get_bypath(result, "modified-in-both.txt", 3));

	git3_index_free(result);
}
