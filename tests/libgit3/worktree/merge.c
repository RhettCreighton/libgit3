#include "clar_libgit3.h"

#include "worktree_helpers.h"
#include "merge/merge_helpers.h"

#define COMMON_REPO "testrepo"
#define WORKTREE_REPO "testrepo-worktree"

#define MASTER_BRANCH "refs/heads/master"
#define CONFLICT_BRANCH "refs/heads/merge-conflict"

#define CONFLICT_BRANCH_FILE_TXT \
	"<<<<<<< HEAD\n" \
	"hi\n" \
	"bye!\n" \
	"=======\n" \
	"conflict\n" \
	">>>>>>> merge-conflict\n" \

static worktree_fixture fixture =
	WORKTREE_FIXTURE_INIT(COMMON_REPO, WORKTREE_REPO);

static const char *merge_files[] = {
	GIT3_MERGE_HEAD_FILE,
	GIT3_ORIG_HEAD_FILE,
	GIT3_MERGE_MODE_FILE,
	GIT3_MERGE_MSG_FILE,
};

void test_worktree_merge__initialize(void)
{
	setup_fixture_worktree(&fixture);
}

void test_worktree_merge__cleanup(void)
{
	cleanup_fixture_worktree(&fixture);
}

void test_worktree_merge__merge_head(void)
{
	git3_reference *theirs_ref, *ref;
	git3_annotated_commit *theirs;

	cl_git_pass(git3_reference_lookup(&theirs_ref, fixture.worktree, CONFLICT_BRANCH));
	cl_git_pass(git3_annotated_commit_from_ref(&theirs, fixture.worktree, theirs_ref));
	cl_git_pass(git3_merge(fixture.worktree, (const git3_annotated_commit **)&theirs, 1, NULL, NULL));

	cl_git_pass(git3_reference_lookup(&ref, fixture.worktree, GIT3_MERGE_HEAD_FILE));

	git3_reference_free(ref);
	git3_reference_free(theirs_ref);
	git3_annotated_commit_free(theirs);
}

void test_worktree_merge__merge_setup(void)
{
	git3_reference *ours_ref, *theirs_ref;
	git3_annotated_commit *ours, *theirs;
	git3_str path = GIT3_STR_INIT;
	unsigned i;

	cl_git_pass(git3_reference_lookup(&ours_ref, fixture.worktree, MASTER_BRANCH));
	cl_git_pass(git3_annotated_commit_from_ref(&ours, fixture.worktree, ours_ref));

	cl_git_pass(git3_reference_lookup(&theirs_ref, fixture.worktree, CONFLICT_BRANCH));
	cl_git_pass(git3_annotated_commit_from_ref(&theirs, fixture.worktree, theirs_ref));

	cl_git_pass(git3_merge__setup(fixture.worktree,
		    ours, (const git3_annotated_commit **)&theirs, 1));

	for (i = 0; i < ARRAY_SIZE(merge_files); i++) {
		cl_git_pass(git3_str_joinpath(&path,
		            fixture.worktree->gitdir,
		            merge_files[i]));
		cl_assert(git3_fs_path_exists(path.ptr));
	}

	git3_str_dispose(&path);
	git3_reference_free(ours_ref);
	git3_reference_free(theirs_ref);
	git3_annotated_commit_free(ours);
	git3_annotated_commit_free(theirs);
}

void test_worktree_merge__merge_conflict(void)
{
	git3_str path = GIT3_STR_INIT, buf = GIT3_STR_INIT;
	git3_reference *theirs_ref;
	git3_annotated_commit *theirs;
	git3_index *index;
	const git3_index_entry *entry;
	size_t i, conflicts = 0;

	cl_git_pass(git3_reference_lookup(&theirs_ref, fixture.worktree, CONFLICT_BRANCH));
	cl_git_pass(git3_annotated_commit_from_ref(&theirs, fixture.worktree, theirs_ref));

	cl_git_pass(git3_merge(fixture.worktree,
		    (const git3_annotated_commit **)&theirs, 1, NULL, NULL));

	cl_git_pass(git3_repository_index(&index, fixture.worktree));
	for (i = 0; i < git3_index_entrycount(index); i++) {
		cl_assert(entry = git3_index_get_byindex(index, i));

		if (git3_index_entry_is_conflict(entry))
			conflicts++;
	}
	cl_assert_equal_sz(conflicts, 3);

	git3_reference_free(theirs_ref);
	git3_annotated_commit_free(theirs);
	git3_index_free(index);

	cl_git_pass(git3_str_joinpath(&path, fixture.worktree->workdir, "branch_file.txt"));
	cl_git_pass(git3_futils_readbuffer(&buf, path.ptr));
	cl_assert_equal_s(buf.ptr, CONFLICT_BRANCH_FILE_TXT);

	git3_str_dispose(&path);
	git3_str_dispose(&buf);
}

