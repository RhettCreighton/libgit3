#include "clar_libgit3.h"
#include "diff_generate.h"
#include "git3/checkout.h"
#include "path.h"
#include "posix.h"
#include "futils.h"

static git3_repository *g_repo = NULL;

/*
From the test repo used for this test:
--------------------------------------

This is a test repo for libgit3 where tree entries have type changes

The key types that could be found in tree entries are:

1 - GIT3_FILEMODE_NEW             = 0000000
2 - GIT3_FILEMODE_TREE            = 0040000
3 - GIT3_FILEMODE_BLOB            = 0100644
4 - GIT3_FILEMODE_BLOB_EXECUTABLE = 0100755
5 - GIT3_FILEMODE_LINK            = 0120000
6 - GIT3_FILEMODE_COMMIT          = 0160000

I will try to have every type of transition somewhere in the history
of this repo.

Commits
-------
Initial commit - a(1)    b(1)    c(1)    d(1)    e(1)
Create content - a(1->2) b(1->3) c(1->4) d(1->5) e(1->6)
Changes #1     - a(2->3) b(3->4) c(4->5) d(5->6) e(6->2)
Changes #2     - a(3->5) b(4->6) c(5->2) d(6->3) e(2->4)
Changes #3     - a(5->3) b(6->4) c(2->5) d(3->6) e(4->2)
Changes #4     - a(3->2) b(4->3) c(5->4) d(6->5) e(2->6)
Changes #5     - a(2->1) b(3->1) c(4->1) d(5->1) e(6->1)

*/

static const char *g_typechange_oids[] = {
	"79b9f23e85f55ea36a472a902e875bc1121a94cb",
	"9bdb75b73836a99e3dbeea640a81de81031fdc29",
	"0e7ed140b514b8cae23254cb8656fe1674403aff",
	"9d0235c7a7edc0889a18f97a42ee6db9fe688447",
	"9b19edf33a03a0c59cdfc113bfa5c06179bf9b1a",
	"1b63caae4a5ca96f78e8dfefc376c6a39a142475",
	"6eae26c90e8ccc4d16208972119c40635489c6f0",
	NULL
};

static bool g_typechange_empty[] = {
	true, false, false, false, false, false, true, true
};

static const int g_typechange_expected_conflicts[] = {
	1, 2, 3, 3, 2, 3, 2
};

static const int g_typechange_expected_untracked[] = {
	6, 4, 3, 2, 3, 2, 5
};

void test_checkout_typechange__initialize(void)
{
	g_repo = cl_git_sandbox_init("typechanges");

	cl_fixture_sandbox("submod2_target");
	p_rename("submod2_target/.gitted", "submod2_target/.git");
}

void test_checkout_typechange__cleanup(void)
{
	cl_git_sandbox_cleanup();
	cl_fixture_cleanup("submod2_target");
}

static void assert_file_exists(const char *path)
{
	cl_assert_(git3_fs_path_isfile(path), path);
}

static void assert_dir_exists(const char *path)
{
	cl_assert_(git3_fs_path_isdir(path), path);
}

static void assert_workdir_matches_tree(
	git3_repository *repo, const git3_oid *id, const char *root, bool recurse)
{
	git3_object *obj;
	git3_tree *tree;
	size_t i, max_i;
	git3_str path = GIT3_STR_INIT;

	if (!root)
		root = git3_repository_workdir(repo);
	cl_assert(root);

	cl_git_pass(git3_object_lookup(&obj, repo, id, GIT3_OBJECT_ANY));
	cl_git_pass(git3_object_peel((git3_object **)&tree, obj, GIT3_OBJECT_TREE));
	git3_object_free(obj);

	max_i = git3_tree_entrycount(tree);

	for (i = 0; i < max_i; ++i) {
		const git3_tree_entry *te = git3_tree_entry_byindex(tree, i);
		cl_assert(te);

		cl_git_pass(git3_str_joinpath(&path, root, git3_tree_entry_name(te)));

		switch (git3_tree_entry_type(te)) {
		case GIT3_OBJECT_COMMIT:
			assert_dir_exists(path.ptr);
			break;
		case GIT3_OBJECT_TREE:
			assert_dir_exists(path.ptr);
			if (recurse)
				assert_workdir_matches_tree(
					repo, git3_tree_entry_id(te), path.ptr, true);
			break;
		case GIT3_OBJECT_BLOB:
			switch (git3_tree_entry_filemode(te)) {
			case GIT3_FILEMODE_BLOB:
			case GIT3_FILEMODE_BLOB_EXECUTABLE:
				assert_file_exists(path.ptr);
				/* because of cross-platform, don't confirm exec bit yet */
				break;
			case GIT3_FILEMODE_LINK:
				cl_assert_(git3_fs_path_exists(path.ptr), path.ptr);
				/* because of cross-platform, don't confirm link yet */
				break;
			default:
				cl_assert(false); /* really?! */
			}
			break;
		default:
			cl_assert(false); /* really?!! */
		}
	}

	git3_tree_free(tree);
	git3_str_dispose(&path);
}

void test_checkout_typechange__checkout_typechanges_safe(void)
{
	int i;
	git3_object *obj;
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;

	for (i = 0; g_typechange_oids[i] != NULL; ++i) {
		cl_git_pass(git3_revparse_single(&obj, g_repo, g_typechange_oids[i]));

		opts.checkout_strategy = !i ? GIT3_CHECKOUT_FORCE : GIT3_CHECKOUT_SAFE;

		cl_git_pass(git3_checkout_tree(g_repo, obj, &opts));

		cl_git_pass(
			git3_repository_set_head_detached(g_repo, git3_object_id(obj)));

		assert_workdir_matches_tree(g_repo, git3_object_id(obj), NULL, true);

		git3_object_free(obj);

		if (!g_typechange_empty[i]) {
			cl_assert(git3_fs_path_isdir("typechanges"));
			cl_assert(git3_fs_path_exists("typechanges/a"));
			cl_assert(git3_fs_path_exists("typechanges/b"));
			cl_assert(git3_fs_path_exists("typechanges/c"));
			cl_assert(git3_fs_path_exists("typechanges/d"));
			cl_assert(git3_fs_path_exists("typechanges/e"));
		} else {
			cl_assert(git3_fs_path_isdir("typechanges"));
			cl_assert(!git3_fs_path_exists("typechanges/a"));
			cl_assert(!git3_fs_path_exists("typechanges/b"));
			cl_assert(!git3_fs_path_exists("typechanges/c"));
			cl_assert(!git3_fs_path_exists("typechanges/d"));
			cl_assert(!git3_fs_path_exists("typechanges/e"));
		}
	}
}

typedef struct {
	int conflicts;
	int dirty;
	int updates;
	int untracked;
	int ignored;
} notify_counts;

static int notify_counter(
	git3_checkout_notify_t why,
	const char *path,
	const git3_diff_file *baseline,
	const git3_diff_file *target,
	const git3_diff_file *workdir,
	void *payload)
{
	notify_counts *cts = payload;

	GIT3_UNUSED(path);
	GIT3_UNUSED(baseline);
	GIT3_UNUSED(target);
	GIT3_UNUSED(workdir);

	switch (why) {
	case GIT3_CHECKOUT_NOTIFY_CONFLICT:  cts->conflicts++; break;
	case GIT3_CHECKOUT_NOTIFY_DIRTY:     cts->dirty++;     break;
	case GIT3_CHECKOUT_NOTIFY_UPDATED:   cts->updates++;   break;
	case GIT3_CHECKOUT_NOTIFY_UNTRACKED: cts->untracked++; break;
	case GIT3_CHECKOUT_NOTIFY_IGNORED:   cts->ignored++;   break;
	default: break;
	}

	return 0;
}

static void force_create_file(const char *file)
{
	int error = git3_futils_rmdir_r(file, NULL,
		GIT3_RMDIR_REMOVE_FILES | GIT3_RMDIR_REMOVE_BLOCKERS);
	cl_assert(!error || error == GIT3_ENOTFOUND);
	cl_git_pass(git3_futils_mkpath2file(file, 0777));
	cl_git_rewritefile(file, "yowza!!");
}

static int make_submodule_dirty(git3_submodule *sm, const char *name, void *payload)
{
	git3_str submodulepath = GIT3_STR_INIT;
	git3_str dirtypath = GIT3_STR_INIT;
	git3_repository *submodule_repo;

	GIT3_UNUSED(name);
	GIT3_UNUSED(payload);

	/* remove submodule directory in preparation for init and repo_init */
	cl_git_pass(git3_str_joinpath(
		&submodulepath,
		git3_repository_workdir(g_repo),
		git3_submodule_path(sm)
	));
	git3_futils_rmdir_r(git3_str_cstr(&submodulepath), NULL, GIT3_RMDIR_REMOVE_FILES);

	/* initialize submodule's repository */
	cl_git_pass(git3_submodule_repo_init(&submodule_repo, sm, 0));

	/* create a file in the submodule workdir to make it dirty */
	cl_git_pass(
		git3_str_joinpath(&dirtypath, git3_repository_workdir(submodule_repo), "dirty"));
	force_create_file(git3_str_cstr(&dirtypath));

	git3_str_dispose(&dirtypath);
	git3_str_dispose(&submodulepath);
	git3_repository_free(submodule_repo);

	return 0;
}

void test_checkout_typechange__checkout_with_conflicts(void)
{
	int i;
	git3_object *obj;
	git3_checkout_options opts = GIT3_CHECKOUT_OPTIONS_INIT;
	notify_counts cts = {0};

	opts.notify_flags =
		GIT3_CHECKOUT_NOTIFY_CONFLICT | GIT3_CHECKOUT_NOTIFY_UNTRACKED;
	opts.notify_cb = notify_counter;
	opts.notify_payload = &cts;

	for (i = 0; g_typechange_oids[i] != NULL; ++i) {
		cl_git_pass(git3_revparse_single(&obj, g_repo, g_typechange_oids[i]));

		force_create_file("typechanges/a/blocker");
		force_create_file("typechanges/b");
		force_create_file("typechanges/c/sub/sub/file");
		git3_futils_rmdir_r("typechanges/d", NULL, GIT3_RMDIR_REMOVE_FILES);
		p_mkdir("typechanges/d", 0777); /* intentionally empty dir */
		force_create_file("typechanges/untracked");
		cl_git_pass(git3_submodule_foreach(g_repo, make_submodule_dirty, NULL));

		opts.checkout_strategy = GIT3_CHECKOUT_SAFE;
		memset(&cts, 0, sizeof(cts));

		cl_git_fail(git3_checkout_tree(g_repo, obj, &opts));
		cl_assert_equal_i(cts.conflicts, g_typechange_expected_conflicts[i]);
		cl_assert_equal_i(cts.untracked, g_typechange_expected_untracked[i]);
		cl_assert_equal_i(cts.dirty, 0);
		cl_assert_equal_i(cts.updates, 0);
		cl_assert_equal_i(cts.ignored, 0);

		opts.checkout_strategy =
			GIT3_CHECKOUT_FORCE | GIT3_CHECKOUT_REMOVE_UNTRACKED;
		memset(&cts, 0, sizeof(cts));

		cl_assert(git3_fs_path_exists("typechanges/untracked"));

		cl_git_pass(git3_checkout_tree(g_repo, obj, &opts));
		cl_assert_equal_i(0, cts.conflicts);

		cl_assert(!git3_fs_path_exists("typechanges/untracked"));

		cl_git_pass(
			git3_repository_set_head_detached(g_repo, git3_object_id(obj)));

		assert_workdir_matches_tree(g_repo, git3_object_id(obj), NULL, true);

		git3_object_free(obj);
	}
}

void test_checkout_typechange__status_char(void)
{
	size_t i;
	git3_oid oid;
	git3_commit *commit;
	git3_diff *diff;
	const git3_diff_delta *delta;
	git3_diff_options diffopts = GIT3_DIFF_OPTIONS_INIT;
	char expected[8] = {'M', 'M', 'R', 'T', 'D', 'R', 'A', 'R'};

	git3_oid_from_string(&oid, "9b19edf33a03a0c59cdfc113bfa5c06179bf9b1a", GIT3_OID_SHA1);
	cl_git_pass(git3_commit_lookup(&commit, g_repo, &oid));
	diffopts.flags |= GIT3_DIFF_INCLUDE_TYPECHANGE;
	cl_git_pass(git3_diff__commit(&diff, g_repo, commit, &diffopts));
	cl_git_pass(git3_diff_find_similar(diff, NULL));

	for (i = 0; i < git3_diff_num_deltas(diff); i++) {
		delta = git3_diff_get_delta(diff, i);
		cl_assert_equal_i(expected[i], git3_diff_status_char(delta->status));
	}

	git3_diff_free(diff);
	git3_commit_free(commit);
}
