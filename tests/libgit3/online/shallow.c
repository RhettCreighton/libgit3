#include "clar_libgit3.h"
#include "futils.h"
#include "repository.h"

static int remote_single_branch(git3_remote **out, git3_repository *repo, const char *name, const char *url, void *payload)
{
	GIT3_UNUSED(payload);

	cl_git_pass(git3_remote_create_with_fetchspec(out, repo, name, url, "+refs/heads/master:refs/remotes/origin/master"));

	return 0;
}

void test_online_shallow__clone_depth_zero(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_clone_options clone_opts = GIT3_CLONE_OPTIONS_INIT;
	git3_oid *roots;
	size_t roots_len;

	clone_opts.fetch_opts.depth = 0;
	clone_opts.remote_cb = remote_single_branch;

	git3_str_joinpath(&path, clar_sandbox_path(), "shallowclone_0");

	cl_git_pass(git3_clone(&repo, "https://github.com/libgit3/TestGitRepository", git3_str_cstr(&path), &clone_opts));

	/* cloning with depth 0 results in a full clone. */
	cl_assert_equal_b(false, git3_repository_is_shallow(repo));

	/* full clones do not have shallow roots. */
	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(0, roots_len);

	git3__free(roots);
	git3_str_dispose(&path);
	git3_repository_free(repo);
}

void test_online_shallow__clone_depth_one(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_revwalk *walk;
	git3_clone_options clone_opts = GIT3_CLONE_OPTIONS_INIT;
	git3_oid oid;
	git3_oid *roots;
	size_t roots_len;
	size_t num_commits = 0;
	int error = 0;

	clone_opts.fetch_opts.depth = 1;
	clone_opts.remote_cb = remote_single_branch;

	git3_str_joinpath(&path, clar_sandbox_path(), "shallowclone_1");

	cl_git_pass(git3_clone(&repo, "https://github.com/libgit3/TestGitRepository", git3_str_cstr(&path), &clone_opts));

	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(1, roots_len);
	cl_assert_equal_s("49322bb17d3acc9146f98c97d078513228bbf3c0", git3_oid_tostr_s(&roots[0]));

	git3_revwalk_new(&walk, repo);

	git3_revwalk_push_head(walk);

	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}

	cl_assert_equal_i(num_commits, 1);
	cl_assert_equal_i(error, GIT3_ITEROVER);

	git3__free(roots);
	git3_str_dispose(&path);
	git3_revwalk_free(walk);
	git3_repository_free(repo);
}

void test_online_shallow__clone_depth_five(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_revwalk *walk;
	git3_clone_options clone_opts = GIT3_CLONE_OPTIONS_INIT;
	git3_oid oid;
	git3_oid *roots;
	size_t roots_len;
	size_t num_commits = 0;
	int error = 0;

	clone_opts.fetch_opts.depth = 5;
	clone_opts.remote_cb = remote_single_branch;

	git3_str_joinpath(&path, clar_sandbox_path(), "shallowclone_5");

	cl_git_pass(git3_clone(&repo, "https://github.com/libgit3/TestGitRepository", git3_str_cstr(&path), &clone_opts));

	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(3, roots_len);
	cl_assert_equal_s("c070ad8c08840c8116da865b2d65593a6bb9cd2a", git3_oid_tostr_s(&roots[0]));
	cl_assert_equal_s("0966a434eb1a025db6b71485ab63a3bfbea520b6", git3_oid_tostr_s(&roots[1]));
	cl_assert_equal_s("83834a7afdaa1a1260568567f6ad90020389f664", git3_oid_tostr_s(&roots[2]));

	git3_revwalk_new(&walk, repo);

	git3_revwalk_push_head(walk);

	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}

	cl_assert_equal_i(num_commits, 13);
	cl_assert_equal_i(error, GIT3_ITEROVER);

	git3__free(roots);
	git3_str_dispose(&path);
	git3_revwalk_free(walk);
	git3_repository_free(repo);
}

void test_online_shallow__unshallow(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_revwalk *walk;
	git3_clone_options clone_opts = GIT3_CLONE_OPTIONS_INIT;
	git3_fetch_options fetch_opts = GIT3_FETCH_OPTIONS_INIT;
	git3_remote *origin = NULL;
	git3_oid oid;
	size_t num_commits = 0;
	int error = 0;

	clone_opts.fetch_opts.depth = 5;
	clone_opts.remote_cb = remote_single_branch;

	git3_str_joinpath(&path, clar_sandbox_path(), "unshallow");
	cl_git_pass(git3_clone(&repo, "https://github.com/libgit3/TestGitRepository", git3_str_cstr(&path), &clone_opts));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	fetch_opts.depth = GIT3_FETCH_DEPTH_UNSHALLOW;
	cl_git_pass(git3_remote_lookup(&origin, repo, "origin"));

	cl_git_pass(git3_remote_fetch(origin, NULL, &fetch_opts, NULL));
	cl_assert_equal_b(false, git3_repository_is_shallow(repo));

	git3_revwalk_new(&walk, repo);
	git3_revwalk_push_head(walk);

	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}

	cl_assert_equal_i(num_commits, 21);
	cl_assert_equal_i(error, GIT3_ITEROVER);

	git3_remote_free(origin);
	git3_str_dispose(&path);
	git3_revwalk_free(walk);
	git3_repository_free(repo);
}

void test_online_shallow__deepen_full(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_revwalk *walk;
	git3_clone_options clone_opts = GIT3_CLONE_OPTIONS_INIT;
	git3_fetch_options fetch_opts = GIT3_FETCH_OPTIONS_INIT;
	git3_remote *origin = NULL;
	git3_oid oid;
	git3_oid *roots;
	size_t roots_len;
	size_t num_commits = 0;
	int error = 0;

	clone_opts.fetch_opts.depth = 7;
	clone_opts.remote_cb = remote_single_branch;

	git3_str_joinpath(&path, clar_sandbox_path(), "deepen_full");
	cl_git_pass(git3_clone(&repo, "https://github.com/libgit3/TestGitRepository", git3_str_cstr(&path), &clone_opts));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	fetch_opts.depth = 8;
	cl_git_pass(git3_remote_lookup(&origin, repo, "origin"));
	cl_git_pass(git3_remote_fetch(origin, NULL, &fetch_opts, NULL));
	cl_assert_equal_b(false, git3_repository_is_shallow(repo));

	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(0, roots_len);

	git3_revwalk_new(&walk, repo);
	git3_revwalk_push_head(walk);

	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}

	cl_assert_equal_i(num_commits, 21);
	cl_assert_equal_i(error, GIT3_ITEROVER);

	git3__free(roots);
	git3_remote_free(origin);
	git3_str_dispose(&path);
	git3_revwalk_free(walk);
	git3_repository_free(repo);
}

void test_online_shallow__deepen_six(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_revwalk *walk;
	git3_clone_options clone_opts = GIT3_CLONE_OPTIONS_INIT;
	git3_fetch_options fetch_opts = GIT3_FETCH_OPTIONS_INIT;
	git3_remote *origin = NULL;
	git3_oid oid;
	git3_oid *roots;
	size_t roots_len;
	size_t num_commits = 0;
	int error = 0;

	clone_opts.fetch_opts.depth = 5;
	clone_opts.remote_cb = remote_single_branch;

	git3_str_joinpath(&path, clar_sandbox_path(), "deepen_6");
	cl_git_pass(git3_clone(&repo, "https://github.com/libgit3/TestGitRepository", git3_str_cstr(&path), &clone_opts));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	fetch_opts.depth = 6;
	cl_git_pass(git3_remote_lookup(&origin, repo, "origin"));
	cl_git_pass(git3_remote_fetch(origin, NULL, &fetch_opts, NULL));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(4, roots_len);
	cl_assert_equal_s("58be4659bb571194ed4562d04b359d26216f526e", git3_oid_tostr_s(&roots[0]));
	cl_assert_equal_s("d31f5a60d406e831d056b8ac2538d515100c2df2", git3_oid_tostr_s(&roots[1]));
	cl_assert_equal_s("6462e7d8024396b14d7651e2ec11e2bbf07a05c4", git3_oid_tostr_s(&roots[2]));
	cl_assert_equal_s("2c349335b7f797072cf729c4f3bb0914ecb6dec9", git3_oid_tostr_s(&roots[3]));

	git3_revwalk_new(&walk, repo);
	git3_revwalk_push_head(walk);

	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}

	cl_assert_equal_i(num_commits, 17);
	cl_assert_equal_i(error, GIT3_ITEROVER);

	git3__free(roots);
	git3_remote_free(origin);
	git3_str_dispose(&path);
	git3_revwalk_free(walk);
	git3_repository_free(repo);
}

void test_online_shallow__shorten_four(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_revwalk *walk;
	git3_clone_options clone_opts = GIT3_CLONE_OPTIONS_INIT;
	git3_fetch_options fetch_opts = GIT3_FETCH_OPTIONS_INIT;
	git3_remote *origin = NULL;
	git3_oid oid;
	git3_oid *roots;
	size_t roots_len;
	size_t num_commits = 0;
	int error = 0;

	clone_opts.fetch_opts.depth = 5;
	clone_opts.remote_cb = remote_single_branch;

	git3_str_joinpath(&path, clar_sandbox_path(), "shorten_4");
	cl_git_pass(git3_clone(&repo, "https://github.com/libgit3/TestGitRepository", git3_str_cstr(&path), &clone_opts));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	fetch_opts.depth = 4;
	cl_git_pass(git3_remote_lookup(&origin, repo, "origin"));
	cl_git_pass(git3_remote_fetch(origin, NULL, &fetch_opts, NULL));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(6, roots_len);
	/* roots added during initial clone, not removed as not encountered during fetch */
	cl_assert_equal_s("c070ad8c08840c8116da865b2d65593a6bb9cd2a", git3_oid_tostr_s(&roots[0]));
	cl_assert_equal_s("0966a434eb1a025db6b71485ab63a3bfbea520b6", git3_oid_tostr_s(&roots[1]));
	cl_assert_equal_s("83834a7afdaa1a1260568567f6ad90020389f664", git3_oid_tostr_s(&roots[3]));
	/* roots added during fetch */
	cl_assert_equal_s("bab66b48f836ed950c99134ef666436fb07a09a0", git3_oid_tostr_s(&roots[2]));
	cl_assert_equal_s("59706a11bde2b9899a278838ef20a97e8f8795d2", git3_oid_tostr_s(&roots[4]));
	cl_assert_equal_s("d86a2aada2f5e7ccf6f11880bfb9ab404e8a8864", git3_oid_tostr_s(&roots[5]));

	git3_revwalk_new(&walk, repo);
	git3_revwalk_push_head(walk);

	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}

	cl_assert_equal_i(num_commits, 10);
	cl_assert_equal_i(error, GIT3_ITEROVER);

	git3__free(roots);
	git3_remote_free(origin);
	git3_str_dispose(&path);
	git3_revwalk_free(walk);
	git3_repository_free(repo);
}

void test_online_shallow__preserve_unrelated_roots(void)
{
	git3_str path = GIT3_STR_INIT;
	git3_repository *repo;
	git3_revwalk *walk;
	git3_fetch_options fetch_opts = GIT3_FETCH_OPTIONS_INIT;
	git3_remote *origin = NULL;
	git3_strarray refspecs;
	git3_oid oid;
	git3_oid *roots;
	size_t roots_len;
	size_t num_commits = 0;
	int error = 0;
	git3_oid first_oid;
	git3_oid second_oid;
	git3_oid third_oid;
	char *first_commit = "c070ad8c08840c8116da865b2d65593a6bb9cd2a";
	char *second_commit = "6e1475206e57110fcef4b92320436c1e9872a322";
	char *third_commit = "7f822839a2fe9760f386cbbbcb3f92c5fe81def7";

#ifdef GIT3_EXPERIMENTAL_SHA256
	cl_git_pass(git3_oid_from_string(&first_oid, first_commit, GIT3_OID_SHA1));
	cl_git_pass(git3_oid_from_string(&second_oid, second_commit, GIT3_OID_SHA1));
	cl_git_pass(git3_oid_from_string(&third_oid, third_commit, GIT3_OID_SHA1));
#else
	cl_git_pass(git3_oid_fromstr(&first_oid, first_commit));
	cl_git_pass(git3_oid_fromstr(&second_oid, second_commit));
	cl_git_pass(git3_oid_fromstr(&third_oid, third_commit));
#endif

	/* setup empty repository without cloning */
	git3_str_joinpath(&path, clar_sandbox_path(), "preserve_unrelated_roots");
	cl_git_pass(git3_repository_init(&repo, git3_str_cstr(&path), true));
	cl_git_pass(git3_remote_create(&origin, repo, "origin", "https://github.com/libgit3/TestGitRepository"));
	cl_assert_equal_b(false, git3_repository_is_shallow(repo));

	/* shallow fetch for first commit */
	fetch_opts.depth = 1;
	refspecs.strings = &first_commit;
	refspecs.count = 1;
	cl_git_pass(git3_remote_fetch(origin, &refspecs, &fetch_opts, NULL));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(1, roots_len);
	cl_assert_equal_s("c070ad8c08840c8116da865b2d65593a6bb9cd2a", git3_oid_tostr_s(&roots[0]));

	cl_git_pass(git3_revwalk_new(&walk, repo));
	cl_git_pass(git3_revwalk_push(walk, &first_oid));
	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}
	cl_assert_equal_i(num_commits, 1);
	cl_assert_equal_i(error, GIT3_ITEROVER);

	/* shallow fetch for second commit */
	fetch_opts.depth = 1;
	refspecs.strings = &second_commit;
	refspecs.count = 1;
	cl_git_pass(git3_remote_fetch(origin, &refspecs, &fetch_opts, NULL));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	git3__free(roots);
	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(2, roots_len);
	cl_assert_equal_s("c070ad8c08840c8116da865b2d65593a6bb9cd2a", git3_oid_tostr_s(&roots[0]));
	cl_assert_equal_s("6e1475206e57110fcef4b92320436c1e9872a322", git3_oid_tostr_s(&roots[1]));

	git3_revwalk_free(walk);
	cl_git_pass(git3_revwalk_new(&walk, repo));
	cl_git_pass(git3_revwalk_push(walk, &second_oid));
	num_commits = 0;
	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}
	cl_assert_equal_i(error, GIT3_ITEROVER);
	cl_assert_equal_i(num_commits, 1);

	/* fetch full history for third commit, includes first commit which should be removed from shallow roots */
	fetch_opts.depth = 100;
	refspecs.strings = &third_commit;
	refspecs.count = 1;
	cl_git_pass(git3_remote_fetch(origin, &refspecs, &fetch_opts, NULL));
	cl_assert_equal_b(true, git3_repository_is_shallow(repo));

	git3__free(roots);
	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(1, roots_len);
	cl_assert_equal_s("6e1475206e57110fcef4b92320436c1e9872a322", git3_oid_tostr_s(&roots[0]));

	git3_revwalk_free(walk);
	cl_git_pass(git3_revwalk_new(&walk, repo));
	cl_git_pass(git3_revwalk_push(walk, &third_oid));
	num_commits = 0;
	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}
	cl_assert_equal_i(error, GIT3_ITEROVER);
	cl_assert_equal_i(num_commits, 12);

	cl_git_pass(git3_revwalk_reset(walk));
	cl_git_pass(git3_revwalk_push(walk, &second_oid));
	num_commits = 0;
	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}
	cl_assert_equal_i(error, GIT3_ITEROVER);
	cl_assert_equal_i(num_commits, 1);

	/* unshallow repository without specifying any refspec */
	fetch_opts.depth = GIT3_FETCH_DEPTH_UNSHALLOW;
	cl_git_pass(git3_remote_fetch(origin, NULL, &fetch_opts, NULL));
	cl_assert_equal_b(false, git3_repository_is_shallow(repo));

	git3__free(roots);
	cl_git_pass(git3_repository__shallow_roots(&roots, &roots_len, repo));
	cl_assert_equal_i(0, roots_len);

	git3_revwalk_free(walk);
	cl_git_pass(git3_revwalk_new(&walk, repo));
	cl_git_pass(git3_revwalk_push(walk, &first_oid));
	cl_git_pass(git3_revwalk_push(walk, &second_oid));
	cl_git_pass(git3_revwalk_push(walk, &third_oid));
	num_commits = 0;
	while ((error = git3_revwalk_next(&oid, walk)) == GIT3_OK) {
		num_commits++;
	}
	cl_assert_equal_i(error, GIT3_ITEROVER);
	cl_assert_equal_i(num_commits, 18);

	git3__free(roots);
	git3_remote_free(origin);
	git3_str_dispose(&path);
	git3_revwalk_free(walk);
	git3_repository_free(repo);
}
