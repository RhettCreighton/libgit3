#include "clar_libgit3.h"
#include "repo/repo_helpers.h"

void test_repo_getters__is_empty_correctly_deals_with_pristine_looking_repos(void)
{
	git3_repository *repo;

	repo = cl_git_sandbox_init("empty_bare.git");
	cl_git_remove_placeholders(git3_repository_path(repo), "dummy-marker.txt");

	cl_assert_equal_i(true, git3_repository_is_empty(repo));

	cl_git_sandbox_cleanup();
}

void test_repo_getters__is_empty_can_detect_used_repositories(void)
{
	git3_repository *repo;

	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));

	cl_assert_equal_i(false, git3_repository_is_empty(repo));

	git3_repository_free(repo);
}

void test_repo_getters__is_empty_can_detect_repositories_with_defaultbranch_config_empty(void)
{
	git3_repository *repo;

	create_tmp_global_config("tmp_global_path", "init.defaultBranch", "");

	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));
	cl_assert_equal_i(false, git3_repository_is_empty(repo));

	git3_repository_free(repo);
}

void test_repo_getters__retrieving_the_odb_honors_the_refcount(void)
{
	git3_odb *odb;
	git3_repository *repo;

	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));

	cl_git_pass(git3_repository_odb(&odb, repo));
	cl_assert(((git3_refcount *)odb)->refcount.val == 2);

	git3_repository_free(repo);
	cl_assert(((git3_refcount *)odb)->refcount.val == 1);

	git3_odb_free(odb);
}

void test_repo_getters__commit_parents(void)
{
	git3_repository *repo;
	git3_commitarray parents;
	git3_oid first_parent;
	git3_oid merge_parents[4];

	git3_oid_from_string(&first_parent, "099fabac3a9ea935598528c27f866e34089c2eff", GIT3_OID_SHA1);

	/* A commit on a new repository has no parents */

	cl_git_pass(git3_repository_init(&repo, "new_repo", false));
	cl_git_pass(git3_repository_commit_parents(&parents, repo));

	cl_assert_equal_sz(0, parents.count);
	cl_assert_equal_p(NULL, parents.commits);

	git3_commitarray_dispose(&parents);
	git3_repository_free(repo);

	/* A standard commit has one parent */

	repo = cl_git_sandbox_init("testrepo");
	cl_git_pass(git3_repository_commit_parents(&parents, repo));

	cl_assert_equal_sz(1, parents.count);
	cl_assert_equal_oid(&first_parent, git3_commit_id(parents.commits[0]));

	git3_commitarray_dispose(&parents);

	/* A merge commit has multiple parents */

	cl_git_rewritefile("testrepo/.git/MERGE_HEAD",
		"8496071c1b46c854b31185ea97743be6a8774479\n"
		"5b5b025afb0b4c913b4c338a42934a3863bf3644\n"
		"4a202b346bb0fb0db7eff3cffeb3c70babbd2045\n"
		"9fd738e8f7967c078dceed8190330fc8648ee56a\n");

	cl_git_pass(git3_repository_commit_parents(&parents, repo));

	cl_assert_equal_sz(5, parents.count);

	cl_assert_equal_oid(&first_parent, git3_commit_id(parents.commits[0]));

	git3_oid_from_string(&merge_parents[0], "8496071c1b46c854b31185ea97743be6a8774479", GIT3_OID_SHA1);
	cl_assert_equal_oid(&merge_parents[0], git3_commit_id(parents.commits[1]));
	git3_oid_from_string(&merge_parents[1], "5b5b025afb0b4c913b4c338a42934a3863bf3644", GIT3_OID_SHA1);
	cl_assert_equal_oid(&merge_parents[1], git3_commit_id(parents.commits[2]));
	git3_oid_from_string(&merge_parents[2], "4a202b346bb0fb0db7eff3cffeb3c70babbd2045", GIT3_OID_SHA1);
	cl_assert_equal_oid(&merge_parents[2], git3_commit_id(parents.commits[3]));
	git3_oid_from_string(&merge_parents[3], "9fd738e8f7967c078dceed8190330fc8648ee56a", GIT3_OID_SHA1);
	cl_assert_equal_oid(&merge_parents[3], git3_commit_id(parents.commits[4]));

	git3_commitarray_dispose(&parents);

	git3_repository_free(repo);

	cl_fixture_cleanup("testrepo");
}
