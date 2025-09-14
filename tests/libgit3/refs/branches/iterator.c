#include "clar_libgit3.h"
#include "refs.h"

static git3_repository *repo;
static git3_reference *fake_remote;

void test_refs_branches_iterator__initialize(void)
{
	git3_oid id;

	cl_fixture_sandbox("testrepo.git");
	cl_git_pass(git3_repository_open(&repo, "testrepo.git"));

	cl_git_pass(git3_oid_from_string(&id, "be3563ae3f795b2b4353bcce3a527ad0a4f7f644", GIT3_OID_SHA1));
	cl_git_pass(git3_reference_create(&fake_remote, repo, "refs/remotes/nulltoken/master", &id, 0, NULL));
}

void test_refs_branches_iterator__cleanup(void)
{
	git3_reference_free(fake_remote);
	fake_remote = NULL;

	git3_repository_free(repo);
	repo = NULL;

	cl_fixture_cleanup("testrepo.git");

	cl_git_sandbox_cleanup();
}

static void assert_retrieval(unsigned int flags, unsigned int expected_count)
{
	git3_branch_iterator *iter;
	git3_reference *ref;
	int count = 0, error;
	git3_branch_t type;

	cl_git_pass(git3_branch_iterator_new(&iter, repo, flags));
	while ((error = git3_branch_next(&ref, &type, iter)) == 0) {
		count++;
		git3_reference_free(ref);
	}

	git3_branch_iterator_free(iter);
	cl_assert_equal_i(error, GIT3_ITEROVER);
	cl_assert_equal_i(expected_count, count);
}

void test_refs_branches_iterator__retrieve_all_branches(void)
{
	assert_retrieval(GIT3_BRANCH_ALL, 15);
}

void test_refs_branches_iterator__retrieve_remote_branches(void)
{
	assert_retrieval(GIT3_BRANCH_REMOTE, 2);
}

void test_refs_branches_iterator__retrieve_local_branches(void)
{
	assert_retrieval(GIT3_BRANCH_LOCAL, 13);
}

struct expectations {
	const char *branch_name;
	int encounters;
};

static void assert_branch_has_been_found(struct expectations *findings, const char* expected_branch_name)
{
	int pos = 0;

	for (pos = 0; findings[pos].branch_name; ++pos) {
		if (strcmp(expected_branch_name, findings[pos].branch_name) == 0) {
			cl_assert_equal_i(1, findings[pos].encounters);
			return;
		}
	}

	cl_fail("expected branch not found in list.");
}

static void contains_branches(struct expectations exp[], git3_branch_iterator *iter)
{
	git3_reference *ref;
	git3_branch_t type;
	int error, pos = 0;

	while ((error = git3_branch_next(&ref, &type, iter)) == 0) {
		for (pos = 0; exp[pos].branch_name; ++pos) {
			if (strcmp(git3_reference_shorthand(ref), exp[pos].branch_name) == 0)
				exp[pos].encounters++;
		}

		git3_reference_free(ref);
	}

	cl_assert_equal_i(error, GIT3_ITEROVER);
}

/*
 * $ git branch -r
 *  nulltoken/HEAD -> nulltoken/master
 *  nulltoken/master
 */
void test_refs_branches_iterator__retrieve_remote_symbolic_HEAD_when_present(void)
{
	git3_branch_iterator *iter;
	struct expectations exp[] = {
		{ "nulltoken/HEAD", 0 },
		{ "nulltoken/master", 0 },
		{ NULL, 0 }
	};

	git3_reference_free(fake_remote);
	cl_git_pass(git3_reference_symbolic_create(&fake_remote, repo, "refs/remotes/nulltoken/HEAD", "refs/remotes/nulltoken/master", 0, NULL));

	assert_retrieval(GIT3_BRANCH_REMOTE, 3);

	cl_git_pass(git3_branch_iterator_new(&iter, repo, GIT3_BRANCH_REMOTE));
	contains_branches(exp, iter);
	git3_branch_iterator_free(iter);

	assert_branch_has_been_found(exp, "nulltoken/HEAD");
	assert_branch_has_been_found(exp, "nulltoken/master");
}

void test_refs_branches_iterator__mix_of_packed_and_loose(void)
{
	git3_branch_iterator *iter;
	struct expectations exp[] = {
		{ "master", 0 },
		{ "origin/HEAD", 0 },
		{ "origin/master", 0 },
		{ "origin/packed", 0 },
		{ NULL, 0 }
	};
	git3_repository *r2;

	r2 = cl_git_sandbox_init("testrepo2");

	cl_git_pass(git3_branch_iterator_new(&iter, r2, GIT3_BRANCH_ALL));
	contains_branches(exp, iter);

	git3_branch_iterator_free(iter);

	assert_branch_has_been_found(exp, "master");
	assert_branch_has_been_found(exp, "origin/HEAD");
	assert_branch_has_been_found(exp, "origin/master");
	assert_branch_has_been_found(exp, "origin/packed");
}
