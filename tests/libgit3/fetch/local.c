#include "clar_libgit3.h"
#include "futils.h"

static git3_repository *repo;

void test_fetch_local__initialize(void)
{
	cl_git_pass(git3_repository_init(&repo, "./fetch", 0));
}

void test_fetch_local__cleanup(void)
{
	git3_repository_free(repo);
	repo = NULL;

	cl_fixture_cleanup("./fetch");
}

void test_fetch_local__defaults(void)
{
	git3_remote *remote;
	git3_object *obj;
	git3_oid expected_id;

	cl_git_pass(git3_remote_create(&remote, repo, "test",
		cl_fixture("testrepo.git")));
	cl_git_pass(git3_remote_fetch(remote, NULL, NULL, NULL));

	git3_oid_from_string(&expected_id, "258f0e2a959a364e40ed6603d5d44fbb24765b10", GIT3_OID_SHA1);

	cl_git_pass(git3_revparse_single(&obj, repo, "refs/remotes/test/haacked"));
	cl_assert_equal_oid(&expected_id, git3_object_id(obj));

	git3_object_free(obj);
	git3_remote_free(remote);
}

void test_fetch_local__reachable_commit(void)
{
	git3_remote *remote;
	git3_strarray refspecs;
	git3_object *obj;
	git3_oid expected_id;
	git3_str fetchhead = GIT3_STR_INIT;
	char *refspec = "+5b5b025afb0b4c913b4c338a42934a3863bf3644:refs/success";

	refspecs.strings = &refspec;
	refspecs.count = 1;

	git3_oid_from_string(&expected_id, "5b5b025afb0b4c913b4c338a42934a3863bf3644", GIT3_OID_SHA1);

	cl_git_pass(git3_remote_create(&remote, repo, "test",
		cl_fixture("testrepo.git")));
	cl_git_pass(git3_remote_fetch(remote, &refspecs, NULL, NULL));

	cl_git_pass(git3_revparse_single(&obj, repo, "refs/success"));
	cl_assert_equal_oid(&expected_id, git3_object_id(obj));

	cl_git_pass(git3_futils_readbuffer(&fetchhead, "./fetch/.git/FETCH_HEAD"));
	cl_assert_equal_strn(fetchhead.ptr,
		"5b5b025afb0b4c913b4c338a42934a3863bf3644\t\t'5b5b025afb0b4c913b4c338a42934a3863bf3644' of ",
		strlen("5b5b025afb0b4c913b4c338a42934a3863bf3644\t\t'5b5b025afb0b4c913b4c338a42934a3863bf3644' of "));

	git3_str_dispose(&fetchhead);
	git3_object_free(obj);
	git3_remote_free(remote);
}
