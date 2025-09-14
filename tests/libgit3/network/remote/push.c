#include "clar_libgit3.h"
#include "git3/sys/commit.h"
#include "oid.h"

static git3_remote *_remote;
static git3_repository *_repo, *_dummy;

void test_network_remote_push__initialize(void)
{
	cl_fixture_sandbox("testrepo.git");
	git3_repository_open(&_repo, "testrepo.git");

	/* We need a repository to have a remote */
	cl_git_pass(git3_repository_init(&_dummy, "dummy.git", true));
	cl_git_pass(git3_remote_create(&_remote, _dummy, "origin", cl_git_path_url("testrepo.git")));
}

void test_network_remote_push__cleanup(void)
{
	git3_remote_free(_remote);
	_remote = NULL;

	git3_repository_free(_repo);
	_repo = NULL;

	git3_repository_free(_dummy);
	_dummy = NULL;

	cl_fixture_cleanup("testrepo.git");
	cl_fixture_cleanup("dummy.git");
}

static int negotiation_cb(const git3_push_update **updates, size_t len, void *payload)
{
	const git3_push_update *expected = payload;

	cl_assert_equal_i(1, len);
	cl_assert_equal_s(expected->src_refname, updates[0]->src_refname);
	cl_assert_equal_s(expected->dst_refname, updates[0]->dst_refname);
	cl_assert_equal_oid(&expected->src, &updates[0]->src);
	cl_assert_equal_oid(&expected->dst, &updates[0]->dst);

	return 0;
}

void test_network_remote_push__delete_notification(void)
{
	git3_push_options opts = GIT3_PUSH_OPTIONS_INIT;
	git3_reference *ref;
	git3_push_update expected;
	char *refspec = ":refs/heads/master";
	const git3_strarray refspecs = {
		&refspec,
		1,
	};

	cl_git_pass(git3_reference_lookup(&ref, _repo, "refs/heads/master"));

	expected.src_refname = "";
	expected.dst_refname = "refs/heads/master";
	git3_oid_clear(&expected.dst, GIT3_OID_SHA1);
	git3_oid_cpy(&expected.src, git3_reference_target(ref));

	opts.callbacks.push_negotiation = negotiation_cb;
	opts.callbacks.payload = &expected;
	cl_git_pass(git3_remote_push(_remote, &refspecs, &opts));

	git3_reference_free(ref);
	cl_git_fail_with(GIT3_ENOTFOUND, git3_reference_lookup(&ref, _repo, "refs/heads/master"));

}

static void create_dummy_commit(git3_reference **out, git3_repository *repo)
{
	git3_index *index;
	git3_oid tree_id, commit_id;
	git3_signature *sig;

	cl_git_pass(git3_repository_index(&index, repo));
	cl_git_pass(git3_index_write_tree(&tree_id, index));
	git3_index_free(index);

	cl_git_pass(git3_signature_now(&sig, "Pusher Joe", "pjoe"));
	cl_git_pass(git3_commit_create_from_ids(&commit_id, repo, NULL, sig, sig,
					       NULL, "Empty tree\n", &tree_id, 0, NULL));
	cl_git_pass(git3_reference_create(out, repo, "refs/heads/empty-tree", &commit_id, true, "commit yo"));
	git3_signature_free(sig);
}

void test_network_remote_push__create_notification(void)
{
	git3_push_options opts = GIT3_PUSH_OPTIONS_INIT;
	git3_reference *ref;
	git3_push_update expected;
	char *refspec = "refs/heads/empty-tree";
	const git3_strarray refspecs = {
		&refspec,
		1,
	};

	create_dummy_commit(&ref, _dummy);

	expected.src_refname = "refs/heads/empty-tree";
	expected.dst_refname = "refs/heads/empty-tree";
	git3_oid_cpy(&expected.dst, git3_reference_target(ref));
	git3_oid_clear(&expected.src, GIT3_OID_SHA1);

	opts.callbacks.push_negotiation = negotiation_cb;
	opts.callbacks.payload = &expected;
	cl_git_pass(git3_remote_push(_remote, &refspecs, &opts));

	git3_reference_free(ref);
	cl_git_pass(git3_reference_lookup(&ref, _repo, "refs/heads/empty-tree"));
	git3_reference_free(ref);
}
