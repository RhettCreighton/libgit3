#include "clar_libgit3.h"
#include "git3/sys/commit.h"

static git3_remote *_remote;
static git3_repository *_repo, *_dummy;

void test_network_remote_tag__initialize(void)
{
	cl_fixture_sandbox("testrepo.git");
	git3_repository_open(&_repo, "testrepo.git");

	/* We need a repository to have a remote */
	cl_git_pass(git3_repository_init(&_dummy, "dummytag.git", true));
	cl_git_pass(git3_remote_create(&_remote, _dummy, "origin", cl_git_path_url("testrepo.git")));
}

void test_network_remote_tag__cleanup(void)
{
	git3_remote_free(_remote);
	_remote = NULL;

	git3_repository_free(_repo);
	_repo = NULL;

	git3_repository_free(_dummy);
	_dummy = NULL;

	cl_fixture_cleanup("testrepo.git");
	cl_fixture_cleanup("dummytag.git");
}

/*
 * Create one commit, one tree, one blob.
 * Create two tags: one for the commit, one for the blob.
 */
static void create_commit_with_tags(git3_reference **out, git3_oid *out_commit_tag_id, git3_oid *out_blob_tag_id, git3_repository *repo)
{
	git3_treebuilder *treebuilder;
	git3_oid blob_id, tree_id, commit_id;
	git3_signature *sig;
	git3_object *target;

	cl_git_pass(git3_treebuilder_new(&treebuilder, repo, NULL));

	cl_git_pass(git3_blob_create_from_buffer(&blob_id, repo, "", 0));
	cl_git_pass(git3_treebuilder_insert(NULL, treebuilder, "README.md", &blob_id, 0100644));
	cl_git_pass(git3_treebuilder_write(&tree_id, treebuilder));

	cl_git_pass(git3_signature_now(&sig, "Pusher Joe", "pjoe"));
	cl_git_pass(git3_commit_create_from_ids(&commit_id, repo, NULL, sig, sig,
					       NULL, "Tree with tags\n", &tree_id, 0, NULL));
	cl_git_pass(git3_reference_create(out, repo, "refs/heads/tree-with-tags", &commit_id, true, "commit yo"));

	cl_git_pass(git3_object_lookup(&target, repo, &commit_id, GIT3_OBJECT_COMMIT));
	cl_git_pass(git3_tag_create_lightweight(out_commit_tag_id, repo, "tagged-commit", target, true));
	git3_object_free(target);

	cl_git_pass(git3_object_lookup(&target, repo, &blob_id, GIT3_OBJECT_BLOB));
	cl_git_pass(git3_tag_create_lightweight(out_blob_tag_id, repo, "tagged-blob", target, true));
	git3_object_free(target);

	git3_treebuilder_free(treebuilder);
	git3_signature_free(sig);
}

void test_network_remote_tag__push_different_tag_types(void)
{
	git3_push_options opts = GIT3_PUSH_OPTIONS_INIT;
	git3_reference *ref;
	git3_oid commit_tag_id, blob_tag_id;
	char* refspec_tree = "refs/heads/tree-with-tags";
	char* refspec_tagged_commit = "refs/tags/tagged-commit";
	char* refspec_tagged_blob = "refs/tags/tagged-blob";
	const git3_strarray refspecs_tree = { &refspec_tree, 1 };
	const git3_strarray refspecs_tagged_commit = { &refspec_tagged_commit, 1 };
	const git3_strarray refspecs_tagged_blob = { &refspec_tagged_blob, 1 };

	create_commit_with_tags(&ref, &commit_tag_id, &blob_tag_id, _dummy);

	/* Push tree */
	cl_git_pass(git3_remote_push(_remote, &refspecs_tree, &opts));
	git3_reference_free(ref);
	cl_git_pass(git3_reference_lookup(&ref, _repo, "refs/heads/tree-with-tags"));
	git3_reference_free(ref);

	/* Push tagged commit */
	cl_git_pass(git3_remote_push(_remote, &refspecs_tagged_commit, &opts));
	cl_git_pass(git3_reference_name_to_id(&commit_tag_id, _repo, "refs/tags/tagged-commit"));

	/* Push tagged blob */
	cl_git_pass(git3_remote_push(_remote, &refspecs_tagged_blob, &opts));
	cl_git_pass(git3_reference_name_to_id(&blob_tag_id, _repo, "refs/tags/tagged-blob"));
}
