#include "clar_libgit3.h"
#include "odb.h"
#include "filebuf.h"

#define TEST_REPO_PATH "redundant.git"

git3_repository *g_repo;
git3_odb *g_odb;

void test_odb_emptyobjects__initialize(void)
{
	g_repo = cl_git_sandbox_init(TEST_REPO_PATH);
	cl_git_pass(git3_repository_odb(&g_odb, g_repo));
}

void test_odb_emptyobjects__cleanup(void)
{
	git3_odb_free(g_odb);
	cl_git_sandbox_cleanup();
}

void test_odb_emptyobjects__blob_notfound(void)
{
	git3_oid id, written_id;
	git3_blob *blob;

	cl_git_pass(git3_oid_from_string(&id, "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391", GIT3_OID_SHA1));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_blob_lookup(&blob, g_repo, &id));

	cl_git_pass(git3_odb_write(&written_id, g_odb, "", 0, GIT3_OBJECT_BLOB));
	cl_assert(git3_fs_path_exists(TEST_REPO_PATH "/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391"));
}

void test_odb_emptyobjects__read_tree(void)
{
	git3_oid id;
	git3_tree *tree;

	cl_git_pass(git3_oid_from_string(&id, "4b825dc642cb6eb9a060e54bf8d69288fbee4904", GIT3_OID_SHA1));
	cl_git_pass(git3_tree_lookup(&tree, g_repo, &id));
	cl_assert_equal_i(GIT3_OBJECT_TREE, git3_object_type((git3_object *) tree));
	cl_assert_equal_i(0, git3_tree_entrycount(tree));
	cl_assert_equal_p(NULL, git3_tree_entry_byname(tree, "foo"));
	git3_tree_free(tree);
}

void test_odb_emptyobjects__read_tree_odb(void)
{
	git3_oid id;
	git3_odb_object *tree_odb;

	cl_git_pass(git3_oid_from_string(&id, "4b825dc642cb6eb9a060e54bf8d69288fbee4904", GIT3_OID_SHA1));
	cl_git_pass(git3_odb_read(&tree_odb, g_odb, &id));
	cl_assert(git3_odb_object_data(tree_odb));
	cl_assert_equal_s("", git3_odb_object_data(tree_odb));
	cl_assert_equal_i(0, git3_odb_object_size(tree_odb));
	git3_odb_object_free(tree_odb);
}
