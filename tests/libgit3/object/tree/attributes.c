#include "clar_libgit3.h"
#include "tree.h"

static git3_repository *repo;

static const char *blob_oid = "3d0970ec547fc41ef8a5882dde99c6adce65b021";
static const char *tree_oid  = "1b05fdaa881ee45b48cbaa5e9b037d667a47745e";

void test_object_tree_attributes__initialize(void)
{
	repo = cl_git_sandbox_init("deprecated-mode.git");
}

void test_object_tree_attributes__cleanup(void)
{
   cl_git_sandbox_cleanup();
}

void test_object_tree_attributes__ensure_correctness_of_attributes_on_insertion(void)
{
	git3_treebuilder *builder;
	git3_oid oid;

	cl_git_pass(git3_oid_from_string(&oid, blob_oid, GIT3_OID_SHA1));

	cl_git_pass(git3_treebuilder_new(&builder, repo, NULL));

	cl_git_fail(git3_treebuilder_insert(NULL, builder, "one.txt", &oid, (git3_filemode_t)0777777));
	cl_git_fail(git3_treebuilder_insert(NULL, builder, "one.txt", &oid, (git3_filemode_t)0100666));
	cl_git_fail(git3_treebuilder_insert(NULL, builder, "one.txt", &oid, (git3_filemode_t)0000001));

	git3_treebuilder_free(builder);
}

void test_object_tree_attributes__group_writable_tree_entries_created_with_an_antique_git_version_can_still_be_accessed(void)
{
	git3_oid tid;
	git3_tree *tree;
	const git3_tree_entry *entry;


	cl_git_pass(git3_oid_from_string(&tid, tree_oid, GIT3_OID_SHA1));
	cl_git_pass(git3_tree_lookup(&tree, repo, &tid));

	entry = git3_tree_entry_byname(tree, "old_mode.txt");
	cl_assert_equal_i(
		GIT3_FILEMODE_BLOB,
		git3_tree_entry_filemode(entry));

	git3_tree_free(tree);
}

void test_object_tree_attributes__treebuilder_reject_invalid_filemode(void)
{
	git3_treebuilder *builder;
	git3_oid bid;
	const git3_tree_entry *entry;

	cl_git_pass(git3_oid_from_string(&bid, blob_oid, GIT3_OID_SHA1));
	cl_git_pass(git3_treebuilder_new(&builder, repo, NULL));

	cl_git_fail(git3_treebuilder_insert(
		&entry,
		builder,
		"normalized.txt",
		&bid,
		GIT3_FILEMODE_BLOB_GROUP_WRITABLE));

	git3_treebuilder_free(builder);
}

void test_object_tree_attributes__normalize_attributes_when_creating_a_tree_from_an_existing_one(void)
{
	git3_treebuilder *builder;
	git3_oid tid, tid2;
	git3_tree *tree;
	const git3_tree_entry *entry;

	cl_git_pass(git3_oid_from_string(&tid, tree_oid, GIT3_OID_SHA1));
	cl_git_pass(git3_tree_lookup(&tree, repo, &tid));

	cl_git_pass(git3_treebuilder_new(&builder, repo, tree));
	
	entry = git3_treebuilder_get(builder, "old_mode.txt");
	cl_assert(entry != NULL);
	cl_assert_equal_i(
		GIT3_FILEMODE_BLOB,
		git3_tree_entry_filemode(entry));

	cl_git_pass(git3_treebuilder_write(&tid2, builder));
	git3_treebuilder_free(builder);
	git3_tree_free(tree);

	cl_git_pass(git3_tree_lookup(&tree, repo, &tid2));
	entry = git3_tree_entry_byname(tree, "old_mode.txt");
	cl_assert(entry != NULL);
	cl_assert_equal_i(
		GIT3_FILEMODE_BLOB,
		git3_tree_entry_filemode(entry));

	git3_tree_free(tree);
}

void test_object_tree_attributes__normalize_600(void)
{
	git3_oid id;
	git3_tree *tree;
	const git3_tree_entry *entry;

	git3_oid_from_string(&id, "0810fb7818088ff5ac41ee49199b51473b1bd6c7", GIT3_OID_SHA1);
	cl_git_pass(git3_tree_lookup(&tree, repo, &id));

	entry = git3_tree_entry_byname(tree, "ListaTeste.xml");
	cl_assert_equal_i(git3_tree_entry_filemode(entry), GIT3_FILEMODE_BLOB);
	cl_assert_equal_i(git3_tree_entry_filemode_raw(entry), 0100600);

	git3_tree_free(tree);
}
