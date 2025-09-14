#include "clar_libgit3.h"

#include "repository.h"

static git3_repository *g_repo;
static git3_tree *g_root_tree;
static git3_commit *g_head_commit;
static git3_object *g_expectedobject,
						*g_actualobject;

void test_object_lookupbypath__initialize(void)
{
	git3_reference *head;
	git3_tree_entry *tree_entry;

	cl_git_pass(git3_repository_open(&g_repo, cl_fixture("attr/.gitted")));

	cl_git_pass(git3_repository_head(&head, g_repo));
	cl_git_pass(git3_reference_peel((git3_object**)&g_head_commit, head, GIT3_OBJECT_COMMIT));
	cl_git_pass(git3_commit_tree(&g_root_tree, g_head_commit));
	cl_git_pass(git3_tree_entry_bypath(&tree_entry, g_root_tree, "subdir/subdir_test2.txt"));
	cl_git_pass(git3_object_lookup(&g_expectedobject, g_repo, git3_tree_entry_id(tree_entry),
				GIT3_OBJECT_ANY));

	git3_tree_entry_free(tree_entry);
	git3_reference_free(head);

	g_actualobject = NULL;
}
void test_object_lookupbypath__cleanup(void)
{
	git3_object_free(g_actualobject);
	git3_object_free(g_expectedobject);
	git3_tree_free(g_root_tree);
	git3_commit_free(g_head_commit);
	g_expectedobject = NULL;
	git3_repository_free(g_repo);
	g_repo = NULL;
}

void test_object_lookupbypath__errors(void)
{
	cl_assert_equal_i(GIT3_EINVALIDSPEC,
			git3_object_lookup_bypath(&g_actualobject, (git3_object*)g_root_tree,
				"subdir/subdir_test2.txt", GIT3_OBJECT_TREE)); /* It's not a tree */
	cl_assert_equal_i(GIT3_ENOTFOUND,
			git3_object_lookup_bypath(&g_actualobject, (git3_object*)g_root_tree,
				"file/doesnt/exist", GIT3_OBJECT_ANY));
}

void test_object_lookupbypath__from_root_tree(void)
{
	cl_git_pass(git3_object_lookup_bypath(&g_actualobject, (git3_object*)g_root_tree,
				"subdir/subdir_test2.txt", GIT3_OBJECT_BLOB));
	cl_assert_equal_oid(git3_object_id(g_expectedobject),
		git3_object_id(g_actualobject));
}

void test_object_lookupbypath__from_head_commit(void)
{
	cl_git_pass(git3_object_lookup_bypath(&g_actualobject, (git3_object*)g_head_commit,
				"subdir/subdir_test2.txt", GIT3_OBJECT_BLOB));
	cl_assert_equal_oid(git3_object_id(g_expectedobject),
				git3_object_id(g_actualobject));
}

void test_object_lookupbypath__from_subdir_tree(void)
{
	git3_tree_entry *entry = NULL;
	git3_tree *tree = NULL;

	cl_git_pass(git3_tree_entry_bypath(&entry, g_root_tree, "subdir"));
	cl_git_pass(git3_tree_lookup(&tree, g_repo, git3_tree_entry_id(entry)));

	cl_git_pass(git3_object_lookup_bypath(&g_actualobject, (git3_object*)tree,
				"subdir_test2.txt", GIT3_OBJECT_BLOB));
	cl_assert_equal_oid(git3_object_id(g_expectedobject),
				git3_object_id(g_actualobject));

	git3_tree_entry_free(entry);
	git3_tree_free(tree);
}

