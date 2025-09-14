#include "clar_libgit3.h"

#include "tree.h"

static const char *tree_oid = "1810dff58d8a660512d4832e740f692884338ccd";

static git3_repository *g_repo;

/* Fixture setup and teardown */
void test_object_tree_read__initialize(void)
{
   g_repo = cl_git_sandbox_init("testrepo");
}

void test_object_tree_read__cleanup(void)
{
   cl_git_sandbox_cleanup();
}



void test_object_tree_read__loaded(void)
{
	/* access randomly the entries on a loaded tree */
	git3_oid id;
	git3_tree *tree;

	git3_oid_from_string(&id, tree_oid, GIT3_OID_SHA1);

	cl_git_pass(git3_tree_lookup(&tree, g_repo, &id));

	cl_assert(git3_tree_entry_byname(tree, "README") != NULL);
	cl_assert(git3_tree_entry_byname(tree, "NOTEXISTS") == NULL);
	cl_assert(git3_tree_entry_byname(tree, "") == NULL);
	cl_assert(git3_tree_entry_byindex(tree, 0) != NULL);
	cl_assert(git3_tree_entry_byindex(tree, 2) != NULL);
	cl_assert(git3_tree_entry_byindex(tree, 3) == NULL);
	cl_assert(git3_tree_entry_byindex(tree, (unsigned int)-1) == NULL);

	git3_tree_free(tree);
}

void test_object_tree_read__two(void)
{
	/* read a tree from the repository */
	git3_oid id;
	git3_tree *tree;
	const git3_tree_entry *entry;
	git3_object *obj;

	git3_oid_from_string(&id, tree_oid, GIT3_OID_SHA1);

	cl_git_pass(git3_tree_lookup(&tree, g_repo, &id));

	cl_assert(git3_tree_entrycount(tree) == 3);

	/* GH-86: git3_object_lookup() should also check the type if the object comes from the cache */
	cl_assert(git3_object_lookup(&obj, g_repo, &id, GIT3_OBJECT_TREE) == 0);
	cl_assert(obj != NULL);
	git3_object_free(obj);
	obj = NULL;
	cl_git_fail(git3_object_lookup(&obj, g_repo, &id, GIT3_OBJECT_BLOB));
	cl_assert(obj == NULL);

	entry = git3_tree_entry_byname(tree, "README");
	cl_assert(entry != NULL);

	cl_assert_equal_s(git3_tree_entry_name(entry), "README");

	cl_git_pass(git3_tree_entry_to_object(&obj, g_repo, entry));
	cl_assert(obj != NULL);

	git3_object_free(obj);
	git3_tree_free(tree);
}

#define BIGFILE "bigfile"

#ifdef GIT3_ARCH_64
#define BIGFILE_SIZE (off_t)4294967296
#else
# define BIGFILE_SIZE SIZE_MAX
#endif

void test_object_tree_read__largefile(void)
{
	const git3_tree_entry *entry;
	git3_index_entry ie;
	git3_commit *commit;
	git3_object *object;
	git3_index *index;
	git3_tree *tree;
	git3_oid oid;
	char *buf;

	if (!cl_is_env_set("GITTEST_INVASIVE_FS_SIZE"))
		cl_skip();

	cl_assert(buf = git3__calloc(1, BIGFILE_SIZE));

	memset(&ie, 0, sizeof(ie));
	ie.mode = GIT3_FILEMODE_BLOB;
	ie.path = BIGFILE;

	cl_git_pass(git3_repository_index(&index, g_repo));
	cl_git_pass(git3_index_add_from_buffer(index, &ie, buf, BIGFILE_SIZE));
	cl_repo_commit_from_index(&oid, g_repo, NULL, 0, BIGFILE);

	cl_git_pass(git3_commit_lookup(&commit, g_repo, &oid));
	cl_git_pass(git3_commit_tree(&tree, commit));
	cl_assert(entry = git3_tree_entry_byname(tree, BIGFILE));
	cl_git_pass(git3_tree_entry_to_object(&object, g_repo, entry));

	git3_object_free(object);
	git3_tree_free(tree);
	git3_index_free(index);
	git3_commit_free(commit);
	git3__free(buf);
}
