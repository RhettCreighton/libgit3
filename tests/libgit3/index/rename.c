#include "clar_libgit3.h"
#include "posix.h"

void test_index_rename__single_file(void)
{
	git3_repository *repo;
	git3_index *index;
	size_t position;
	git3_oid expected;
	const git3_index_entry *entry;

	p_mkdir("rename", 0700);

	cl_git_pass(git3_repository_init(&repo, "./rename", 0));
	cl_git_pass(git3_repository_index(&index, repo));

	cl_assert(git3_index_entrycount(index) == 0);

	cl_git_mkfile("./rename/lame.name.txt", "new_file\n");

	/* This should add a new blob to the object database in 'd4/fa8600b4f37d7516bef4816ae2c64dbf029e3a' */
	cl_git_pass(git3_index_add_bypath(index, "lame.name.txt"));
	cl_assert(git3_index_entrycount(index) == 1);

	cl_git_pass(git3_oid_from_string(&expected, "d4fa8600b4f37d7516bef4816ae2c64dbf029e3a", GIT3_OID_SHA1));

	cl_assert(!git3_index_find(&position, index, "lame.name.txt"));

	entry = git3_index_get_byindex(index, position);
	cl_assert_equal_oid(&expected, &entry->id);

	/* This removes the entry from the index, but not from the object database */
	cl_git_pass(git3_index_remove(index, "lame.name.txt", 0));
	cl_assert(git3_index_entrycount(index) == 0);

	p_rename("./rename/lame.name.txt", "./rename/fancy.name.txt");

	cl_git_pass(git3_index_add_bypath(index, "fancy.name.txt"));
	cl_assert(git3_index_entrycount(index) == 1);

	cl_assert(!git3_index_find(&position, index, "fancy.name.txt"));

	entry = git3_index_get_byindex(index, position);
	cl_assert_equal_oid(&expected, &entry->id);

	git3_index_free(index);
	git3_repository_free(repo);

	cl_fixture_cleanup("rename");
}

void test_index_rename__casechanging(void)
{
	git3_repository *repo;
	git3_index *index;
	const git3_index_entry *entry;
	git3_index_entry new = {{0}};

	p_mkdir("rename", 0700);

	cl_git_pass(git3_repository_init(&repo, "./rename", 0));
	cl_git_pass(git3_repository_index(&index, repo));

	cl_git_mkfile("./rename/lame.name.txt", "new_file\n");

	cl_git_pass(git3_index_add_bypath(index, "lame.name.txt"));
	cl_assert_equal_i(1, git3_index_entrycount(index));
	cl_assert((entry = git3_index_get_bypath(index, "lame.name.txt", 0)));

	memcpy(&new, entry, sizeof(git3_index_entry));
	new.path = "LAME.name.TXT";

	cl_git_pass(git3_index_add(index, &new));
	cl_assert((entry = git3_index_get_bypath(index, "LAME.name.TXT", 0)));

	if (cl_repo_get_bool(repo, "core.ignorecase"))
		cl_assert_equal_i(1, git3_index_entrycount(index));
	else
		cl_assert_equal_i(2, git3_index_entrycount(index));

	git3_index_free(index);
	git3_repository_free(repo);

	cl_fixture_cleanup("rename");
}

