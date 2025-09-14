#include "clar_libgit3.h"
#include "index.h"

void test_index_inmemory__can_create_an_inmemory_index(void)
{
	git3_index *index;

	cl_git_pass(git3_index_new(&index));
	cl_assert_equal_i(0, (int)git3_index_entrycount(index));

	git3_index_free(index);
}

void test_index_inmemory__cannot_add_bypath_to_an_inmemory_index(void)
{
	git3_index *index;

	cl_git_pass(git3_index_new_ext(&index, NULL));

	cl_assert_equal_i(GIT3_ERROR, git3_index_add_bypath(index, "test.txt"));

	git3_index_free(index);
}
