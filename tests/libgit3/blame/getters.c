#include "clar_libgit3.h"

#include "blame.h"

git3_blame *g_blame;

void test_blame_getters__initialize(void)
{
	size_t i;
	git3_blame_options opts = GIT3_BLAME_OPTIONS_INIT;

	git3_blame_hunk hunks[] = {
		{ 3, GIT3_OID_SHA1_ZERO,  1, NULL, NULL, GIT3_OID_SHA1_ZERO, "a", 0},
		{ 3, GIT3_OID_SHA1_ZERO,  4, NULL, NULL, GIT3_OID_SHA1_ZERO, "b", 0},
		{ 3, GIT3_OID_SHA1_ZERO,  7, NULL, NULL, GIT3_OID_SHA1_ZERO, "c", 0},
		{ 3, GIT3_OID_SHA1_ZERO, 10, NULL, NULL, GIT3_OID_SHA1_ZERO, "d", 0},
		{ 3, GIT3_OID_SHA1_ZERO, 13, NULL, NULL, GIT3_OID_SHA1_ZERO, "e", 0},
	};

	g_blame = git3_blame__alloc(NULL, opts, "");

	for (i=0; i<5; i++) {
		git3_blame_hunk *h = git3__calloc(1, sizeof(git3_blame_hunk));
		h->final_start_line_number = hunks[i].final_start_line_number;
		h->orig_path = git3__strdup(hunks[i].orig_path);
		h->lines_in_hunk = hunks[i].lines_in_hunk;

		git3_vector_insert(&g_blame->hunks, h);
	}
}

void test_blame_getters__cleanup(void)
{
	git3_blame_free(g_blame);
}


void test_blame_getters__byindex(void)
{
	const git3_blame_hunk *h = git3_blame_hunk_byindex(g_blame, 2);
	cl_assert(h);
	cl_assert_equal_s(h->orig_path, "c");

	h = git3_blame_hunk_byindex(g_blame, 95);
	cl_assert_equal_p(h, NULL);
}

void test_blame_getters__byline(void)
{
	const git3_blame_hunk *h = git3_blame_hunk_byline(g_blame, 5);
	cl_assert(h);
	cl_assert_equal_s(h->orig_path, "b");

	h = git3_blame_hunk_byline(g_blame, 95);
	cl_assert_equal_p(h, NULL);
}
