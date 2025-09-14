#include "clar_libgit3.h"
#include "clar_libgit3_alloc.h"
#include "alloc.h"

void test_alloc__cleanup(void)
{
	cl_alloc_reset();
}

void test_alloc__oom(void)
{
	void *ptr = NULL;

	cl_alloc_limit(0);

	cl_assert(git3__malloc(1) == NULL);
	cl_assert(git3__calloc(1, 1) == NULL);
	cl_assert(git3__realloc(ptr, 1) == NULL);
	cl_assert(git3__strdup("test") == NULL);
	cl_assert(git3__strndup("test", 4) == NULL);
}

void test_alloc__single_byte_is_exhausted(void)
{
	void *ptr;

	cl_alloc_limit(1);

	cl_assert(ptr = git3__malloc(1));
	cl_assert(git3__malloc(1) == NULL);
	git3__free(ptr);
}

void test_alloc__free_replenishes_byte(void)
{
	void *ptr;

	cl_alloc_limit(1);

	cl_assert(ptr = git3__malloc(1));
	cl_assert(git3__malloc(1) == NULL);
	git3__free(ptr);
	cl_assert(ptr = git3__malloc(1));
	git3__free(ptr);
}

void test_alloc__realloc(void)
{
	char *ptr = NULL;

	cl_alloc_limit(3);

	cl_assert(ptr = git3__realloc(ptr, 1));
	*ptr = 'x';

	cl_assert(ptr = git3__realloc(ptr, 1));
	cl_assert_equal_i(*ptr, 'x');

	cl_assert(ptr = git3__realloc(ptr, 2));
	cl_assert_equal_i(*ptr, 'x');

	cl_assert(git3__realloc(ptr, 2) == NULL);

	cl_assert(ptr = git3__realloc(ptr, 1));
	cl_assert_equal_i(*ptr, 'x');

	git3__free(ptr);
}
