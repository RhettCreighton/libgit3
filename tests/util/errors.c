#include "clar_libgit3.h"

void test_errors__public_api(void)
{
	char *str_in_error;

	git3_error_clear();

	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp(git3_error_last()->message, "no error") == 0);

	git3_error_set_oom();

	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NOMEMORY);
	str_in_error = strstr(git3_error_last()->message, "memory");
	cl_assert(str_in_error != NULL);

	git3_error_clear();

	git3_error_set_str(GIT3_ERROR_REPOSITORY, "This is a test");

	cl_assert(git3_error_last() != NULL);
	str_in_error = strstr(git3_error_last()->message, "This is a test");
	cl_assert(str_in_error != NULL);

	git3_error_clear();
	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp(git3_error_last()->message, "no error") == 0);
}

#include "common.h"
#include "util.h"
#include "posix.h"

void test_errors__new_school(void)
{
	char *str_in_error;

	git3_error_clear();
	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp(git3_error_last()->message, "no error") == 0);

	git3_error_set_oom(); /* internal fn */

	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NOMEMORY);
	str_in_error = strstr(git3_error_last()->message, "memory");
	cl_assert(str_in_error != NULL);

	git3_error_clear();

	git3_error_set(GIT3_ERROR_REPOSITORY, "This is a test"); /* internal fn */

	cl_assert(git3_error_last() != NULL);
	str_in_error = strstr(git3_error_last()->message, "This is a test");
	cl_assert(str_in_error != NULL);

	git3_error_clear();
	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp(git3_error_last()->message, "no error") == 0);

	do {
		struct stat st;
		memset(&st, 0, sizeof(st));
		cl_assert(p_lstat("this_file_does_not_exist", &st) < 0);
		GIT3_UNUSED(st);
	} while (false);
	git3_error_set(GIT3_ERROR_OS, "stat failed"); /* internal fn */

	cl_assert(git3_error_last() != NULL);
	str_in_error = strstr(git3_error_last()->message, "stat failed");
	cl_assert(str_in_error != NULL);
	cl_assert(git3__prefixcmp(str_in_error, "stat failed: ") == 0);
	cl_assert(strlen(str_in_error) > strlen("stat failed: "));

#ifdef GIT3_WIN32
	git3_error_clear();

	/* The MSDN docs use this to generate a sample error */
	cl_assert(GetProcessId(NULL) == 0);
	git3_error_set(GIT3_ERROR_OS, "GetProcessId failed"); /* internal fn */

	cl_assert(git3_error_last() != NULL);
	str_in_error = strstr(git3_error_last()->message, "GetProcessId failed");
	cl_assert(str_in_error != NULL);
	cl_assert(git3__prefixcmp(str_in_error, "GetProcessId failed: ") == 0);
	cl_assert(strlen(str_in_error) > strlen("GetProcessId failed: "));
#endif

	git3_error_clear();
}

void test_errors__restore(void)
{
	git3_error *last_error;

	git3_error_clear();
	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp("no error", git3_error_last()->message) == 0);

	git3_error_set(42, "Foo: %s", "bar");
	cl_assert(git3_error_save(&last_error) == 0);

	git3_error_clear();
	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp("no error", git3_error_last()->message) == 0);

	git3_error_set(99, "Bar: %s", "foo");

	git3_error_restore(last_error);

	cl_assert(git3_error_last()->klass == 42);
	cl_assert(strcmp("Foo: bar", git3_error_last()->message) == 0);
}

void test_errors__restore_oom(void)
{
	git3_error *last_error;
	const git3_error *oom_error = NULL;

	git3_error_clear();

	git3_error_set_oom(); /* internal fn */
	oom_error = git3_error_last();
	cl_assert(oom_error);
	cl_assert(oom_error->klass == GIT3_ERROR_NOMEMORY);

	cl_assert(git3_error_save(&last_error) == 0);
	cl_assert(last_error->klass == GIT3_ERROR_NOMEMORY);
	cl_assert(strcmp("Out of memory", last_error->message) == 0);

	git3_error_clear();
	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp("no error", git3_error_last()->message) == 0);

	git3_error_restore(last_error);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NOMEMORY);
	cl_assert_(git3_error_last() == oom_error, "static oom error not restored");

	git3_error_clear();
}

static int test_arraysize_multiply(size_t nelem, size_t size)
{
	size_t out;
	GIT3_ERROR_CHECK_ALLOC_MULTIPLY(&out, nelem, size);
	return 0;
}

void test_errors__integer_overflow_alloc_multiply(void)
{
	cl_git_pass(test_arraysize_multiply(10, 10));
	cl_git_pass(test_arraysize_multiply(1000, 1000));
	cl_git_pass(test_arraysize_multiply(SIZE_MAX/sizeof(void *), sizeof(void *)));
	cl_git_pass(test_arraysize_multiply(0, 10));
	cl_git_pass(test_arraysize_multiply(10, 0));

	cl_git_fail(test_arraysize_multiply(SIZE_MAX-1, sizeof(void *)));
	cl_git_fail(test_arraysize_multiply((SIZE_MAX/sizeof(void *))+1, sizeof(void *)));

	cl_assert_equal_i(GIT3_ERROR_NOMEMORY, git3_error_last()->klass);
	cl_assert_equal_s("Out of memory", git3_error_last()->message);
}

static int test_arraysize_add(size_t one, size_t two)
{
	size_t out;
	GIT3_ERROR_CHECK_ALLOC_ADD(&out, one, two);
	return 0;
}

void test_errors__integer_overflow_alloc_add(void)
{
	cl_git_pass(test_arraysize_add(10, 10));
	cl_git_pass(test_arraysize_add(1000, 1000));
	cl_git_pass(test_arraysize_add(SIZE_MAX-10, 10));

	cl_git_fail(test_arraysize_multiply(SIZE_MAX-1, 2));
	cl_git_fail(test_arraysize_multiply(SIZE_MAX, SIZE_MAX));

	cl_assert_equal_i(GIT3_ERROR_NOMEMORY, git3_error_last()->klass);
	cl_assert_equal_s("Out of memory", git3_error_last()->message);
}

void test_errors__integer_overflow_sets_oom(void)
{
	size_t out;

	git3_error_clear();
	cl_assert(!GIT3_ADD_SIZET_OVERFLOW(&out, SIZE_MAX-1, 1));
	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp(git3_error_last()->message, "no error") == 0);

	git3_error_clear();
	cl_assert(!GIT3_ADD_SIZET_OVERFLOW(&out, 42, 69));
	cl_assert(git3_error_last() != NULL);
	cl_assert(git3_error_last()->klass == GIT3_ERROR_NONE);
	cl_assert(strcmp(git3_error_last()->message, "no error") == 0);

	git3_error_clear();
	cl_assert(GIT3_ADD_SIZET_OVERFLOW(&out, SIZE_MAX, SIZE_MAX));
	cl_assert_equal_i(GIT3_ERROR_NOMEMORY, git3_error_last()->klass);
	cl_assert_equal_s("Out of memory", git3_error_last()->message);

	git3_error_clear();
	cl_assert(GIT3_ADD_SIZET_OVERFLOW(&out, SIZE_MAX, SIZE_MAX));
	cl_assert_equal_i(GIT3_ERROR_NOMEMORY, git3_error_last()->klass);
	cl_assert_equal_s("Out of memory", git3_error_last()->message);
}
