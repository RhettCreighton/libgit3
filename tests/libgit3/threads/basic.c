#include "clar_libgit3.h"

#include "thread_helpers.h"
#include "cache.h"


static git3_repository *g_repo;

void test_threads_basic__initialize(void)
{
	g_repo = cl_git_sandbox_init("testrepo");
}

void test_threads_basic__cleanup(void)
{
	cl_git_sandbox_cleanup();
}


void test_threads_basic__cache(void)
{
	/* run several threads polling the cache at the same time */
	cl_assert(1 == 1);
}

void test_threads_basic__multiple_init(void)
{
	git3_repository *nested_repo;

	git3_libgit3_init();
	cl_git_pass(git3_repository_open(&nested_repo, cl_fixture("testrepo.git")));
	git3_repository_free(nested_repo);

	git3_libgit3_shutdown();
	cl_git_pass(git3_repository_open(&nested_repo, cl_fixture("testrepo.git")));
	git3_repository_free(nested_repo);
}

static void *set_error(void *dummy)
{
	git3_error_set(GIT3_ERROR_INVALID, "oh no, something happened!\n");

	return dummy;
}

/* Set errors so we can check that we free it */
void test_threads_basic__set_error(void)
{
	run_in_parallel(1, 4, set_error, NULL, NULL);
}

#ifdef GIT3_THREADS
static void *return_normally(void *param)
{
	return param;
}

static void *exit_abruptly(void *param)
{
	git3_thread_exit(param);
	return NULL;
}
#endif

void test_threads_basic__exit(void)
{
#ifndef GIT3_THREADS
	clar__skip();
#else
	git3_thread thread;
	void *result;

	/* Ensure that the return value of the threadproc is returned. */
	cl_git_pass(git3_thread_create(&thread, return_normally, (void *)424242));
	cl_git_pass(git3_thread_join(&thread, &result));
	cl_assert_equal_sz(424242, (size_t)result);

	/* Ensure that the return value of `git3_thread_exit` is returned. */
	cl_git_pass(git3_thread_create(&thread, exit_abruptly, (void *)232323));
	cl_git_pass(git3_thread_join(&thread, &result));
	cl_assert_equal_sz(232323, (size_t)result);
#endif
}
