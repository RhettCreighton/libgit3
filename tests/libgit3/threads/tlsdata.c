#include "clar_libgit3.h"

#include "thread_helpers.h"

void test_threads_tlsdata__can_set_and_get(void)
{
	git3_tlsdata_key key_one, key_two, key_three;

	cl_git_pass(git3_tlsdata_init(&key_one, NULL));
	cl_git_pass(git3_tlsdata_init(&key_two, NULL));
	cl_git_pass(git3_tlsdata_init(&key_three, NULL));

	cl_git_pass(git3_tlsdata_set(key_one, (void *)(size_t)42424242));
	cl_git_pass(git3_tlsdata_set(key_two, (void *)(size_t)0xdeadbeef));
	cl_git_pass(git3_tlsdata_set(key_three, (void *)(size_t)98761234));

	cl_assert_equal_sz((size_t)42424242, git3_tlsdata_get(key_one));
	cl_assert_equal_sz((size_t)0xdeadbeef, git3_tlsdata_get(key_two));
	cl_assert_equal_sz((size_t)98761234, git3_tlsdata_get(key_three));

	cl_git_pass(git3_tlsdata_dispose(key_one));
	cl_git_pass(git3_tlsdata_dispose(key_two));
	cl_git_pass(git3_tlsdata_dispose(key_three));
}

#ifdef GIT3_THREADS

static void *set_and_get(void *param)
{
	git3_tlsdata_key *tlsdata_key = (git3_tlsdata_key *)param;
	int val;

	if (git3_tlsdata_set(*tlsdata_key, &val) != 0 ||
	    git3_tlsdata_get(*tlsdata_key) != &val)
		return (void *)0;

	return (void *)1;
}

#endif

#define THREAD_COUNT 10

void test_threads_tlsdata__threads(void)
{
#ifdef GIT3_THREADS
	git3_thread thread[THREAD_COUNT];
	git3_tlsdata_key tlsdata;
	int i;

	cl_git_pass(git3_tlsdata_init(&tlsdata, NULL));

	for (i = 0; i < THREAD_COUNT; i++)
		cl_git_pass(git3_thread_create(&thread[i], set_and_get, &tlsdata));

	for (i = 0; i < THREAD_COUNT; i++) {
		void *result;

		cl_git_pass(git3_thread_join(&thread[i], &result));
		cl_assert_equal_sz(1, (size_t)result);
	}

	cl_git_pass(git3_tlsdata_dispose(tlsdata));
#endif
}
