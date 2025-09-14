#include "clar_libgit3.h"
#include "thread_helpers.h"

void run_in_parallel(
	int repeats,
	int threads,
	void *(*func)(void *),
	void (*before_test)(void),
	void (*after_test)(void))
{
	int r, t, *id = git3__calloc(threads, sizeof(int));
#ifdef GIT3_THREADS
	git3_thread *th = git3__calloc(threads, sizeof(git3_thread));
	cl_assert(th != NULL);
#else
	void *th = NULL;
#endif

	cl_assert(id != NULL);

	for (r = 0; r < repeats; ++r) {
		if (before_test) before_test();

		for (t = 0; t < threads; ++t) {
			id[t] = t;
#ifdef GIT3_THREADS
			cl_git_pass(git3_thread_create(&th[t], func, &id[t]));
#else
			cl_assert(func(&id[t]) == &id[t]);
#endif
		}

#ifdef GIT3_THREADS
		for (t = 0; t < threads; ++t)
			cl_git_pass(git3_thread_join(&th[t], NULL));
		memset(th, 0, threads * sizeof(git3_thread));
#endif

		if (after_test) after_test();
	}

	git3__free(id);
	git3__free(th);
}
