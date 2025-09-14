#include "clar_libgit3.h"
#include "thread_helpers.h"
#include "iterator.h"

static git3_repository *_repo;

void test_threads_iterator__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

static void *run_workdir_iterator(void *arg)
{
	int error = 0;
	git3_repository *repo;
	git3_iterator *iter;
	git3_iterator_options iter_opts = GIT3_ITERATOR_OPTIONS_INIT;
	const git3_index_entry *entry = NULL;

	iter_opts.flags = GIT3_ITERATOR_DONT_AUTOEXPAND;

	cl_git_pass(git3_repository_open(&repo, git3_repository_path(_repo)));
	cl_git_pass(git3_iterator_for_workdir(
		&iter, repo, NULL, NULL, &iter_opts));

	while (!error) {
		if (entry && entry->mode == GIT3_FILEMODE_TREE) {
			error = git3_iterator_advance_into(&entry, iter);

			if (error == GIT3_ENOTFOUND)
				error = git3_iterator_advance(&entry, iter);
		} else {
			error = git3_iterator_advance(&entry, iter);
		}

		if (!error)
			(void)git3_iterator_current_is_ignored(iter);
	}

	cl_assert_equal_i(GIT3_ITEROVER, error);

	git3_iterator_free(iter);
	git3_repository_free(repo);
	git3_error_clear();
	return arg;
}


void test_threads_iterator__workdir(void)
{
	_repo = cl_git_sandbox_init("status");

	run_in_parallel(
		1, 20, run_workdir_iterator, NULL, NULL);
}
