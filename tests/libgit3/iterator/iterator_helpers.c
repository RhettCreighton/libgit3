#include "clar_libgit3.h"
#include "iterator.h"
#include "repository.h"
#include "futils.h"
#include "iterator_helpers.h"
#include <stdarg.h>

static void assert_at_end(git3_iterator *i, bool verbose)
{
	const git3_index_entry *end;
	int error = git3_iterator_advance(&end, i);

	if (verbose && error != GIT3_ITEROVER)
		fprintf(stderr, "Expected end of iterator, got '%s'\n", end->path);

	cl_git_fail_with(GIT3_ITEROVER, error);
}

void expect_iterator_items(
	git3_iterator *i,
	size_t expected_flat,
	const char **expected_flat_paths,
	size_t expected_total,
	const char **expected_total_paths)
{
	const git3_index_entry *entry;
	size_t count;
	int no_trees = !(git3_iterator_flags(i) & GIT3_ITERATOR_INCLUDE_TREES);
	bool v = false;
	int error;

	if (v) fprintf(stderr, "== %s ==\n", no_trees ? "notrees" : "trees");

	count = 0;

	while (!git3_iterator_advance(&entry, i)) {
		if (v) fprintf(stderr, "  %s %07o\n", entry->path, (int)entry->mode);

		if (no_trees)
			cl_assert(entry->mode != GIT3_FILEMODE_TREE);

		if (expected_flat_paths) {
			const char *expect_path = expected_flat_paths[count];
			size_t expect_len = strlen(expect_path);

			cl_assert_equal_s(expect_path, entry->path);

			if (expect_path[expect_len - 1] == '/')
				cl_assert_equal_i(GIT3_FILEMODE_TREE, entry->mode);
			else
				cl_assert(entry->mode != GIT3_FILEMODE_TREE);
		}

		cl_assert(++count <= expected_flat);
	}

	assert_at_end(i, v);
	cl_assert_equal_i(expected_flat, count);

	cl_git_pass(git3_iterator_reset(i));

	count = 0;
	cl_git_pass(git3_iterator_current(&entry, i));

	if (v) fprintf(stderr, "-- %s --\n", no_trees ? "notrees" : "trees");

	while (entry != NULL) {
		if (v) fprintf(stderr, "  %s %07o\n", entry->path, (int)entry->mode);

		if (no_trees)
			cl_assert(entry->mode != GIT3_FILEMODE_TREE);

		if (expected_total_paths) {
			const char *expect_path = expected_total_paths[count];
			size_t expect_len = strlen(expect_path);

			cl_assert_equal_s(expect_path, entry->path);

			if (expect_path[expect_len - 1] == '/')
				cl_assert_equal_i(GIT3_FILEMODE_TREE, entry->mode);
			else
				cl_assert(entry->mode != GIT3_FILEMODE_TREE);
		}

		if (entry->mode == GIT3_FILEMODE_TREE) {
			error = git3_iterator_advance_into(&entry, i);

			/* could return NOTFOUND if directory is empty */
			cl_assert(!error || error == GIT3_ENOTFOUND);

			if (error == GIT3_ENOTFOUND) {
				error = git3_iterator_advance(&entry, i);
				cl_assert(!error || error == GIT3_ITEROVER);
			}
		} else {
			error = git3_iterator_advance(&entry, i);
			cl_assert(!error || error == GIT3_ITEROVER);
		}

		if (++count >= expected_total)
			break;
	}

	assert_at_end(i, v);
	cl_assert_equal_i(expected_total, count);
}


void expect_advance_over(
	git3_iterator *i,
	const char *expected_path,
	git3_iterator_status_t expected_status)
{
	const git3_index_entry *entry;
	git3_iterator_status_t status;
	int error;

	cl_git_pass(git3_iterator_current(&entry, i));
	cl_assert_equal_s(expected_path, entry->path);

	error = git3_iterator_advance_over(&entry, &status, i);
	cl_assert(!error || error == GIT3_ITEROVER);
	cl_assert_equal_i(expected_status, status);
}

void expect_advance_into(
	git3_iterator *i,
	const char *expected_path)
{
	const git3_index_entry *entry;
	int error;

	cl_git_pass(git3_iterator_current(&entry, i));
	cl_assert_equal_s(expected_path, entry->path);

	if (S_ISDIR(entry->mode))
		error = git3_iterator_advance_into(&entry, i);
	else
		error = git3_iterator_advance(&entry, i);

	cl_assert(!error || error == GIT3_ITEROVER);
}

