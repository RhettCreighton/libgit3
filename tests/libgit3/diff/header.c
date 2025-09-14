#include "clar_libgit3.h"
#include "git3/sys/repository.h"

#include "diff_helpers.h"
#include "diff.h"
#include "repository.h"

static git3_repository *g_repo = NULL;

void test_diff_header__initialize(void)
{
}

void test_diff_header__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

#define EXPECTED_HEADER "diff --git a/subdir.txt b/subdir.txt\n"	\
	"deleted file mode 100644\n"					\
	"index e8ee89e..0000000\n"					\
	"--- a/subdir.txt\n"						\
	"+++ /dev/null\n"

static int check_header_cb(
	const git3_diff_delta *delta,
	const git3_diff_hunk *hunk,
	const git3_diff_line *line,
	void *payload)
{
	int *counter = (int *) payload;

	GIT3_UNUSED(delta);

	switch (line->origin) {
	case GIT3_DIFF_LINE_FILE_HDR:
		cl_assert(hunk == NULL);
		(*counter)++;
		break;
	default:
		/* unexpected code path */
		return -1;
	}

	return 0;
}

void test_diff_header__can_print_just_headers(void)
{
	const char *one_sha = "26a125e";
	git3_tree *one;
	git3_diff *diff;
	int counter = 0;

	g_repo = cl_git_sandbox_init("status");

	one = resolve_commit_oid_to_tree(g_repo, one_sha);

	cl_git_pass(git3_diff_tree_to_index(&diff, g_repo, one, NULL, NULL));

	cl_git_pass(git3_diff_print(
			    diff, GIT3_DIFF_FORMAT_PATCH_HEADER, check_header_cb, &counter));

	cl_assert_equal_i(8, counter);

	git3_diff_free(diff);

	git3_tree_free(one);
}
