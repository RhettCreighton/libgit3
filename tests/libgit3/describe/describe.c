#include "clar_libgit3.h"
#include "describe_helpers.h"

void test_describe_describe__can_describe_against_a_bare_repo(void)
{
	git3_repository *repo;
	git3_describe_options opts = GIT3_DESCRIBE_OPTIONS_INIT;
	git3_describe_format_options fmt_opts = GIT3_DESCRIBE_FORMAT_OPTIONS_INIT;

	cl_git_pass(git3_repository_open(&repo, cl_fixture("testrepo.git")));

	assert_describe("hard_tag", "HEAD", repo, &opts, &fmt_opts);

	opts.show_commit_oid_as_fallback = 1;

	assert_describe("be3563a*", "HEAD^", repo, &opts, &fmt_opts);

	git3_repository_free(repo);
}

static int delete_cb(git3_reference *ref, void *payload)
{
	GIT3_UNUSED(payload);

	cl_git_pass(git3_reference_delete(ref));
	git3_reference_free(ref);

	return 0;
}

void test_describe_describe__describe_a_repo_with_no_refs(void)
{
	git3_repository *repo;
	git3_describe_options opts = GIT3_DESCRIBE_OPTIONS_INIT;
	git3_str buf = GIT3_STR_INIT;
	git3_object *object;
	git3_describe_result *result = NULL;

	repo = cl_git_sandbox_init("testrepo.git");
	cl_git_pass(git3_revparse_single(&object, repo, "HEAD"));

	cl_git_pass(git3_reference_foreach(repo, delete_cb, NULL));

	/* Impossible to describe without falling back to OIDs */
	cl_git_fail(git3_describe_commit(&result, object, &opts));

	/* Try again with OID fallbacks */
	opts.show_commit_oid_as_fallback = 1;
	cl_git_pass(git3_describe_commit(&result, object, &opts));

	git3_describe_result_free(result);
	git3_object_free(object);
	git3_str_dispose(&buf);
	cl_git_sandbox_cleanup();
}
