#include "describe_helpers.h"

#include "wildmatch.h"

void assert_describe(
	const char *expected_output,
	const char *revparse_spec,
	git3_repository *repo,
	git3_describe_options *opts,
	git3_describe_format_options *fmt_opts)
{
	git3_object *object;
	git3_buf label = GIT3_BUF_INIT;
	git3_describe_result *result;

	cl_git_pass(git3_revparse_single(&object, repo, revparse_spec));

	cl_git_pass(git3_describe_commit(&result, object, opts));
	cl_git_pass(git3_describe_format(&label, result, fmt_opts));

	cl_must_pass(wildmatch(expected_output, label.ptr, 0));

	git3_describe_result_free(result);
	git3_object_free(object);
	git3_buf_dispose(&label);
}

void assert_describe_workdir(
	const char *expected_output,
	git3_repository *repo,
	git3_describe_options *opts,
	git3_describe_format_options *fmt_opts)
{
	git3_buf label = GIT3_BUF_INIT;
	git3_describe_result *result;

	cl_git_pass(git3_describe_workdir(&result, repo, opts));
	cl_git_pass(git3_describe_format(&label, result, fmt_opts));

	cl_must_pass(wildmatch(expected_output, label.ptr, 0));

	git3_describe_result_free(result);
	git3_buf_dispose(&label);
}
