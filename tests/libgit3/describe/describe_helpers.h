#include "clar_libgit3.h"

extern void assert_describe(
	const char *expected_output,
	const char *revparse_spec,
	git3_repository *repo,
	git3_describe_options *opts,
	git3_describe_format_options *fmt_opts);

extern void assert_describe_workdir(
	const char *expected_output,
	git3_repository *repo,
	git3_describe_options *opts,
	git3_describe_format_options *fmt_opts);
