#include "clar_libgit3.h"

#include "userdiff.h"

static git3_regexp regex;

void test_diff_userdiff__cleanup(void)
{
	git3_regexp_dispose(&regex);
}

void test_diff_userdiff__compile_userdiff_regexps(void)
{
	size_t idx;

	for (idx = 0; idx < ARRAY_SIZE(builtin_defs); ++idx) {
		git3_diff_driver_definition ddef = builtin_defs[idx];

		cl_git_pass(git3_regexp_compile(&regex, ddef.fns, ddef.flags));
		git3_regexp_dispose(&regex);

		cl_git_pass(git3_regexp_compile(&regex, ddef.words, 0));
		git3_regexp_dispose(&regex);
	}
}
