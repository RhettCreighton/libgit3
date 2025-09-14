#include "clar_libgit3.h"
#include "git3/sys/config.h"

void test_config_backend__checks_version(void)
{
	git3_config *cfg;
	git3_config_backend backend = GIT3_CONFIG_BACKEND_INIT;
	const git3_error *err;

	backend.version = 1024;

	cl_git_pass(git3_config_new(&cfg));
	cl_git_fail(git3_config_add_backend(cfg, &backend, 0, NULL, false));
	err = git3_error_last();
	cl_assert_equal_i(GIT3_ERROR_INVALID, err->klass);

	git3_error_clear();
	backend.version = 1024;
	cl_git_fail(git3_config_add_backend(cfg, &backend, 0, NULL, false));
	err = git3_error_last();
	cl_assert_equal_i(GIT3_ERROR_INVALID, err->klass);

	git3_config_free(cfg);
}
