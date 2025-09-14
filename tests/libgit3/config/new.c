#include "clar_libgit3.h"

#include "filebuf.h"
#include "futils.h"
#include "posix.h"

#define TEST_CONFIG "git-new-config"

void test_config_new__write_new_config(void)
{
	git3_config *config;
	git3_buf buf = GIT3_BUF_INIT;

	cl_git_mkfile(TEST_CONFIG, "");
	cl_git_pass(git3_config_open_ondisk(&config, TEST_CONFIG));

	cl_git_pass(git3_config_set_string(config, "color.ui", "auto"));
	cl_git_pass(git3_config_set_string(config, "core.editor", "ed"));

	git3_config_free(config);

	cl_git_pass(git3_config_open_ondisk(&config, TEST_CONFIG));

	cl_git_pass(git3_config_get_string_buf(&buf, config, "color.ui"));
	cl_assert_equal_s("auto", buf.ptr);
	git3_buf_dispose(&buf);
	cl_git_pass(git3_config_get_string_buf(&buf, config, "core.editor"));
	cl_assert_equal_s("ed", buf.ptr);

	git3_buf_dispose(&buf);
	git3_config_free(config);

	cl_must_pass(p_unlink(TEST_CONFIG));
}
