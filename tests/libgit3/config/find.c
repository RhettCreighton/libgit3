#include "clar_libgit3.h"

void test_config_find__one(void)
{
	git3_buf buf = GIT3_BUF_INIT;

	cl_git_fail_with(GIT3_ENOTFOUND, git3_config_find_global(&buf));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_config_find_xdg(&buf));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_config_find_system(&buf));
	cl_git_fail_with(GIT3_ENOTFOUND, git3_config_find_programdata(&buf));
}
