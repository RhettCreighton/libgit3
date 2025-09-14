#include "clar_libgit3.h"
#include "buf.h"

void test_core_buf__sanitize(void)
{
	git3_buf buf = { (char *)0x42, 0, 16 };

	cl_git_pass(git3_buf_sanitize(&buf));
	cl_assert_equal_s(buf.ptr, "");
	cl_assert_equal_i(buf.reserved, 0);
	cl_assert_equal_i(buf.size, 0);

	git3_buf_dispose(&buf);
}

void test_core_buf__tostr(void)
{
	git3_str str = GIT3_STR_INIT;
	git3_buf buf = { (char *)0x42, 0, 16 };

	cl_git_pass(git3_buf_tostr(&str, &buf));

	cl_assert_equal_s(buf.ptr, "");
	cl_assert_equal_i(buf.reserved, 0);
	cl_assert_equal_i(buf.size, 0);

	cl_assert_equal_s(str.ptr, "");
	cl_assert_equal_i(str.asize, 0);
	cl_assert_equal_i(str.size, 0);

	git3_buf_dispose(&buf);
	git3_str_dispose(&str);
}

void test_core_buf__fromstr(void)
{
	git3_str str = GIT3_STR_INIT;
	git3_buf buf = { (char *)0x42, 0, 16 };

	cl_git_pass(git3_buf_tostr(&str, &buf));
	cl_git_pass(git3_str_puts(&str, "Hello, world."));
	cl_git_pass(git3_buf_fromstr(&buf, &str));

	cl_assert(buf.reserved > 14);
	cl_assert_equal_i(buf.size, 13);
	cl_assert_equal_s(buf.ptr, "Hello, world.");

	cl_assert_equal_s(str.ptr, "");
	cl_assert_equal_i(str.asize, 0);
	cl_assert_equal_i(str.size, 0);

	git3_buf_dispose(&buf);
	git3_str_dispose(&str);
}
