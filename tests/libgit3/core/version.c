#include "clar_libgit3.h"

void test_core_version__query(void)
{
	int major, minor, rev;

	git3_libgit3_version(&major, &minor, &rev);
	cl_assert_equal_i(LIBGIT3_VERSION_MAJOR, major);
	cl_assert_equal_i(LIBGIT3_VERSION_MINOR, minor);
	cl_assert_equal_i(LIBGIT3_VERSION_REVISION, rev);
}

void test_core_version__check(void)
{
#if !LIBGIT3_VERSION_CHECK(1,6,3)
	cl_fail("version check");
#endif

#if LIBGIT3_VERSION_CHECK(99,99,99)
	cl_fail("version check");
#endif
}
