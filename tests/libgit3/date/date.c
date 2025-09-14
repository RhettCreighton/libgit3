#include "clar_libgit3.h"

#include "date.h"

void test_date_date__overflow(void)
{
#ifdef __LP64__
   git3_time_t d2038, d2039;

   /* This is expected to fail on a 32-bit machine. */
   cl_git_pass(git3_date_parse(&d2038, "2038-1-1"));
   cl_git_pass(git3_date_parse(&d2039, "2039-1-1"));
   cl_assert(d2038 < d2039);
#endif
}

void test_date_date__invalid_date(void)
{
   git3_time_t d;
   cl_git_fail(git3_date_parse(&d, ""));
   cl_git_fail(git3_date_parse(&d, "NEITHER_INTEGER_NOR_DATETIME"));
}

void test_date_date__offset(void)
{
	git3_time_t d;
	int offset;
	cl_git_pass(git3_date_offset_parse(&d, &offset, "1970-1-1 01:00:00+03"));
	cl_assert_equal_i(offset, 3*60);
}
