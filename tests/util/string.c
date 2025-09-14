#include "clar_libgit3.h"

/* compare prefixes */
void test_string__0(void)
{
	cl_assert(git3__prefixcmp("", "") == 0);
	cl_assert(git3__prefixcmp("a", "") == 0);
	cl_assert(git3__prefixcmp("", "a") < 0);
	cl_assert(git3__prefixcmp("a", "b") < 0);
	cl_assert(git3__prefixcmp("b", "a") > 0);
	cl_assert(git3__prefixcmp("ab", "a") == 0);
	cl_assert(git3__prefixcmp("ab", "ac") < 0);
	cl_assert(git3__prefixcmp("ab", "aa") > 0);
}

/* compare suffixes */
void test_string__1(void)
{
	cl_assert(git3__suffixcmp("", "") == 0);
	cl_assert(git3__suffixcmp("a", "") == 0);
	cl_assert(git3__suffixcmp("", "a") < 0);
	cl_assert(git3__suffixcmp("a", "b") < 0);
	cl_assert(git3__suffixcmp("b", "a") > 0);
	cl_assert(git3__suffixcmp("ba", "a") == 0);
	cl_assert(git3__suffixcmp("zaa", "ac") < 0);
	cl_assert(git3__suffixcmp("zaz", "ac") > 0);
}

/* compare icase sorting with case equality */
void test_string__2(void)
{
	cl_assert(git3__strcasesort_cmp("", "") == 0);
	cl_assert(git3__strcasesort_cmp("foo", "foo") == 0);
	cl_assert(git3__strcasesort_cmp("foo", "bar") > 0);
	cl_assert(git3__strcasesort_cmp("bar", "foo") < 0);
	cl_assert(git3__strcasesort_cmp("foo", "FOO") > 0);
	cl_assert(git3__strcasesort_cmp("FOO", "foo") < 0);
	cl_assert(git3__strcasesort_cmp("foo", "BAR") > 0);
	cl_assert(git3__strcasesort_cmp("BAR", "foo") < 0);
	cl_assert(git3__strcasesort_cmp("fooBar", "foobar") < 0);
}

/* compare prefixes with len */
void test_string__prefixncmp(void)
{
	cl_assert(git3__prefixncmp("", 0, "") == 0);
	cl_assert(git3__prefixncmp("a", 1, "") == 0);
	cl_assert(git3__prefixncmp("", 0, "a") < 0);
	cl_assert(git3__prefixncmp("a", 1, "b") < 0);
	cl_assert(git3__prefixncmp("b", 1, "a") > 0);
	cl_assert(git3__prefixncmp("ab", 2, "a") == 0);
	cl_assert(git3__prefixncmp("ab", 1, "a") == 0);
	cl_assert(git3__prefixncmp("ab", 2, "ac") < 0);
	cl_assert(git3__prefixncmp("a", 1, "ac") < 0);
	cl_assert(git3__prefixncmp("ab", 1, "ac") < 0);
	cl_assert(git3__prefixncmp("ab", 2, "aa") > 0);
	cl_assert(git3__prefixncmp("ab", 1, "aa") < 0);
}

/* compare prefixes with len */
void test_string__prefixncmp_icase(void)
{
	cl_assert(git3__prefixncmp_icase("", 0, "") == 0);
	cl_assert(git3__prefixncmp_icase("a", 1, "") == 0);
	cl_assert(git3__prefixncmp_icase("", 0, "a") < 0);
	cl_assert(git3__prefixncmp_icase("a", 1, "b") < 0);
	cl_assert(git3__prefixncmp_icase("A", 1, "b") < 0);
	cl_assert(git3__prefixncmp_icase("a", 1, "B") < 0);
	cl_assert(git3__prefixncmp_icase("b", 1, "a") > 0);
	cl_assert(git3__prefixncmp_icase("B", 1, "a") > 0);
	cl_assert(git3__prefixncmp_icase("b", 1, "A") > 0);
	cl_assert(git3__prefixncmp_icase("ab", 2, "a") == 0);
	cl_assert(git3__prefixncmp_icase("Ab", 2, "a") == 0);
	cl_assert(git3__prefixncmp_icase("ab", 2, "A") == 0);
	cl_assert(git3__prefixncmp_icase("ab", 1, "a") == 0);
	cl_assert(git3__prefixncmp_icase("ab", 2, "ac") < 0);
	cl_assert(git3__prefixncmp_icase("Ab", 2, "ac") < 0);
	cl_assert(git3__prefixncmp_icase("ab", 2, "Ac") < 0);
	cl_assert(git3__prefixncmp_icase("a", 1, "ac") < 0);
	cl_assert(git3__prefixncmp_icase("ab", 1, "ac") < 0);
	cl_assert(git3__prefixncmp_icase("ab", 2, "aa") > 0);
	cl_assert(git3__prefixncmp_icase("ab", 1, "aa") < 0);
}

void test_string__strcmp(void)
{
	cl_assert(git3__strcmp("", "") == 0);
	cl_assert(git3__strcmp("foo", "foo") == 0);
	cl_assert(git3__strcmp("Foo", "foo") < 0);
	cl_assert(git3__strcmp("foo", "FOO") > 0);
	cl_assert(git3__strcmp("foo", "fOO") > 0);

	cl_assert(strcmp("rt\303\202of", "rt dev\302\266h") > 0);
	cl_assert(strcmp("e\342\202\254ghi=", "et") > 0);
	cl_assert(strcmp("rt dev\302\266h", "rt\303\202of") < 0);
	cl_assert(strcmp("et", "e\342\202\254ghi=") < 0);
	cl_assert(strcmp("\303\215", "\303\255") < 0);

	cl_assert(git3__strcmp("rt\303\202of", "rt dev\302\266h") > 0);
	cl_assert(git3__strcmp("e\342\202\254ghi=", "et") > 0);
	cl_assert(git3__strcmp("rt dev\302\266h", "rt\303\202of") < 0);
	cl_assert(git3__strcmp("et", "e\342\202\254ghi=") < 0);
	cl_assert(git3__strcmp("\303\215", "\303\255") < 0);
}

void test_string__strcasecmp(void)
{
	cl_assert(git3__strcasecmp("", "") == 0);
	cl_assert(git3__strcasecmp("foo", "foo") == 0);
	cl_assert(git3__strcasecmp("foo", "Foo") == 0);
	cl_assert(git3__strcasecmp("foo", "FOO") == 0);
	cl_assert(git3__strcasecmp("foo", "fOO") == 0);

	cl_assert(git3__strcasecmp("rt\303\202of", "rt dev\302\266h") > 0);
	cl_assert(git3__strcasecmp("e\342\202\254ghi=", "et") > 0);
	cl_assert(git3__strcasecmp("rt dev\302\266h", "rt\303\202of") < 0);
	cl_assert(git3__strcasecmp("et", "e\342\202\254ghi=") < 0);
	cl_assert(git3__strcasecmp("\303\215", "\303\255") < 0);
}

void test_string__strlcmp(void)
{
	const char foo[3] = { 'f', 'o', 'o' };

	cl_assert(git3__strlcmp("foo", "foo", 3) == 0);
	cl_assert(git3__strlcmp("foo", foo, 3) == 0);
	cl_assert(git3__strlcmp("foo", "foobar", 3) == 0);
	cl_assert(git3__strlcmp("foobar", "foo", 3) > 0);
	cl_assert(git3__strlcmp("foo", "foobar", 6) < 0);
}
