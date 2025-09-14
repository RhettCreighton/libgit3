
#include "clar_libgit3.h"

#include "odb.h"

void test_object_raw_compare__succeed_on_copy_oid(void)
{
	git3_oid a, b;
	unsigned char exp[] = {
		0x16, 0xa6, 0x77, 0x70, 0xb7,
		0xd8, 0xd7, 0x23, 0x17, 0xc4,
		0xb7, 0x75, 0x21, 0x3c, 0x23,
		0xa8, 0xbd, 0x74, 0xf5, 0xe0,
	};
	memset(&b, 0, sizeof(b));
	git3_oid_from_raw(&a, exp, GIT3_OID_SHA1);
	git3_oid_cpy(&b, &a);
	cl_git_pass(memcmp(a.id, exp, GIT3_OID_SHA1_SIZE));
}

void test_object_raw_compare__succeed_on_oid_comparison_lesser(void)
{
	git3_oid a, b;
	unsigned char a_in[] = {
		0x16, 0xa6, 0x77, 0x70, 0xb7,
		0xd8, 0xd7, 0x23, 0x17, 0xc4,
		0xb7, 0x75, 0x21, 0x3c, 0x23,
		0xa8, 0xbd, 0x74, 0xf5, 0xe0,
	};
	unsigned char b_in[] = {
		0x16, 0xa6, 0x77, 0x70, 0xb7,
		0xd8, 0xd7, 0x23, 0x17, 0xc4,
		0xb7, 0x75, 0x21, 0x3c, 0x23,
		0xa8, 0xbd, 0x74, 0xf5, 0xf0,
	};
	git3_oid_from_raw(&a, a_in, GIT3_OID_SHA1);
	git3_oid_from_raw(&b, b_in, GIT3_OID_SHA1);
	cl_assert(git3_oid_cmp(&a, &b) < 0);
}

void test_object_raw_compare__succeed_on_oid_comparison_equal(void)
{
	git3_oid a, b;
	unsigned char a_in[] = {
		0x16, 0xa6, 0x77, 0x70, 0xb7,
		0xd8, 0xd7, 0x23, 0x17, 0xc4,
		0xb7, 0x75, 0x21, 0x3c, 0x23,
		0xa8, 0xbd, 0x74, 0xf5, 0xe0,
	};
	git3_oid_from_raw(&a, a_in, GIT3_OID_SHA1);
	git3_oid_from_raw(&b, a_in, GIT3_OID_SHA1);
	cl_assert(git3_oid_cmp(&a, &b) == 0);
}

void test_object_raw_compare__succeed_on_oid_comparison_greater(void)
{
	git3_oid a, b;
	unsigned char a_in[] = {
		0x16, 0xa6, 0x77, 0x70, 0xb7,
		0xd8, 0xd7, 0x23, 0x17, 0xc4,
		0xb7, 0x75, 0x21, 0x3c, 0x23,
		0xa8, 0xbd, 0x74, 0xf5, 0xe0,
	};
	unsigned char b_in[] = {
		0x16, 0xa6, 0x77, 0x70, 0xb7,
		0xd8, 0xd7, 0x23, 0x17, 0xc4,
		0xb7, 0x75, 0x21, 0x3c, 0x23,
		0xa8, 0xbd, 0x74, 0xf5, 0xd0,
	};
	git3_oid_from_raw(&a, a_in, GIT3_OID_SHA1);
	git3_oid_from_raw(&b, b_in, GIT3_OID_SHA1);
	cl_assert(git3_oid_cmp(&a, &b) > 0);
}

void test_object_raw_compare__compare_fmt_oids(void)
{
	const char *exp = "16a0123456789abcdef4b775213c23a8bd74f5e0";
	git3_oid in;
	char out[GIT3_OID_SHA1_HEXSIZE + 1];

	cl_git_pass(git3_oid_from_string(&in, exp, GIT3_OID_SHA1));

	/* Format doesn't touch the last byte */
	out[GIT3_OID_SHA1_HEXSIZE] = 'Z';
	git3_oid_fmt(out, &in);
	cl_assert(out[GIT3_OID_SHA1_HEXSIZE] == 'Z');

	/* Format produced the right result */
	out[GIT3_OID_SHA1_HEXSIZE] = '\0';
	cl_assert_equal_s(exp, out);
}

void test_object_raw_compare__compare_static_oids(void)
{
	const char *exp = "16a0123456789abcdef4b775213c23a8bd74f5e0";
	git3_oid in;
	char *out;

	cl_git_pass(git3_oid_from_string(&in, exp, GIT3_OID_SHA1));

	out = git3_oid_tostr_s(&in);
	cl_assert(out);
	cl_assert_equal_s(exp, out);
}

void test_object_raw_compare__compare_pathfmt_oids(void)
{
	const char *exp1 = "16a0123456789abcdef4b775213c23a8bd74f5e0";
	const char *exp2 = "16/a0123456789abcdef4b775213c23a8bd74f5e0";
	git3_oid in;
	char out[GIT3_OID_SHA1_HEXSIZE + 2];

	cl_git_pass(git3_oid_from_string(&in, exp1, GIT3_OID_SHA1));

	/* Format doesn't touch the last byte */
	out[GIT3_OID_SHA1_HEXSIZE + 1] = 'Z';
	git3_oid_pathfmt(out, &in);
	cl_assert(out[GIT3_OID_SHA1_HEXSIZE + 1] == 'Z');

	/* Format produced the right result */
	out[GIT3_OID_SHA1_HEXSIZE + 1] = '\0';
	cl_assert_equal_s(exp2, out);
}
