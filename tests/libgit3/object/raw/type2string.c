
#include "clar_libgit3.h"

#include "odb.h"
#include "hash.h"

void test_object_raw_type2string__convert_type_to_string(void)
{
	cl_assert_equal_s(git3_object_type2string(GIT3_OBJECT_INVALID), "");
	cl_assert_equal_s(git3_object_type2string(0), ""); /* unused */
	cl_assert_equal_s(git3_object_type2string(GIT3_OBJECT_COMMIT), "commit");
	cl_assert_equal_s(git3_object_type2string(GIT3_OBJECT_TREE), "tree");
	cl_assert_equal_s(git3_object_type2string(GIT3_OBJECT_BLOB), "blob");
	cl_assert_equal_s(git3_object_type2string(GIT3_OBJECT_TAG), "tag");
	cl_assert_equal_s(git3_object_type2string(5), ""); /* unused */
	cl_assert_equal_s(git3_object_type2string(6), ""); /* packfile offset delta */
	cl_assert_equal_s(git3_object_type2string(7), ""); /* packfile ref delta */

	cl_assert_equal_s(git3_object_type2string(-2), "");
	cl_assert_equal_s(git3_object_type2string(8), "");
	cl_assert_equal_s(git3_object_type2string(1234), "");
}

void test_object_raw_type2string__convert_string_to_type(void)
{
	cl_assert(git3_object_string2type(NULL) == GIT3_OBJECT_INVALID);
	cl_assert(git3_object_string2type("") == GIT3_OBJECT_INVALID);
	cl_assert(git3_object_string2type("commit") == GIT3_OBJECT_COMMIT);
	cl_assert(git3_object_string2type("tree") == GIT3_OBJECT_TREE);
	cl_assert(git3_object_string2type("blob") == GIT3_OBJECT_BLOB);
	cl_assert(git3_object_string2type("tag") == GIT3_OBJECT_TAG);
	cl_assert(git3_object_string2type("OFS_DELTA") == GIT3_OBJECT_INVALID);
	cl_assert(git3_object_string2type("REF_DELTA") == GIT3_OBJECT_INVALID);

	cl_assert(git3_object_string2type("CoMmIt") == GIT3_OBJECT_INVALID);
	cl_assert(git3_object_string2type("hohoho") == GIT3_OBJECT_INVALID);
}

void test_object_raw_type2string__check_type_is_valid(void)
{
	cl_assert(git3_object_type_is_valid(GIT3_OBJECT_INVALID) == 0);
	cl_assert(git3_object_type_is_valid(0) == 0); /* unused */
	cl_assert(git3_object_type_is_valid(GIT3_OBJECT_COMMIT) == 1);
	cl_assert(git3_object_type_is_valid(GIT3_OBJECT_TREE) == 1);
	cl_assert(git3_object_type_is_valid(GIT3_OBJECT_BLOB) == 1);
	cl_assert(git3_object_type_is_valid(GIT3_OBJECT_TAG) == 1);
	cl_assert(git3_object_type_is_valid(5) == 0); /* unused */
	cl_assert(git3_object_type_is_valid(6) == 0); /* packfile offset delta */
	cl_assert(git3_object_type_is_valid(7) == 0); /* packfile ref delta */

	cl_assert(git3_object_type_is_valid(-2) == 0);
	cl_assert(git3_object_type_is_valid(8) == 0);
	cl_assert(git3_object_type_is_valid(1234) == 0);
}
