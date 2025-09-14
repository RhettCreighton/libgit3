
#include "clar_libgit3.h"

#include "odb.h"

void test_object_raw_size__validate_oid_size(void)
{
	git3_oid out;

	cl_assert(20 == GIT3_OID_SHA1_SIZE);
	cl_assert(40 == GIT3_OID_SHA1_HEXSIZE);
	cl_assert(sizeof(out.id) == GIT3_OID_MAX_SIZE);
}
