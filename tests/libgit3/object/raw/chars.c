
#include "clar_libgit3.h"

#include "odb.h"

void test_object_raw_chars__find_invalid_chars_in_oid(void)
{
	git3_oid out;
	unsigned char exp[] = {
		0x16, 0xa6, 0x77, 0x70, 0xb7,
		0xd8, 0xd7, 0x23, 0x17, 0xc4,
		0xb7, 0x75, 0x21, 0x3c, 0x23,
		0xa8, 0xbd, 0x74, 0xf5, 0xe0,
	};
	char in[] = "16a67770b7d8d72317c4b775213c23a8bd74f5e0";
	unsigned int i;

	for (i = 0; i < 256; i++) {
		in[38] = (char)i;
		if (git3__fromhex(i) >= 0) {
			exp[19] = (unsigned char)(git3__fromhex(i) << 4);
			cl_git_pass(git3_oid_from_string(&out, in, GIT3_OID_SHA1));
			cl_assert(memcmp(out.id, exp, GIT3_OID_SHA1_SIZE) == 0);
		} else {
			cl_git_fail(git3_oid_from_string(&out, in, GIT3_OID_SHA1));
		}
	}
}

void test_object_raw_chars__build_valid_oid_from_raw_bytes(void)
{
	git3_oid out;
	unsigned char exp[] = {
		0x16, 0xa6, 0x77, 0x70, 0xb7,
		0xd8, 0xd7, 0x23, 0x17, 0xc4,
		0xb7, 0x75, 0x21, 0x3c, 0x23,
		0xa8, 0xbd, 0x74, 0xf5, 0xe0,
	};
	git3_oid_from_raw(&out, exp, GIT3_OID_SHA1);
	cl_git_pass(memcmp(out.id, exp, GIT3_OID_SHA1_SIZE));
}
