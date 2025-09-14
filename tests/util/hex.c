#include "clar_libgit3.h"
#include "util.h"

void test_hex__fromhex(void)
{
	/* Passing cases */
	cl_assert(git3__fromhex('0') == 0x0);
	cl_assert(git3__fromhex('1') == 0x1);
	cl_assert(git3__fromhex('3') == 0x3);
	cl_assert(git3__fromhex('9') == 0x9);
	cl_assert(git3__fromhex('A') == 0xa);
	cl_assert(git3__fromhex('C') == 0xc);
	cl_assert(git3__fromhex('F') == 0xf);
	cl_assert(git3__fromhex('a') == 0xa);
	cl_assert(git3__fromhex('c') == 0xc);
	cl_assert(git3__fromhex('f') == 0xf);

	/* Failing cases */
	cl_assert(git3__fromhex('g') == -1);
	cl_assert(git3__fromhex('z') == -1);
	cl_assert(git3__fromhex('X') == -1);
}
