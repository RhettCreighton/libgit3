#include "clar_libgit3.h"
#include "zstream.h"

static const char *data = "This is a test test test of This is a test";

#define INFLATE_EXTRA 2

static void assert_zlib_equal_(
	const void *expected, size_t e_len,
	const void *compressed, size_t c_len,
	const char *msg, const char *file, const char *func, int line)
{
	z_stream stream;
	char *expanded = git3__calloc(1, e_len + INFLATE_EXTRA);
	cl_assert(expanded);

	memset(&stream, 0, sizeof(stream));
	stream.next_out  = (Bytef *)expanded;
	stream.avail_out = (uInt)(e_len + INFLATE_EXTRA);
	stream.next_in   = (Bytef *)compressed;
	stream.avail_in  = (uInt)c_len;

	cl_assert(inflateInit(&stream) == Z_OK);
	cl_assert(inflate(&stream, Z_FINISH));
	inflateEnd(&stream);

	clar__assert_equal(
		file, func, line, msg, 1,
		"%d", (int)stream.total_out, (int)e_len);
	clar__assert_equal(
		file, func, line, "Buffer len was not exact match", 1,
		"%d", (int)stream.avail_out, (int)INFLATE_EXTRA);

	clar__assert(
		memcmp(expanded, expected, e_len) == 0,
		file, func, line, "uncompressed data did not match", NULL, 1);

	git3__free(expanded);
}

#define assert_zlib_equal(E,EL,C,CL) \
	assert_zlib_equal_(E, EL, C, CL, #EL " != " #CL, __FILE__, __func__, (int)__LINE__)

void test_zstream__basic(void)
{
	git3_zstream z = GIT3_ZSTREAM_INIT;
	char out[128];
	size_t outlen = sizeof(out);

	cl_git_pass(git3_zstream_init(&z, GIT3_ZSTREAM_DEFLATE));
	cl_git_pass(git3_zstream_set_input(&z, data, strlen(data) + 1));
	cl_git_pass(git3_zstream_get_output(out, &outlen, &z));
	cl_assert(git3_zstream_done(&z));
	cl_assert(outlen > 0);
	git3_zstream_free(&z);

	assert_zlib_equal(data, strlen(data) + 1, out, outlen);
}

void test_zstream__fails_on_trailing_garbage(void)
{
	git3_str deflated = GIT3_STR_INIT, inflated = GIT3_STR_INIT;
	char i = 0;

	/* compress a simple string */
	git3_zstream_deflatebuf(&deflated, "foobar!!", 8);

	/* append some garbage */
	for (i = 0; i < 10; i++) {
		git3_str_putc(&deflated, i);
	}

	cl_git_fail(git3_zstream_inflatebuf(&inflated, deflated.ptr, deflated.size));

	git3_str_dispose(&deflated);
	git3_str_dispose(&inflated);
}

void test_zstream__buffer(void)
{
	git3_str out = GIT3_STR_INIT;
	cl_git_pass(git3_zstream_deflatebuf(&out, data, strlen(data) + 1));
	assert_zlib_equal(data, strlen(data) + 1, out.ptr, out.size);
	git3_str_dispose(&out);
}

#define BIG_STRING_PART "Big Data IS Big - Long Data IS Long - We need a buffer larger than 1024 x 1024 to make sure we trigger chunked compression - Big Big Data IS Bigger than Big - Long Long Data IS Longer than Long"

static void compress_and_decompress_input_various_ways(git3_str *input)
{
	git3_str out1 = GIT3_STR_INIT, out2 = GIT3_STR_INIT;
	git3_str inflated = GIT3_STR_INIT;
	size_t i, fixed_size = max(input->size / 2, 256);
	char *fixed = git3__malloc(fixed_size);
	cl_assert(fixed);

	/* compress with deflatebuf */

	cl_git_pass(git3_zstream_deflatebuf(&out1, input->ptr, input->size));
	assert_zlib_equal(input->ptr, input->size, out1.ptr, out1.size);

	/* compress with various fixed size buffer (accumulating the output) */

	for (i = 0; i < 3; ++i) {
		git3_zstream zs = GIT3_ZSTREAM_INIT;
		size_t use_fixed_size;

		switch (i) {
		case 0: use_fixed_size = 256; break;
		case 1: use_fixed_size = fixed_size / 2; break;
		case 2: use_fixed_size = fixed_size; break;
		}
		cl_assert(use_fixed_size <= fixed_size);

		cl_git_pass(git3_zstream_init(&zs, GIT3_ZSTREAM_DEFLATE));
		cl_git_pass(git3_zstream_set_input(&zs, input->ptr, input->size));

		while (!git3_zstream_done(&zs)) {
			size_t written = use_fixed_size;
			cl_git_pass(git3_zstream_get_output(fixed, &written, &zs));
			cl_git_pass(git3_str_put(&out2, fixed, written));
		}

		git3_zstream_free(&zs);
		assert_zlib_equal(input->ptr, input->size, out2.ptr, out2.size);

		/* did both approaches give the same data? */
		cl_assert_equal_sz(out1.size, out2.size);
		cl_assert(!memcmp(out1.ptr, out2.ptr, out1.size));

		git3_str_dispose(&out2);
	}

	cl_git_pass(git3_zstream_inflatebuf(&inflated, out1.ptr, out1.size));
	cl_assert_equal_i(input->size, inflated.size);
	cl_assert(memcmp(input->ptr, inflated.ptr, inflated.size) == 0);

	git3_str_dispose(&out1);
	git3_str_dispose(&inflated);
	git3__free(fixed);
}

void test_zstream__big_data(void)
{
	git3_str in = GIT3_STR_INIT;
	size_t scan, target;

	for (target = 1024; target <= 1024 * 1024 * 4; target *= 8) {

		/* make a big string that's easy to compress */
		git3_str_clear(&in);
		while (in.size < target)
			cl_git_pass(
				git3_str_put(&in, BIG_STRING_PART, strlen(BIG_STRING_PART)));

		compress_and_decompress_input_various_ways(&in);

		/* make a big string that's hard to compress */
		srand(0xabad1dea);
		for (scan = 0; scan < in.size; ++scan)
			in.ptr[scan] = (char)rand();

		compress_and_decompress_input_various_ways(&in);
	}

	git3_str_dispose(&in);
}
