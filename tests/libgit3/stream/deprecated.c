#include "clar_libgit3.h"
#include "git3/sys/stream.h"
#include "streams/tls.h"
#include "streams/socket.h"
#include "stream.h"

void test_stream_deprecated__cleanup(void)
{
	cl_git_pass(git3_stream_register(GIT3_STREAM_TLS | GIT3_STREAM_STANDARD, NULL));
}

#ifndef GIT3_DEPRECATE_HARD
static git3_stream test_stream;
static int ctor_called;

static int test_stream_init(git3_stream **out, const char *host, const char *port)
{
	GIT3_UNUSED(host);
	GIT3_UNUSED(port);

	ctor_called = 1;
	*out = &test_stream;

	return 0;
}
#endif

void test_stream_deprecated__register_tls(void)
{
#ifndef GIT3_DEPRECATE_HARD
	git3_stream *stream;
	int error;

	ctor_called = 0;
	cl_git_pass(git3_stream_register_tls(test_stream_init));
	cl_git_pass(git3_tls_stream_new(&stream, "localhost", "443"));
	cl_assert_equal_i(1, ctor_called);
	cl_assert_equal_p(&test_stream, stream);

	ctor_called = 0;
	stream = NULL;
	cl_git_pass(git3_stream_register_tls(NULL));
	error = git3_tls_stream_new(&stream, "localhost", "443");

	/*
	 * We don't have TLS support enabled, or we're on Windows,
	 * which has no arbitrary TLS stream support.
	 */
#if defined(GIT3_WIN32) || !defined(GIT3_HTTPS)
	cl_git_fail_with(-1, error);
#else
	cl_git_pass(error);
#endif

	cl_assert_equal_i(0, ctor_called);
	cl_assert(&test_stream != stream);

	git3_stream_free(stream);
#endif
}
