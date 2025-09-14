#include "clar_libgit3.h"
#include "git3/sys/stream.h"
#include "streams/tls.h"
#include "streams/socket.h"
#include "stream.h"

static git3_stream test_stream;
static int ctor_called;

void test_stream_registration__cleanup(void)
{
	cl_git_pass(git3_stream_register(GIT3_STREAM_TLS | GIT3_STREAM_STANDARD, NULL));
}

static int test_stream_init(git3_stream **out, const char *host, const char *port)
{
	GIT3_UNUSED(host);
	GIT3_UNUSED(port);

	ctor_called = 1;
	*out = &test_stream;

	return 0;
}

static int test_stream_wrap(git3_stream **out, git3_stream *in, const char *host)
{
	GIT3_UNUSED(in);
	GIT3_UNUSED(host);

	ctor_called = 1;
	*out = &test_stream;

	return 0;
}

void test_stream_registration__insecure(void)
{
	git3_stream *stream;
	git3_stream_registration registration = {0};

	registration.version = 1;
	registration.init = test_stream_init;
	registration.wrap = test_stream_wrap;

	ctor_called = 0;
	cl_git_pass(git3_stream_register(GIT3_STREAM_STANDARD, &registration));
	cl_git_pass(git3_socket_stream_new(&stream, "localhost", "80"));
	cl_assert_equal_i(1, ctor_called);
	cl_assert_equal_p(&test_stream, stream);

	ctor_called = 0;
	stream = NULL;
	cl_git_pass(git3_stream_register(GIT3_STREAM_STANDARD, NULL));
	cl_git_pass(git3_socket_stream_new(&stream, "localhost", "80"));

	cl_assert_equal_i(0, ctor_called);
	cl_assert(&test_stream != stream);

	git3_stream_free(stream);
}

void test_stream_registration__tls(void)
{
	git3_stream *stream;
	git3_stream_registration registration = {0};
	int error;

	registration.version = 1;
	registration.init = test_stream_init;
	registration.wrap = test_stream_wrap;

	ctor_called = 0;
	cl_git_pass(git3_stream_register(GIT3_STREAM_TLS, &registration));
	cl_git_pass(git3_tls_stream_new(&stream, "localhost", "443"));
	cl_assert_equal_i(1, ctor_called);
	cl_assert_equal_p(&test_stream, stream);

	ctor_called = 0;
	stream = NULL;
	cl_git_pass(git3_stream_register(GIT3_STREAM_TLS, NULL));
	error = git3_tls_stream_new(&stream, "localhost", "443");

	/* We don't have TLS support enabled, or we're on Windows
	 * with WinHTTP, which is not actually TLS stream support.
	 */
#if defined(GIT3_HTTPS_WINHTTP) || !defined(GIT3_HTTPS)
	cl_git_fail_with(-1, error);
#else
	cl_git_pass(error);
#endif

	cl_assert_equal_i(0, ctor_called);
	cl_assert(&test_stream != stream);

	git3_stream_free(stream);
}

void test_stream_registration__both(void)
{
	git3_stream *stream;
	git3_stream_registration registration = {0};

	registration.version = 1;
	registration.init = test_stream_init;
	registration.wrap = test_stream_wrap;

	cl_git_pass(git3_stream_register(GIT3_STREAM_STANDARD | GIT3_STREAM_TLS, &registration));

	ctor_called = 0;
	cl_git_pass(git3_tls_stream_new(&stream, "localhost", "443"));
	cl_assert_equal_i(1, ctor_called);
	cl_assert_equal_p(&test_stream, stream);

	ctor_called = 0;
	cl_git_pass(git3_socket_stream_new(&stream, "localhost", "80"));
	cl_assert_equal_i(1, ctor_called);
	cl_assert_equal_p(&test_stream, stream);
}
