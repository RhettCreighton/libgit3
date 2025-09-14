/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_stream_h__
#define INCLUDE_stream_h__

#include "common.h"
#include "git3/sys/stream.h"

GIT3_INLINE(int) git3_stream_connect(git3_stream *st)
{
	return st->connect(st);
}

GIT3_INLINE(int) git3_stream_is_encrypted(git3_stream *st)
{
	return st->encrypted;
}

GIT3_INLINE(int) git3_stream_certificate(git3_cert **out, git3_stream *st)
{
	if (!st->encrypted) {
		git3_error_set(GIT3_ERROR_INVALID, "an unencrypted stream does not have a certificate");
		return -1;
	}

	return st->certificate(out, st);
}

GIT3_INLINE(int) git3_stream_supports_proxy(git3_stream *st)
{
	return st->proxy_support;
}

GIT3_INLINE(int) git3_stream_set_proxy(git3_stream *st, const git3_proxy_options *proxy_opts)
{
	if (!st->proxy_support) {
		git3_error_set(GIT3_ERROR_INVALID, "proxy not supported on this stream");
		return -1;
	}

	return st->set_proxy(st, proxy_opts);
}

GIT3_INLINE(ssize_t) git3_stream_read(git3_stream *st, void *data, size_t len)
{
	return st->read(st, data, len);
}

GIT3_INLINE(ssize_t) git3_stream_write(git3_stream *st, const char *data, size_t len, int flags)
{
	return st->write(st, data, len, flags);
}

GIT3_INLINE(int) git3_stream__write_full(git3_stream *st, const char *data, size_t len, int flags)
{
	size_t total_written = 0;

	while (total_written < len) {
		ssize_t written = git3_stream_write(st, data + total_written, len - total_written, flags);
		if (written <= 0)
			return -1;

		total_written += written;
	}

	return 0;
}

GIT3_INLINE(int) git3_stream_close(git3_stream *st)
{
	return st->close(st);
}

GIT3_INLINE(void) git3_stream_free(git3_stream *st)
{
	if (!st)
		return;

	st->free(st);
}

#endif
