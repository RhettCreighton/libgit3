/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "streams/stransport.h"

#ifdef GIT3_HTTPS_SECURETRANSPORT

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecureTransport.h>
#include <Security/SecCertificate.h>

#include "common.h"
#include "trace.h"
#include "git3/transport.h"
#include "streams/socket.h"

static int stransport_error(OSStatus ret)
{
	CFStringRef message_ref = NULL;
	const char *message_cstr = NULL;
	char *message_ptr = NULL;

	if (ret == noErr || ret == errSSLClosedGraceful) {
		git3_error_clear();
		return 0;
	}

#if !TARGET_OS_IPHONE
	message_ref = SecCopyErrorMessageString(ret, NULL);
	GIT3_ERROR_CHECK_ALLOC(message_ref);

	/*
	 * Attempt the cheap CFString conversion; this can return NULL
	 * when that would be expensive. In that case, call the more
	 * expensive function.
	 */
	message_cstr = CFStringGetCStringPtr(message_ref, kCFStringEncodingUTF8);

	if (!message_cstr) {
		/* Provide buffer to convert from UTF16 to UTF8 */
		size_t message_size = CFStringGetLength(message_ref) * 2 + 1;

		message_cstr = message_ptr = git3__malloc(message_size);
		GIT3_ERROR_CHECK_ALLOC(message_ptr);

		if (!CFStringGetCString(message_ref, message_ptr, message_size, kCFStringEncodingUTF8)) {
			git3_error_set(GIT3_ERROR_NET, "SecureTransport error: %d", (unsigned int)ret);
			goto done;
		}
	}

	git3_error_set(GIT3_ERROR_NET, "SecureTransport error: %s", message_cstr);

done:
	git3__free(message_ptr);
	CFRelease(message_ref);
#else
	git3_error_set(GIT3_ERROR_NET, "SecureTransport error: OSStatus %d", (unsigned int)ret);
	GIT3_UNUSED(message_ref);
	GIT3_UNUSED(message_cstr);
	GIT3_UNUSED(message_ptr);
#endif

	return -1;
}

typedef struct {
	git3_stream parent;
	git3_stream *io;
	int owned;
	int error;
	SSLContextRef ctx;
	CFDataRef der_data;
	git3_cert_x509 cert_info;
} stransport_stream;

static int stransport_connect(git3_stream *stream)
{
	stransport_stream *st = (stransport_stream *) stream;
	int error;
	SecTrustRef trust = NULL;
	SecTrustResultType sec_res;
	OSStatus ret;

	if (st->owned && (error = git3_stream_connect(st->io)) < 0)
		return error;

	ret = SSLHandshake(st->ctx);

	if (ret != errSSLServerAuthCompleted && st->error != 0)
		return -1;
	else if (ret != errSSLServerAuthCompleted) {
		git3_error_set(GIT3_ERROR_SSL, "unexpected return value from ssl handshake %d", (int)ret);
		return -1;
	}

	if ((ret = SSLCopyPeerTrust(st->ctx, &trust)) != noErr)
		goto on_error;

	if (!trust)
		return GIT3_ECERTIFICATE;

	if ((ret = SecTrustEvaluate(trust, &sec_res)) != noErr)
		goto on_error;

	CFRelease(trust);

	if (sec_res == kSecTrustResultInvalid || sec_res == kSecTrustResultOtherError) {
		git3_error_set(GIT3_ERROR_SSL, "internal security trust error");
		return -1;
	}

	if (sec_res == kSecTrustResultDeny || sec_res == kSecTrustResultRecoverableTrustFailure ||
	    sec_res == kSecTrustResultFatalTrustFailure) {
		git3_error_set(GIT3_ERROR_SSL, "untrusted connection error");
		return GIT3_ECERTIFICATE;
	}

	return 0;

on_error:
	if (trust)
		CFRelease(trust);

	return stransport_error(ret);
}

static int stransport_certificate(git3_cert **out, git3_stream *stream)
{
	stransport_stream *st = (stransport_stream *) stream;
	SecTrustRef trust = NULL;
	SecCertificateRef sec_cert;
	OSStatus ret;

	if ((ret = SSLCopyPeerTrust(st->ctx, &trust)) != noErr)
		return stransport_error(ret);

	sec_cert = SecTrustGetCertificateAtIndex(trust, 0);
	st->der_data = SecCertificateCopyData(sec_cert);
	CFRelease(trust);

	if (st->der_data == NULL) {
		git3_error_set(GIT3_ERROR_SSL, "retrieved invalid certificate data");
		return -1;
	}

	st->cert_info.parent.cert_type = GIT3_CERT_X509;
	st->cert_info.data = (void *) CFDataGetBytePtr(st->der_data);
	st->cert_info.len = CFDataGetLength(st->der_data);

	*out = (git3_cert *)&st->cert_info;
	return 0;
}

static int stransport_set_proxy(
	git3_stream *stream,
	const git3_proxy_options *proxy_opts)
{
	stransport_stream *st = (stransport_stream *) stream;

	return git3_stream_set_proxy(st->io, proxy_opts);
}

/*
 * Contrary to typical network IO callbacks, Secure Transport write callback is
 * expected to write *all* passed data, not just as much as it can, and any
 * other case would be considered a failure.
 *
 * This behavior is actually not specified in the Apple documentation, but is
 * required for things to work correctly (and incidentally, that's also how
 * Apple implements it in its projects at opensource.apple.com).
 *
 * Libgit2 streams happen to already have this very behavior so this is just
 * passthrough.
 */
static OSStatus write_cb(SSLConnectionRef conn, const void *data, size_t *len)
{
	stransport_stream *st = (stransport_stream *)conn;
	git3_stream *io = st->io;
	OSStatus ret;

	st->error = 0;

	ret = git3_stream__write_full(io, data, *len, 0);

	if (ret < 0) {
		st->error = ret;
		return (ret == GIT3_TIMEOUT) ?
		       -9853 /* errSSLNetworkTimeout */:
		       -36 /* ioErr */;
	}

	return noErr;
}

static ssize_t stransport_write(git3_stream *stream, const char *data, size_t len, int flags)
{
	stransport_stream *st = (stransport_stream *) stream;
	size_t data_len, processed;
	OSStatus ret;

	GIT3_UNUSED(flags);

	data_len = min(len, SSIZE_MAX);
	if ((ret = SSLWrite(st->ctx, data, data_len, &processed)) != noErr) {
		if (st->error == GIT3_TIMEOUT)
			return GIT3_TIMEOUT;

		return stransport_error(ret);
	}

	GIT3_ASSERT(processed < SSIZE_MAX);
	return (ssize_t)processed;
}

/*
 * Contrary to typical network IO callbacks, Secure Transport read callback is
 * expected to read *exactly* the requested number of bytes, not just as much
 * as it can, and any other case would be considered a failure.
 *
 * This behavior is actually not specified in the Apple documentation, but is
 * required for things to work correctly (and incidentally, that's also how
 * Apple implements it in its projects at opensource.apple.com).
 */
static OSStatus read_cb(SSLConnectionRef conn, void *data, size_t *len)
{
	stransport_stream *st = (stransport_stream *)conn;
	git3_stream *io = st->io;
	OSStatus error = noErr;
	size_t off = 0;
	ssize_t ret;

	st->error = 0;

	do {
		ret = git3_stream_read(io, data + off, *len - off);

		if (ret < 0) {
			st->error = ret;
			error = (ret == GIT3_TIMEOUT) ?
			        -9853 /* errSSLNetworkTimeout */:
			        -36 /* ioErr */;
			break;
		} else if (ret == 0) {
			error = errSSLClosedGraceful;
			break;
		}

		off += ret;
	} while (off < *len);

	*len = off;
	return error;
}

static ssize_t stransport_read(git3_stream *stream, void *data, size_t len)
{
	stransport_stream *st = (stransport_stream *)stream;
	size_t processed;
	OSStatus ret;

	if ((ret = SSLRead(st->ctx, data, len, &processed)) != noErr) {
		/* This specific SecureTransport error is not well described */
		if (ret == -9806)
			git3_trace(GIT3_TRACE_INFO, "SecureTraceport error during SSLRead: returned -9806 (connection closed via error)");

		if (st->error == GIT3_TIMEOUT)
			return GIT3_TIMEOUT;

		return stransport_error(ret);
	}

	return processed;
}

static int stransport_close(git3_stream *stream)
{
	stransport_stream *st = (stransport_stream *) stream;
	OSStatus ret;

	ret = SSLClose(st->ctx);
	if (ret != noErr && ret != errSSLClosedGraceful)
		return stransport_error(ret);

	return st->owned ? git3_stream_close(st->io) : 0;
}

static void stransport_free(git3_stream *stream)
{
	stransport_stream *st = (stransport_stream *) stream;

	if (st->owned)
		git3_stream_free(st->io);

	CFRelease(st->ctx);
	if (st->der_data)
		CFRelease(st->der_data);
	git3__free(st);
}

static int stransport_wrap(
	git3_stream **out,
	git3_stream *in,
	const char *host,
	int owned)
{
	stransport_stream *st;
	OSStatus ret;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(in);
	GIT3_ASSERT_ARG(host);

	st = git3__calloc(1, sizeof(stransport_stream));
	GIT3_ERROR_CHECK_ALLOC(st);

	st->io = in;
	st->owned = owned;

	st->ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
	if (!st->ctx) {
		git3_error_set(GIT3_ERROR_NET, "failed to create SSL context");
		git3__free(st);
		return -1;
	}

	if ((ret = SSLSetIOFuncs(st->ctx, read_cb, write_cb)) != noErr ||
	    (ret = SSLSetConnection(st->ctx, st)) != noErr ||
	    (ret = SSLSetSessionOption(st->ctx, kSSLSessionOptionBreakOnServerAuth, true)) != noErr ||
	    (ret = SSLSetProtocolVersionMin(st->ctx, kTLSProtocol12)) != noErr ||
	    (ret = SSLSetPeerDomainName(st->ctx, host, strlen(host))) != noErr) {
		CFRelease(st->ctx);
		git3__free(st);
		return stransport_error(ret);
	}

	st->parent.version = GIT3_STREAM_VERSION;
	st->parent.encrypted = 1;
	st->parent.proxy_support = git3_stream_supports_proxy(st->io);
	st->parent.connect = stransport_connect;
	st->parent.certificate = stransport_certificate;
	st->parent.set_proxy = stransport_set_proxy;
	st->parent.read = stransport_read;
	st->parent.write = stransport_write;
	st->parent.close = stransport_close;
	st->parent.free = stransport_free;

	*out = (git3_stream *) st;
	return 0;
}

int git3_stransport_stream_wrap(
	git3_stream **out,
	git3_stream *in,
	const char *host)
{
	return stransport_wrap(out, in, host, 0);
}

int git3_stransport_stream_new(git3_stream **out, const char *host, const char *port)
{
	git3_stream *stream = NULL;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(host);

	error = git3_socket_stream_new(&stream, host, port);

	if (!error)
		error = stransport_wrap(out, stream, host, 1);

	if (error < 0 && stream) {
		git3_stream_close(stream);
		git3_stream_free(stream);
	}

	return error;
}

#endif
