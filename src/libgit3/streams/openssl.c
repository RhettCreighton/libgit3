/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "streams/openssl.h"
#include "streams/openssl_legacy.h"
#include "streams/openssl_dynamic.h"

#if defined(GIT3_HTTPS_OPENSSL) || defined(GIT3_HTTPS_OPENSSL_DYNAMIC)

#include <ctype.h>

#include "common.h"
#include "runtime.h"
#include "settings.h"
#include "posix.h"
#include "stream.h"
#include "net.h"
#include "streams/socket.h"
#include "git3/transport.h"
#include "git3/sys/openssl.h"

#ifndef GIT3_WIN32
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
#endif

#ifndef GIT3_HTTPS_OPENSSL_DYNAMIC
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/x509v3.h>
# include <openssl/bio.h>
#endif

extern char *git3__ssl_ciphers;

SSL_CTX *git3__ssl_ctx;

#define GIT3_SSL_DEFAULT_CIPHERS "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"


static BIO_METHOD *git3_stream_bio_method;
static int init_bio_method(void);

/**
 * This function aims to clean-up the SSL context which
 * we allocated.
 */
static void shutdown_ssl(void)
{
	if (git3_stream_bio_method) {
		BIO_meth_free(git3_stream_bio_method);
		git3_stream_bio_method = NULL;
	}

	if (git3__ssl_ctx) {
		SSL_CTX_free(git3__ssl_ctx);
		git3__ssl_ctx = NULL;
	}
}

#ifdef VALGRIND
# if !defined(GIT3_HTTPS_OPENSSL_LEGACY) && !defined(GIT3_HTTPS_OPENSSL_DYNAMIC)

static void *git3_openssl_malloc(size_t bytes, const char *file, int line)
{
	GIT3_UNUSED(file);
	GIT3_UNUSED(line);
	return git3__calloc(1, bytes);
}

static void *git3_openssl_realloc(void *mem, size_t size, const char *file, int line)
{
	GIT3_UNUSED(file);
	GIT3_UNUSED(line);
	return git3__realloc(mem, size);
}

static void git3_openssl_free(void *mem, const char *file, int line)
{
	GIT3_UNUSED(file);
	GIT3_UNUSED(line);
	git3__free(mem);
}
# else /* !GIT3_HTTPS_OPENSSL_LEGACY && !GIT3_HTTPS_OPENSSL_DYNAMIC */
static void *git3_openssl_malloc(size_t bytes)
{
	return git3__calloc(1, bytes);
}

static void *git3_openssl_realloc(void *mem, size_t size)
{
	return git3__realloc(mem, size);
}

static void git3_openssl_free(void *mem)
{
	git3__free(mem);
}
# endif /* !GIT3_HTTPS_OPENSSL_LEGACY && !GIT3_HTTPS_OPENSSL_DYNAMIC */
#endif /* VALGRIND */

static int openssl_init(void)
{
	long ssl_opts = SSL_OP_NO_SSLv2 |
	                SSL_OP_NO_SSLv3 |
	                SSL_OP_NO_TLSv1 |
	                SSL_OP_NO_TLSv1_1;
	const char *ciphers = git3__ssl_ciphers;
#ifdef VALGRIND
	static bool allocators_initialized = false;
#endif

	/* Older OpenSSL and MacOS OpenSSL doesn't have this */
#ifdef SSL_OP_NO_COMPRESSION
	ssl_opts |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef VALGRIND
	/*
	 * Swap in our own allocator functions that initialize
	 * allocated memory to avoid spurious valgrind warnings.
	 * Don't error on failure; many builds of OpenSSL do not
	 * allow you to set these functions.
	 */
	if (!allocators_initialized) {
	    CRYPTO_set_mem_functions(git3_openssl_malloc,
				     git3_openssl_realloc,
				     git3_openssl_free);
		allocators_initialized = true;
	}
#endif

	OPENSSL_init_ssl(0, NULL);

	/*
	 * Despite the name SSLv23_method, this is actually a version-
	 * flexible context, which honors the protocol versions
	 * specified in `ssl_opts`. So we only support TLSv1.2 and
	 * higher.
	 */
	if (!(git3__ssl_ctx = SSL_CTX_new(SSLv23_method())))
		goto error;

	SSL_CTX_set_options(git3__ssl_ctx, ssl_opts);
	SSL_CTX_set_mode(git3__ssl_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify(git3__ssl_ctx, SSL_VERIFY_NONE, NULL);
	if (!SSL_CTX_set_default_verify_paths(git3__ssl_ctx))
		goto error;

	if (!ciphers)
		ciphers = GIT3_SSL_DEFAULT_CIPHERS;

	if(!SSL_CTX_set_cipher_list(git3__ssl_ctx, ciphers))
		goto error;

	if (init_bio_method() < 0)
		goto error;

	return git3_runtime_shutdown_register(shutdown_ssl);

error:
	git3_error_set(GIT3_ERROR_NET, "could not initialize openssl: %s",
		ERR_error_string(ERR_get_error(), NULL));
	SSL_CTX_free(git3__ssl_ctx);
	git3__ssl_ctx = NULL;
	return -1;
}

/*
 * When we use dynamic loading, we defer OpenSSL initialization until
 * it's first used.  `openssl_ensure_initialized` will do the work
 * under a mutex.
 */
git3_mutex openssl_mutex;
bool openssl_initialized;

int git3_openssl_stream_global_init(void)
{
#ifndef GIT3_HTTPS_OPENSSL_DYNAMIC
	return openssl_init();
#else
	if (git3_mutex_init(&openssl_mutex) != 0)
		return -1;

	return 0;
#endif
}

static int openssl_ensure_initialized(void)
{
#ifdef GIT3_HTTPS_OPENSSL_DYNAMIC
	int error = 0;

	if (git3_mutex_lock(&openssl_mutex) != 0)
		return -1;

	if (!openssl_initialized) {
		if ((error = git3_openssl_stream_dynamic_init()) == 0)
			error = openssl_init();

		openssl_initialized = !error;
	}

	error |= git3_mutex_unlock(&openssl_mutex);
	return error;

#else
	return 0;
#endif
}

#if !defined(GIT3_HTTPS_OPENSSL_LEGACY) && !defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
int git3_openssl_set_locking(void)
{
# ifdef GIT3_THREADS
	return 0;
# else
	git3_error_set(GIT3_ERROR_THREAD, "libgit3 was not built with threads");
	return -1;
# endif
}
#endif


static int bio_create(BIO *b)
{
	BIO_set_init(b, 1);
	BIO_set_data(b, NULL);

	return 1;
}

static int bio_destroy(BIO *b)
{
	if (!b)
		return 0;

	BIO_set_data(b, NULL);

	return 1;
}

static int bio_read(BIO *b, char *buf, int len)
{
	git3_stream *io = (git3_stream *) BIO_get_data(b);

	return (int) git3_stream_read(io, buf, len);
}

static int bio_write(BIO *b, const char *buf, int len)
{
	git3_stream *io = (git3_stream *) BIO_get_data(b);
	return (int) git3_stream_write(io, buf, len, 0);
}

static long bio_ctrl(BIO *b, int cmd, long num, void *ptr)
{
	GIT3_UNUSED(b);
	GIT3_UNUSED(num);
	GIT3_UNUSED(ptr);

	if (cmd == BIO_CTRL_FLUSH)
		return 1;

	return 0;
}

static int bio_gets(BIO *b, char *buf, int len)
{
	GIT3_UNUSED(b);
	GIT3_UNUSED(buf);
	GIT3_UNUSED(len);
	return -1;
}

static int bio_puts(BIO *b, const char *str)
{
	return bio_write(b, str, strlen(str));
}

static int init_bio_method(void)
{
	/* Set up the BIO_METHOD we use for wrapping our own stream implementations */
	git3_stream_bio_method = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "git3_stream");
	GIT3_ERROR_CHECK_ALLOC(git3_stream_bio_method);

	BIO_meth_set_write(git3_stream_bio_method, bio_write);
	BIO_meth_set_read(git3_stream_bio_method, bio_read);
	BIO_meth_set_puts(git3_stream_bio_method, bio_puts);
	BIO_meth_set_gets(git3_stream_bio_method, bio_gets);
	BIO_meth_set_ctrl(git3_stream_bio_method, bio_ctrl);
	BIO_meth_set_create(git3_stream_bio_method, bio_create);
	BIO_meth_set_destroy(git3_stream_bio_method, bio_destroy);

	return 0;
}

static int ssl_set_error(SSL *ssl, int error)
{
	int err;
	unsigned long e;

	err = SSL_get_error(ssl, error);

	GIT3_ASSERT(err != SSL_ERROR_WANT_READ);
	GIT3_ASSERT(err != SSL_ERROR_WANT_WRITE);

	switch (err) {
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
		git3_error_set(GIT3_ERROR_SSL, "SSL error: connection failure");
		break;
	case SSL_ERROR_WANT_X509_LOOKUP:
		git3_error_set(GIT3_ERROR_SSL, "SSL error: x509 error");
		break;
	case SSL_ERROR_SYSCALL:
		e = ERR_get_error();
		if (e > 0) {
			char errmsg[256];
			ERR_error_string_n(e, errmsg, sizeof(errmsg));
			git3_error_set(GIT3_ERROR_NET, "SSL error: %s", errmsg);
			break;
		} else if (error < 0) {
			git3_error_set(GIT3_ERROR_OS, "SSL error: syscall failure");
			break;
		}
		git3_error_set(GIT3_ERROR_SSL, "SSL error: received early EOF");
		return GIT3_EEOF;
		break;
	case SSL_ERROR_SSL:
	{
		char errmsg[256];
		e = ERR_get_error();
		ERR_error_string_n(e, errmsg, sizeof(errmsg));
		git3_error_set(GIT3_ERROR_SSL, "SSL error: %s", errmsg);
		break;
	}
	case SSL_ERROR_NONE:
	case SSL_ERROR_ZERO_RETURN:
	default:
		git3_error_set(GIT3_ERROR_SSL, "SSL error: unknown error");
		break;
	}
	return -1;
}

static int ssl_teardown(SSL *ssl)
{
	int ret;

	ret = SSL_shutdown(ssl);
	if (ret < 0)
		ret = ssl_set_error(ssl, ret);
	else
		ret = 0;

	return ret;
}

static bool check_host_name(const char *host, const char *name)
{
	return !strcasecmp(host, name) ||
	       git3_net_hostname_matches_cert(host, name);
}

static int verify_server_cert(SSL *ssl, const char *host)
{
	X509 *cert = NULL;
	X509_NAME *peer_name;
	ASN1_STRING *str;
	unsigned char *peer_cn = NULL;
	int matched = -1, type = GEN_DNS;
	GENERAL_NAMES *alts;
	struct in6_addr addr6;
	struct in_addr addr4;
	void *addr = NULL;
	int i = -1, j, error = 0;

	if (SSL_get_verify_result(ssl) != X509_V_OK) {
		git3_error_set(GIT3_ERROR_SSL, "the SSL certificate is invalid");
		return GIT3_ECERTIFICATE;
	}

	/* Try to parse the host as an IP address to see if it is */
	if (p_inet_pton(AF_INET, host, &addr4)) {
		type = GEN_IPADD;
		addr = &addr4;
	} else {
		if (p_inet_pton(AF_INET6, host, &addr6)) {
			type = GEN_IPADD;
			addr = &addr6;
		}
	}


	cert = SSL_get_peer_certificate(ssl);
	if (!cert) {
		error = -1;
		git3_error_set(GIT3_ERROR_SSL, "the server did not provide a certificate");
		goto cleanup;
	}

	/* Check the alternative names */
	alts = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (alts) {
		int num;

		num = sk_GENERAL_NAME_num(alts);
		for (i = 0; i < num && matched != 1; i++) {
			const GENERAL_NAME *gn = sk_GENERAL_NAME_value(alts, i);
			const char *name = (char *) ASN1_STRING_get0_data(gn->d.ia5);
			size_t namelen = (size_t) ASN1_STRING_length(gn->d.ia5);

			/* Skip any names of a type we're not looking for */
			if (gn->type != type)
				continue;

			if (type == GEN_DNS) {
				/* If it contains embedded NULs, don't even try */
				if (memchr(name, '\0', namelen))
					continue;

				matched = !!check_host_name(host, name);
			} else if (type == GEN_IPADD) {
				/* Here name isn't so much a name but a binary representation of the IP */
				matched = addr && !!memcmp(name, addr, namelen);
			}
		}
	}
	GENERAL_NAMES_free(alts);

	if (matched == 0)
		goto cert_fail_name;

	if (matched == 1) {
		goto cleanup;
	}

	/* If no alternative names are available, check the common name */
	peer_name = X509_get_subject_name(cert);
	if (peer_name == NULL)
		goto on_error;

	if (peer_name) {
		/* Get the index of the last CN entry */
		while ((j = X509_NAME_get_index_by_NID(peer_name, NID_commonName, i)) >= 0)
			i = j;
	}

	if (i < 0)
		goto on_error;

	str = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(peer_name, i));
	if (str == NULL)
		goto on_error;

	/* Work around a bug in OpenSSL whereby ASN1_STRING_to_UTF8 fails if it's already in utf-8 */
	if (ASN1_STRING_type(str) == V_ASN1_UTF8STRING) {
		int size = ASN1_STRING_length(str);

		if (size > 0) {
			peer_cn = OPENSSL_malloc(size + 1);
			GIT3_ERROR_CHECK_ALLOC(peer_cn);
			memcpy(peer_cn, ASN1_STRING_get0_data(str), size);
			peer_cn[size] = '\0';
		} else {
			goto cert_fail_name;
		}
	} else {
		int size = ASN1_STRING_to_UTF8(&peer_cn, str);
		GIT3_ERROR_CHECK_ALLOC(peer_cn);
		if (memchr(peer_cn, '\0', size))
			goto cert_fail_name;
	}

	if (!check_host_name(host, (char *)peer_cn))
		goto cert_fail_name;

	goto cleanup;

cert_fail_name:
	error = GIT3_ECERTIFICATE;
	git3_error_set(GIT3_ERROR_SSL, "hostname does not match certificate");
	goto cleanup;

on_error:
	error = ssl_set_error(ssl, 0);
	goto cleanup;

cleanup:
	X509_free(cert);
	OPENSSL_free(peer_cn);
	return error;
}

typedef struct {
	git3_stream parent;
	git3_stream *io;
	int owned;
	bool connected;
	char *host;
	SSL *ssl;
	git3_cert_x509 cert_info;
} openssl_stream;

static int openssl_connect(git3_stream *stream)
{
	int ret;
	BIO *bio;
	openssl_stream *st = (openssl_stream *) stream;

	if (st->owned && (ret = git3_stream_connect(st->io)) < 0)
		return ret;

	bio = BIO_new(git3_stream_bio_method);
	GIT3_ERROR_CHECK_ALLOC(bio);

	BIO_set_data(bio, st->io);
	SSL_set_bio(st->ssl, bio, bio);

	/* specify the host in case SNI is needed */
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	SSL_set_tlsext_host_name(st->ssl, st->host);
#endif

	if ((ret = SSL_connect(st->ssl)) <= 0)
		return ssl_set_error(st->ssl, ret);

	st->connected = true;

	return verify_server_cert(st->ssl, st->host);
}

static int openssl_certificate(git3_cert **out, git3_stream *stream)
{
	openssl_stream *st = (openssl_stream *) stream;
	X509 *cert = SSL_get_peer_certificate(st->ssl);
	unsigned char *guard, *encoded_cert = NULL;
	int error, len;

	/* Retrieve the length of the certificate first */
	len = i2d_X509(cert, NULL);
	if (len < 0) {
		git3_error_set(GIT3_ERROR_NET, "failed to retrieve certificate information");
		error = -1;
		goto out;
	}

	encoded_cert = git3__malloc(len);
	GIT3_ERROR_CHECK_ALLOC(encoded_cert);
	/* i2d_X509 makes 'guard' point to just after the data */
	guard = encoded_cert;

	len = i2d_X509(cert, &guard);
	if (len < 0) {
		git3_error_set(GIT3_ERROR_NET, "failed to retrieve certificate information");
		error = -1;
		goto out;
	}

	st->cert_info.parent.cert_type = GIT3_CERT_X509;
	st->cert_info.data = encoded_cert;
	st->cert_info.len = len;
	encoded_cert = NULL;

	*out = &st->cert_info.parent;
	error = 0;

out:
	git3__free(encoded_cert);
	X509_free(cert);
	return error;
}

static int openssl_set_proxy(git3_stream *stream, const git3_proxy_options *proxy_opts)
{
	openssl_stream *st = (openssl_stream *) stream;

	return git3_stream_set_proxy(st->io, proxy_opts);
}

static ssize_t openssl_write(git3_stream *stream, const char *data, size_t data_len, int flags)
{
	openssl_stream *st = (openssl_stream *) stream;
	int ret, len = min(data_len, INT_MAX);

	GIT3_UNUSED(flags);

	if ((ret = SSL_write(st->ssl, data, len)) <= 0)
		return ssl_set_error(st->ssl, ret);

	return ret;
}

static ssize_t openssl_read(git3_stream *stream, void *data, size_t len)
{
	openssl_stream *st = (openssl_stream *) stream;
	int ret;

	if ((ret = SSL_read(st->ssl, data, len)) <= 0)
		return ssl_set_error(st->ssl, ret);

	return ret;
}

static int openssl_close(git3_stream *stream)
{
	openssl_stream *st = (openssl_stream *) stream;
	int ret;

	if (st->connected && (ret = ssl_teardown(st->ssl)) < 0)
		return -1;

	st->connected = false;

	return st->owned ? git3_stream_close(st->io) : 0;
}

static void openssl_free(git3_stream *stream)
{
	openssl_stream *st = (openssl_stream *) stream;

	if (st->owned)
		git3_stream_free(st->io);

	SSL_free(st->ssl);
	git3__free(st->host);
	git3__free(st->cert_info.data);
	git3__free(st);
}

static int openssl_stream_wrap(
	git3_stream **out,
	git3_stream *in,
	const char *host,
	int owned)
{
	openssl_stream *st;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(in);
	GIT3_ASSERT_ARG(host);

	st = git3__calloc(1, sizeof(openssl_stream));
	GIT3_ERROR_CHECK_ALLOC(st);

	st->io = in;
	st->owned = owned;

	st->ssl = SSL_new(git3__ssl_ctx);
	if (st->ssl == NULL) {
		git3_error_set(GIT3_ERROR_SSL, "failed to create ssl object");
		git3__free(st);
		return -1;
	}

	st->host = git3__strdup(host);
	GIT3_ERROR_CHECK_ALLOC(st->host);

	st->parent.version = GIT3_STREAM_VERSION;
	st->parent.encrypted = 1;
	st->parent.proxy_support = git3_stream_supports_proxy(st->io);
	st->parent.connect = openssl_connect;
	st->parent.certificate = openssl_certificate;
	st->parent.set_proxy = openssl_set_proxy;
	st->parent.read = openssl_read;
	st->parent.write = openssl_write;
	st->parent.close = openssl_close;
	st->parent.free = openssl_free;

	*out = (git3_stream *) st;
	return 0;
}

int git3_openssl_stream_wrap(git3_stream **out, git3_stream *in, const char *host)
{
	if (openssl_ensure_initialized() < 0)
		return -1;

	return openssl_stream_wrap(out, in, host, 0);
}

int git3_openssl_stream_new(git3_stream **out, const char *host, const char *port)
{
	git3_stream *stream = NULL;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(host);
	GIT3_ASSERT_ARG(port);

	if (openssl_ensure_initialized() < 0)
		return -1;

	if ((error = git3_socket_stream_new(&stream, host, port)) < 0)
		return error;

	if ((error = openssl_stream_wrap(out, stream, host, 1)) < 0) {
		git3_stream_close(stream);
		git3_stream_free(stream);
	}

	return error;
}

int git3_openssl__set_cert_location(const char *file, const char *path)
{
	if (openssl_ensure_initialized() < 0)
		return -1;

	if (SSL_CTX_load_verify_locations(git3__ssl_ctx, file, path) == 0) {
		char errmsg[256];

		ERR_error_string_n(ERR_get_error(), errmsg, sizeof(errmsg));
		git3_error_set(GIT3_ERROR_SSL, "OpenSSL error: failed to load certificates: %s",
			errmsg);

		return -1;
	}
	return 0;
}

int git3_openssl__add_x509_cert(X509 *cert)
{
	X509_STORE *cert_store;

	if (openssl_ensure_initialized() < 0)
		return -1;

	if (!(cert_store = SSL_CTX_get_cert_store(git3__ssl_ctx)))
		return -1;

	if (cert && X509_STORE_add_cert(cert_store, cert) == 0) {
		git3_error_set(GIT3_ERROR_SSL, "OpenSSL error: failed to add raw X509 certificate");
		return -1;
	}

	return 0;
}

int git3_openssl__reset_context(void)
{
	shutdown_ssl();
	return openssl_init();
}

#else

#include "stream.h"
#include "git3/sys/openssl.h"

int git3_openssl_stream_global_init(void)
{
	return 0;
}

int git3_openssl_set_locking(void)
{
	git3_error_set(GIT3_ERROR_SSL, "libgit3 was not built with OpenSSL support");
	return -1;
}

#endif
