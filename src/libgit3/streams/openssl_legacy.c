/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "streams/openssl.h"
#include "streams/openssl_legacy.h"

#include "runtime.h"
#include "git3/sys/openssl.h"

#if defined(GIT3_HTTPS_OPENSSL) && !defined(GIT3_HTTPS_OPENSSL_DYNAMIC)
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/x509v3.h>
# include <openssl/bio.h>
#endif

#if defined(GIT3_HTTPS_OPENSSL_LEGACY) || defined(GIT3_HTTPS_OPENSSL_DYNAMIC)

/*
 * OpenSSL 1.1 made BIO opaque so we have to use functions to interact with it
 * which do not exist in previous versions. We define these inline functions so
 * we can program against the interface instead of littering the implementation
 * with ifdefs. We do the same for OPENSSL_init_ssl.
 */

int OPENSSL_init_ssl__legacy(uint64_t opts, const void *settings)
{
	GIT3_UNUSED(opts);
	GIT3_UNUSED(settings);
	SSL_load_error_strings();
	SSL_library_init();
	return 0;
}

BIO_METHOD *BIO_meth_new__legacy(int type, const char *name)
{
	BIO_METHOD *meth = git3__calloc(1, sizeof(BIO_METHOD));
	if (!meth) {
		return NULL;
	}

	meth->type = type;
	meth->name = name;

	return meth;
}

void BIO_meth_free__legacy(BIO_METHOD *biom)
{
	git3__free(biom);
}

int BIO_meth_set_write__legacy(BIO_METHOD *biom, int (*write) (BIO *, const char *, int))
{
	biom->bwrite = write;
	return 1;
}

int BIO_meth_set_read__legacy(BIO_METHOD *biom, int (*read) (BIO *, char *, int))
{
	biom->bread = read;
	return 1;
}

int BIO_meth_set_puts__legacy(BIO_METHOD *biom, int (*puts) (BIO *, const char *))
{
	biom->bputs = puts;
	return 1;
}

int BIO_meth_set_gets__legacy(BIO_METHOD *biom, int (*gets) (BIO *, char *, int))

{
	biom->bgets = gets;
	return 1;
}

int BIO_meth_set_ctrl__legacy(BIO_METHOD *biom, long (*ctrl) (BIO *, int, long, void *))
{
	biom->ctrl = ctrl;
	return 1;
}

int BIO_meth_set_create__legacy(BIO_METHOD *biom, int (*create) (BIO *))
{
	biom->create = create;
	return 1;
}

int BIO_meth_set_destroy__legacy(BIO_METHOD *biom, int (*destroy) (BIO *))
{
	biom->destroy = destroy;
	return 1;
}

int BIO_get_new_index__legacy(void)
{
	/* This exists as of 1.1 so before we'd just have 0 */
	return 0;
}

void BIO_set_init__legacy(BIO *b, int init)
{
	b->init = init;
}

void BIO_set_data__legacy(BIO *a, void *ptr)
{
	a->ptr = ptr;
}

void *BIO_get_data__legacy(BIO *a)
{
	return a->ptr;
}

const unsigned char *ASN1_STRING_get0_data__legacy(const ASN1_STRING *x)
{
	return ASN1_STRING_data((ASN1_STRING *)x);
}

long SSL_CTX_set_options__legacy(SSL_CTX *ctx, long op)
{
	return SSL_CTX_ctrl(ctx, SSL_CTRL_OPTIONS, op, NULL);
}

# if defined(GIT3_THREADS)
static git3_mutex *openssl_locks;

static void openssl_locking_function(int mode, int n, const char *file, int line)
{
	int lock;

	GIT3_UNUSED(file);
	GIT3_UNUSED(line);

	lock = mode & CRYPTO_LOCK;

	if (lock)
		(void)git3_mutex_lock(&openssl_locks[n]);
	else
		git3_mutex_unlock(&openssl_locks[n]);
}

static void shutdown_ssl_locking(void)
{
	int num_locks, i;

	num_locks = CRYPTO_num_locks();
	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < num_locks; ++i)
		git3_mutex_free(&openssl_locks[i]);
	git3__free(openssl_locks);
}

static void threadid_cb(CRYPTO_THREADID *threadid)
{
	GIT3_UNUSED(threadid);
	CRYPTO_THREADID_set_numeric(threadid, git3_thread_currentid());
}

int git3_openssl_set_locking(void)
{
	int num_locks, i;

#ifndef GIT3_THREADS
	git3_error_set(GIT3_ERROR_THREAD, "libgit3 was not built with threads");
	return -1;
#endif

#ifdef GIT3_HTTPS_OPENSSL_DYNAMIC
	/*
	 * This function is required on legacy versions of OpenSSL; when building
	 * with dynamically-loaded OpenSSL, we detect whether we loaded it or not.
	 */
	if (!CRYPTO_set_locking_callback)
		return 0;
#endif

	CRYPTO_THREADID_set_callback(threadid_cb);

	num_locks = CRYPTO_num_locks();
	openssl_locks = git3__calloc(num_locks, sizeof(git3_mutex));
	GIT3_ERROR_CHECK_ALLOC(openssl_locks);

	for (i = 0; i < num_locks; i++) {
		if (git3_mutex_init(&openssl_locks[i]) != 0) {
			git3_error_set(GIT3_ERROR_SSL, "failed to initialize openssl locks");
			return -1;
		}
	}

	CRYPTO_set_locking_callback(openssl_locking_function);
	return git3_runtime_shutdown_register(shutdown_ssl_locking);
}
#endif /* GIT3_THREADS */

#endif /* GIT3_HTTPS_OPENSSL_LEGACY || GIT3_HTTPS_OPENSSL_DYNAMIC */
