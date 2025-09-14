/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "streams/registry.h"

#include "runtime.h"
#include "streams/tls.h"
#include "streams/mbedtls.h"
#include "streams/openssl.h"
#include "streams/stransport.h"

struct stream_registry {
	git3_rwlock lock;
	git3_stream_registration callbacks;
	git3_stream_registration tls_callbacks;
};

static struct stream_registry stream_registry;

static void shutdown_stream_registry(void)
{
	git3_rwlock_free(&stream_registry.lock);
}

int git3_stream_registry_global_init(void)
{
	if (git3_rwlock_init(&stream_registry.lock) < 0)
		return -1;

	return git3_runtime_shutdown_register(shutdown_stream_registry);
}

GIT3_INLINE(void) stream_registration_cpy(
	git3_stream_registration *target,
	git3_stream_registration *src)
{
	if (src)
		memcpy(target, src, sizeof(git3_stream_registration));
	else
		memset(target, 0, sizeof(git3_stream_registration));
}

int git3_stream_registry_lookup(git3_stream_registration *out, git3_stream_t type)
{
	git3_stream_registration *target;
	int error = GIT3_ENOTFOUND;

	GIT3_ASSERT_ARG(out);

	switch(type) {
	case GIT3_STREAM_STANDARD:
		target = &stream_registry.callbacks;
		break;
	case GIT3_STREAM_TLS:
		target = &stream_registry.tls_callbacks;
		break;
	default:
		git3_error_set(GIT3_ERROR_INVALID, "invalid stream type");
		return -1;
	}

	if (git3_rwlock_rdlock(&stream_registry.lock) < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to lock stream registry");
		return -1;
	}

	if (target->init) {
		stream_registration_cpy(out, target);
		error = 0;
	}

	git3_rwlock_rdunlock(&stream_registry.lock);
	return error;
}

int git3_stream_register(git3_stream_t type, git3_stream_registration *registration)
{
	GIT3_ASSERT(!registration || registration->init);

	GIT3_ERROR_CHECK_VERSION(registration, GIT3_STREAM_VERSION, "stream_registration");

	if (git3_rwlock_wrlock(&stream_registry.lock) < 0) {
		git3_error_set(GIT3_ERROR_OS, "failed to lock stream registry");
		return -1;
	}

	if ((type & GIT3_STREAM_STANDARD) == GIT3_STREAM_STANDARD)
		stream_registration_cpy(&stream_registry.callbacks, registration);

	if ((type & GIT3_STREAM_TLS) == GIT3_STREAM_TLS)
		stream_registration_cpy(&stream_registry.tls_callbacks, registration);

	git3_rwlock_wrunlock(&stream_registry.lock);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_stream_register_tls(
	int GIT3_CALLBACK(ctor)(git3_stream **out, const char *host, const char *port))
{
	git3_stream_registration registration = {0};

	if (ctor) {
		registration.version = GIT3_STREAM_VERSION;
		registration.init = ctor;
		registration.wrap = NULL;

		return git3_stream_register(GIT3_STREAM_TLS, &registration);
	} else {
		return git3_stream_register(GIT3_STREAM_TLS, NULL);
	}
}
#endif
