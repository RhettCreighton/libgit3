/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3/types.h"
#include "git3/remote.h"
#include "git3/net.h"
#include "git3/transport.h"
#include "git3/sys/transport.h"
#include "fs_path.h"

typedef struct transport_definition {
	char *prefix;
	git3_transport_cb fn;
	void *param;
} transport_definition;

static git3_smart_subtransport_definition http_subtransport_definition = { git3_smart_subtransport_http, 1, NULL };
static git3_smart_subtransport_definition git3_subtransport_definition = { git3_smart_subtransport_git, 0, NULL };

#ifdef GIT3_SSH
static git3_smart_subtransport_definition ssh_subtransport_definition = { git3_smart_subtransport_ssh, 0, NULL };
#endif

static transport_definition local_transport_definition = { "file://", git3_transport_local, NULL };

static transport_definition transports[] = {
	{ "git://",   git3_transport_smart, &git3_subtransport_definition },
	{ "http://",  git3_transport_smart, &http_subtransport_definition },
	{ "https://", git3_transport_smart, &http_subtransport_definition },
	{ "file://",  git3_transport_local, NULL },

#ifdef GIT3_SSH
	{ "ssh://",   git3_transport_smart, &ssh_subtransport_definition },
	{ "ssh+git://",   git3_transport_smart, &ssh_subtransport_definition },
	{ "git+ssh://",   git3_transport_smart, &ssh_subtransport_definition },
#endif

	{ NULL, 0, 0 }
};

static git3_vector custom_transports = GIT3_VECTOR_INIT;

#define GIT3_TRANSPORT_COUNT (sizeof(transports)/sizeof(transports[0])) - 1

static transport_definition * transport_find_by_url(const char *url)
{
	size_t i = 0;
	transport_definition *d;

	/* Find a user transport who wants to deal with this URI */
	git3_vector_foreach(&custom_transports, i, d) {
		if (strncasecmp(url, d->prefix, strlen(d->prefix)) == 0) {
			return d;
		}
	}

	/* Find a system transport for this URI */
	for (i = 0; i < GIT3_TRANSPORT_COUNT; ++i) {
		d = &transports[i];

		if (strncasecmp(url, d->prefix, strlen(d->prefix)) == 0) {
			return d;
		}
	}

	return NULL;
}

static int transport_find_fn(
	git3_transport_cb *out,
	const char *url,
	void **param)
{
	transport_definition *definition = transport_find_by_url(url);

#ifdef GIT3_WIN32
	/* On Windows, it might not be possible to discern between absolute local
	 * and ssh paths - first check if this is a valid local path that points
	 * to a directory and if so assume local path, else assume SSH */

	/* Check to see if the path points to a file on the local file system */
	if (!definition && git3_fs_path_exists(url) && git3_fs_path_isdir(url))
		definition = &local_transport_definition;
#endif

	/* For other systems, perform the SSH check first, to avoid going to the
	 * filesystem if it is not necessary */

	/* It could be a SSH remote path. Check to see if there's a : */
	if (!definition && strrchr(url, ':')) {
		/* re-search transports again with ssh:// as url
		 * so that we can find a third party ssh transport */
		definition = transport_find_by_url("ssh://");
	}

#ifndef GIT3_WIN32
	/* Check to see if the path points to a file on the local file system */
	if (!definition && git3_fs_path_exists(url) && git3_fs_path_isdir(url))
		definition = &local_transport_definition;
#endif

	if (!definition)
		return GIT3_ENOTFOUND;

	*out = definition->fn;
	*param = definition->param;

	return 0;
}

/**************
 * Public API *
 **************/

int git3_transport_new(git3_transport **out, git3_remote *owner, const char *url)
{
	git3_transport_cb fn;
	git3_transport *transport;
	void *param;
	int error;

	if ((error = transport_find_fn(&fn, url, &param)) == GIT3_ENOTFOUND) {
		git3_error_set(GIT3_ERROR_NET, "unsupported URL protocol");
		return -1;
	} else if (error < 0)
		return error;

	if ((error = fn(&transport, owner, param)) < 0)
		return error;

	GIT3_ERROR_CHECK_VERSION(transport, GIT3_TRANSPORT_VERSION, "git3_transport");

	*out = transport;

	return 0;
}

int git3_transport_register(
	const char *scheme,
	git3_transport_cb cb,
	void *param)
{
	git3_str prefix = GIT3_STR_INIT;
	transport_definition *d, *definition = NULL;
	size_t i;
	int error = 0;

	GIT3_ASSERT_ARG(scheme);
	GIT3_ASSERT_ARG(cb);

	if ((error = git3_str_printf(&prefix, "%s://", scheme)) < 0)
		goto on_error;

	git3_vector_foreach(&custom_transports, i, d) {
		if (strcasecmp(d->prefix, prefix.ptr) == 0) {
			error = GIT3_EEXISTS;
			goto on_error;
		}
	}

	definition = git3__calloc(1, sizeof(transport_definition));
	GIT3_ERROR_CHECK_ALLOC(definition);

	definition->prefix = git3_str_detach(&prefix);
	definition->fn = cb;
	definition->param = param;

	if (git3_vector_insert(&custom_transports, definition) < 0)
		goto on_error;

	return 0;

on_error:
	git3_str_dispose(&prefix);
	git3__free(definition);
	return error;
}

int git3_transport_unregister(const char *scheme)
{
	git3_str prefix = GIT3_STR_INIT;
	transport_definition *d;
	size_t i;
	int error = 0;

	GIT3_ASSERT_ARG(scheme);

	if ((error = git3_str_printf(&prefix, "%s://", scheme)) < 0)
		goto done;

	git3_vector_foreach(&custom_transports, i, d) {
		if (strcasecmp(d->prefix, prefix.ptr) == 0) {
			if ((error = git3_vector_remove(&custom_transports, i)) < 0)
				goto done;

			git3__free(d->prefix);
			git3__free(d);

			if (!custom_transports.length)
				git3_vector_dispose(&custom_transports);

			error = 0;
			goto done;
		}
	}

	error = GIT3_ENOTFOUND;

done:
	git3_str_dispose(&prefix);
	return error;
}

int git3_transport_init(git3_transport *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_transport, GIT3_TRANSPORT_INIT);
	return 0;
}
