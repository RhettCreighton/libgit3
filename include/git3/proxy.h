/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_proxy_h__
#define INCLUDE_git_proxy_h__

#include "common.h"

#include "cert.h"
#include "credential.h"

/**
 * @file git3/proxy.h
 * @brief TLS proxies
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/**
 * The type of proxy to use.
 */
typedef enum {
	/**
	 * Do not attempt to connect through a proxy
	 *
	 * If built against libcurl, it itself may attempt to connect
	 * to a proxy if the environment variables specify it.
	 */
	GIT3_PROXY_NONE,
	/**
	 * Try to auto-detect the proxy from the git configuration.
	 */
	GIT3_PROXY_AUTO,
	/**
	 * Connect via the URL given in the options
	 */
	GIT3_PROXY_SPECIFIED
} git3_proxy_t;

/**
 * Options for connecting through a proxy
 *
 * Note that not all types may be supported, depending on the platform
 * and compilation options.
 */
typedef struct {
	unsigned int version;

	/**
	 * The type of proxy to use, by URL, auto-detect.
	 */
	git3_proxy_t type;

	/**
	 * The URL of the proxy.
	 */
	const char *url;

	/**
	 * This will be called if the remote host requires
	 * authentication in order to connect to it.
	 *
	 * Returning GIT3_PASSTHROUGH will make libgit3 behave as
	 * though this field isn't set.
	 */
	git3_credential_acquire_cb credentials;

	/**
	 * If cert verification fails, this will be called to let the
	 * user make the final decision of whether to allow the
	 * connection to proceed. Returns 0 to allow the connection
	 * or a negative value to indicate an error.
	 */
	git3_transport_certificate_check_cb certificate_check;

	/**
	 * Payload to be provided to the credentials and certificate
	 * check callbacks.
	 */
	void *payload;
} git3_proxy_options;

/** Current version for the `git3_proxy_options` structure */
#define GIT3_PROXY_OPTIONS_VERSION 1

/** Static constructor for `git3_proxy_options` */
#define GIT3_PROXY_OPTIONS_INIT {GIT3_PROXY_OPTIONS_VERSION}

/**
 * Initialize git3_proxy_options structure
 *
 * Initializes a `git3_proxy_options` with default values. Equivalent to
 * creating an instance with `GIT3_PROXY_OPTIONS_INIT`.
 *
 * @param opts The `git3_proxy_options` struct to initialize.
 * @param version The struct version; pass `GIT3_PROXY_OPTIONS_VERSION`.
 * @return Zero on success; -1 on failure.
 */
GIT3_EXTERN(int) git3_proxy_options_init(git3_proxy_options *opts, unsigned int version);

/** @} */
GIT3_END_DECL

#endif
