/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_sys_git_stream_h__
#define INCLUDE_sys_git_stream_h__

#include "git3/common.h"
#include "git3/types.h"
#include "git3/proxy.h"

/**
 * @file git3/sys/stream.h
 * @brief Streaming file I/O functionality
 * @defgroup git3_stream Streaming file I/O functionality
 * @ingroup Git
 * @{
 */
GIT3_BEGIN_DECL

/** Current version for the `git3_stream` structures */
#define GIT3_STREAM_VERSION 1

/**
 * Every stream must have this struct as its first element, so the
 * API can talk to it. You'd define your stream as
 *
 *     struct my_stream {
 *             git3_stream parent;
 *             ...
 *     }
 *
 * and fill the functions
 */
typedef struct git3_stream {
	int version;

	unsigned int encrypted : 1,
	             proxy_support : 1;

	/**
	 * Timeout for read and write operations; can be set to `0` to
	 * block indefinitely.
	 */
	int timeout;

	/**
	 * Timeout to connect to the remote server; can be set to `0`
	 * to use the system defaults. This can be shorter than the
	 * system default - often 75 seconds - but cannot be longer.
	 */
	int connect_timeout;

	int GIT3_CALLBACK(connect)(struct git3_stream *);
	int GIT3_CALLBACK(certificate)(git3_cert **, struct git3_stream *);
	int GIT3_CALLBACK(set_proxy)(struct git3_stream *, const git3_proxy_options *proxy_opts);
	ssize_t GIT3_CALLBACK(read)(struct git3_stream *, void *, size_t);
	ssize_t GIT3_CALLBACK(write)(struct git3_stream *, const char *, size_t, int);
	int GIT3_CALLBACK(close)(struct git3_stream *);
	void GIT3_CALLBACK(free)(struct git3_stream *);
} git3_stream;

typedef struct {
	/** The `version` field should be set to `GIT3_STREAM_VERSION`. */
	int version;

	/**
	 * Called to create a new connection to a given host.
	 *
	 * @param out The created stream
	 * @param host The hostname to connect to; may be a hostname or
	 *             IP address
	 * @param port The port to connect to; may be a port number or
	 *             service name
	 * @return 0 or an error code
	 */
	int GIT3_CALLBACK(init)(git3_stream **out, const char *host, const char *port);

	/**
	 * Called to create a new connection on top of the given stream.  If
	 * this is a TLS stream, then this function may be used to proxy a
	 * TLS stream over an HTTP CONNECT session.  If this is unset, then
	 * HTTP CONNECT proxies will not be supported.
	 *
	 * @param out The created stream
	 * @param in An existing stream to add TLS to
	 * @param host The hostname that the stream is connected to,
	 *             for certificate validation
	 * @return 0 or an error code
	 */
	int GIT3_CALLBACK(wrap)(git3_stream **out, git3_stream *in, const char *host);
} git3_stream_registration;

/**
 * The type of stream to register.
 */
typedef enum {
	/** A standard (non-TLS) socket. */
	GIT3_STREAM_STANDARD = 1,

	/** A TLS-encrypted socket. */
	GIT3_STREAM_TLS = 2
} git3_stream_t;

/**
 * Register stream constructors for the library to use
 *
 * If a registration structure is already set, it will be overwritten.
 * Pass `NULL` in order to deregister the current constructor and return
 * to the system defaults.
 *
 * The type parameter may be a bitwise AND of types.
 *
 * @param type the type or types of stream to register
 * @param registration the registration data
 * @return 0 or an error code
 */
GIT3_EXTERN(int) git3_stream_register(
	git3_stream_t type, git3_stream_registration *registration);

#ifndef GIT3_DEPRECATE_HARD

/** @name Deprecated TLS Stream Registration Functions
 *
 * These functions are retained for backward compatibility.  The newer
 * versions of these values should be preferred in all new code.
 *
 * There is no plan to remove these backward compatibility values at
 * this time.
 */
/**@{*/

/**
 * @deprecated Provide a git3_stream_registration to git3_stream_register
 * @see git3_stream_registration
 */
typedef int GIT3_CALLBACK(git3_stream_cb)(git3_stream **out, const char *host, const char *port);

/**
 * Register a TLS stream constructor for the library to use.  This stream
 * will not support HTTP CONNECT proxies.  This internally calls
 * `git3_stream_register` and is preserved for backward compatibility.
 *
 * This function is deprecated, but there is no plan to remove this
 * function at this time.
 *
 * @deprecated Provide a git3_stream_registration to git3_stream_register
 * @see git3_stream_register
 */
GIT3_EXTERN(int) git3_stream_register_tls(git3_stream_cb ctor);

/**@}*/

#endif

/**@}*/
GIT3_END_DECL

#endif
