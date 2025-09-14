/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_transports_auth_h__
#define INCLUDE_transports_auth_h__

#include "common.h"
#include "net.h"

typedef enum {
	GIT3_HTTP_AUTH_BASIC = 1,
	GIT3_HTTP_AUTH_NEGOTIATE = 2,
	GIT3_HTTP_AUTH_NTLM = 4
} git3_http_auth_t;

typedef struct git3_http_auth_context git3_http_auth_context;

struct git3_http_auth_context {
	/** Type of scheme */
	git3_http_auth_t type;

	/** Supported credentials */
	git3_credential_t credtypes;

	/** Connection affinity or request affinity */
	unsigned connection_affinity : 1;

	/** Sets the challenge on the authentication context */
	int (*set_challenge)(git3_http_auth_context *ctx, const char *challenge);

	/** Gets the next authentication token from the context */
	int (*next_token)(git3_str *out, git3_http_auth_context *ctx, git3_credential *cred);

	/** Examines if all tokens have been presented. */
	int (*is_complete)(git3_http_auth_context *ctx);

	/** Frees the authentication context */
	void (*free)(git3_http_auth_context *ctx);
};

typedef struct {
	/** Type of scheme */
	git3_http_auth_t type;

	/** Name of the scheme (as used in the Authorization header) */
	const char *name;

	/** Credential types this scheme supports */
	git3_credential_t credtypes;

	/** Function to initialize an authentication context */
	int (*init_context)(
		git3_http_auth_context **out,
		const git3_net_url *url);
} git3_http_auth_scheme;

int git3_http_auth_dummy(
	git3_http_auth_context **out,
	const git3_net_url *url);

int git3_http_auth_basic(
	git3_http_auth_context **out,
	const git3_net_url *url);

#endif
