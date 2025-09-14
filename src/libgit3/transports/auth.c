/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "auth.h"

#include "git3/sys/credential.h"

static int basic_next_token(
	git3_str *out,
	git3_http_auth_context *ctx,
	git3_credential *c)
{
	git3_credential_userpass_plaintext *cred;
	git3_str raw = GIT3_STR_INIT;
	int error = GIT3_EAUTH;

	GIT3_UNUSED(ctx);

	if (c->credtype != GIT3_CREDENTIAL_USERPASS_PLAINTEXT) {
		git3_error_set(GIT3_ERROR_INVALID, "invalid credential type for basic auth");
		goto on_error;
	}

	cred = (git3_credential_userpass_plaintext *)c;

	git3_str_printf(&raw, "%s:%s", cred->username, cred->password);

	if (git3_str_oom(&raw) ||
		git3_str_puts(out, "Basic ") < 0 ||
		git3_str_encode_base64(out, git3_str_cstr(&raw), raw.size) < 0)
		goto on_error;

	error = 0;

on_error:
	if (raw.size)
		git3__memzero(raw.ptr, raw.size);

	git3_str_dispose(&raw);
	return error;
}

static git3_http_auth_context basic_context = {
	GIT3_HTTP_AUTH_BASIC,
	GIT3_CREDENTIAL_USERPASS_PLAINTEXT,
	0,
	NULL,
	basic_next_token,
	NULL,
	NULL
};

int git3_http_auth_basic(
	git3_http_auth_context **out, const git3_net_url *url)
{
	GIT3_UNUSED(url);

	*out = &basic_context;
	return 0;
}

int git3_http_auth_dummy(
	git3_http_auth_context **out, const git3_net_url *url)
{
	GIT3_UNUSED(url);

	*out = NULL;
	return GIT3_PASSTHROUGH;
}

