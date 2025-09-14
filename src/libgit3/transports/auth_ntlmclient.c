/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "auth_ntlm.h"

#include "common.h"
#include "str.h"
#include "auth.h"
#include "git3/sys/credential.h"

#ifdef GIT3_AUTH_NTLM_BUILTIN

#include "ntlmclient.h"

typedef struct {
	git3_http_auth_context parent;
	ntlm_client *ntlm;
	char *challenge;
	bool complete;
} http_auth_ntlm_context;

static int ntlmclient_set_challenge(
	git3_http_auth_context *c,
	const char *challenge)
{
	http_auth_ntlm_context *ctx = (http_auth_ntlm_context *)c;

	GIT3_ASSERT_ARG(ctx);
	GIT3_ASSERT_ARG(challenge);

	git3__free(ctx->challenge);

	ctx->challenge = git3__strdup(challenge);
	GIT3_ERROR_CHECK_ALLOC(ctx->challenge);

	return 0;
}

static int ntlmclient_set_credentials(http_auth_ntlm_context *ctx, git3_credential *_cred)
{
	git3_credential_userpass_plaintext *cred;
	const char *sep, *username;
	char *domain = NULL, *domainuser = NULL;
	int error = 0;

	GIT3_ASSERT(_cred->credtype == GIT3_CREDENTIAL_USERPASS_PLAINTEXT);
	cred = (git3_credential_userpass_plaintext *)_cred;

	if ((sep = strchr(cred->username, '\\')) != NULL) {
		domain = git3__strndup(cred->username, (sep - cred->username));
		GIT3_ERROR_CHECK_ALLOC(domain);

		domainuser = git3__strdup(sep + 1);
		GIT3_ERROR_CHECK_ALLOC(domainuser);

		username = domainuser;
	} else {
		username = cred->username;
	}

	if (ntlm_client_set_credentials(ctx->ntlm,
	    username, domain, cred->password) < 0) {
		git3_error_set(GIT3_ERROR_NET, "could not set credentials: %s",
		    ntlm_client_errmsg(ctx->ntlm));
		error = -1;
		goto done;
	}

done:
	git3__free(domain);
	git3__free(domainuser);
	return error;
}

static int ntlmclient_next_token(
	git3_str *buf,
	git3_http_auth_context *c,
	git3_credential *cred)
{
	http_auth_ntlm_context *ctx = (http_auth_ntlm_context *)c;
	git3_str input_buf = GIT3_STR_INIT;
	const unsigned char *msg;
	size_t challenge_len, msg_len;
	int error = GIT3_EAUTH;

	GIT3_ASSERT_ARG(buf);
	GIT3_ASSERT_ARG(ctx);

	GIT3_ASSERT(ctx->ntlm);

	challenge_len = ctx->challenge ? strlen(ctx->challenge) : 0;

	if (ctx->complete)
		ntlm_client_reset(ctx->ntlm);

	/*
	 * Set us complete now since it's the default case; the one
	 * incomplete case (successfully created a client request)
	 * will explicitly set that it requires a second step.
	 */
	ctx->complete = true;

	if (cred && ntlmclient_set_credentials(ctx, cred) != 0)
		goto done;

	if (challenge_len < 4) {
		git3_error_set(GIT3_ERROR_NET, "no ntlm challenge sent from server");
		goto done;
	} else if (challenge_len == 4) {
		if (memcmp(ctx->challenge, "NTLM", 4) != 0) {
			git3_error_set(GIT3_ERROR_NET, "server did not request NTLM");
			goto done;
		}

		if (ntlm_client_negotiate(&msg, &msg_len, ctx->ntlm) != 0) {
			git3_error_set(GIT3_ERROR_NET, "ntlm authentication failed: %s",
				ntlm_client_errmsg(ctx->ntlm));
			goto done;
		}

		ctx->complete = false;
	} else {
		if (memcmp(ctx->challenge, "NTLM ", 5) != 0) {
			git3_error_set(GIT3_ERROR_NET, "challenge from server was not NTLM");
			goto done;
		}

		if (git3_str_decode_base64(&input_buf,
		    ctx->challenge + 5, challenge_len - 5) < 0) {
			git3_error_set(GIT3_ERROR_NET, "invalid NTLM challenge from server");
			goto done;
		}

		if (ntlm_client_set_challenge(ctx->ntlm,
		    (const unsigned char *)input_buf.ptr, input_buf.size) != 0) {
			git3_error_set(GIT3_ERROR_NET, "ntlm challenge failed: %s",
				ntlm_client_errmsg(ctx->ntlm));
			goto done;
		}

		if (ntlm_client_response(&msg, &msg_len, ctx->ntlm) != 0) {
			git3_error_set(GIT3_ERROR_NET, "ntlm authentication failed: %s",
				ntlm_client_errmsg(ctx->ntlm));
			goto done;
		}
	}

	git3_str_puts(buf, "NTLM ");
	git3_str_encode_base64(buf, (const char *)msg, msg_len);

	if (git3_str_oom(buf))
		goto done;

	error = 0;

done:
	git3_str_dispose(&input_buf);
	return error;
}

static int ntlmclient_is_complete(git3_http_auth_context *c)
{
	http_auth_ntlm_context *ctx = (http_auth_ntlm_context *)c;

	GIT3_ASSERT_ARG(ctx);
	return (ctx->complete == true);
}

static void ntlmclient_context_free(git3_http_auth_context *c)
{
	http_auth_ntlm_context *ctx = (http_auth_ntlm_context *)c;

	ntlm_client_free(ctx->ntlm);
	git3__free(ctx->challenge);
	git3__free(ctx);
}

static int ntlmclient_init_context(
	http_auth_ntlm_context *ctx,
	const git3_net_url *url)
{
	GIT3_UNUSED(url);

	if ((ctx->ntlm = ntlm_client_init(NTLM_CLIENT_DEFAULTS)) == NULL) {
		git3_error_set_oom();
		return -1;
	}

	return 0;
}

int git3_http_auth_ntlm(
	git3_http_auth_context **out,
	const git3_net_url *url)
{
	http_auth_ntlm_context *ctx;

	GIT3_UNUSED(url);

	*out = NULL;

	ctx = git3__calloc(1, sizeof(http_auth_ntlm_context));
	GIT3_ERROR_CHECK_ALLOC(ctx);

	if (ntlmclient_init_context(ctx, url) < 0) {
		git3__free(ctx);
		return -1;
	}

	ctx->parent.type = GIT3_HTTP_AUTH_NTLM;
	ctx->parent.credtypes = GIT3_CREDENTIAL_USERPASS_PLAINTEXT;
	ctx->parent.connection_affinity = 1;
	ctx->parent.set_challenge = ntlmclient_set_challenge;
	ctx->parent.next_token = ntlmclient_next_token;
	ctx->parent.is_complete = ntlmclient_is_complete;
	ctx->parent.free = ntlmclient_context_free;

	*out = (git3_http_auth_context *)ctx;

	return 0;
}

#endif /* GIT3_AUTH_NTLM_BUILTIN */
