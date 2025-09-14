/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_transports_auth_ntlm_h__
#define INCLUDE_transports_auth_ntlm_h__

#include "auth.h"

/* NTLM requires a full request/challenge/response */
#define GIT3_AUTH_STEPS_NTLM 2

#if defined(GIT3_AUTH_NTLM)

extern int git3_http_auth_ntlm(
	git3_http_auth_context **out,
	const git3_net_url *url);

#else

#define git3_http_auth_ntlm git3_http_auth_dummy

#endif /* GIT3_AUTH_NTLM */

#endif

