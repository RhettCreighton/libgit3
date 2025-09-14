/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef INCLUDE_transports_auth_negotiate_h__
#define INCLUDE_transports_auth_negotiate_h__

#include "common.h"
#include "git3.h"
#include "auth.h"

#ifdef GIT3_AUTH_NEGOTIATE

extern int git3_http_auth_negotiate(
	git3_http_auth_context **out,
	const git3_net_url *url);

#else

#define git3_http_auth_negotiate git3_http_auth_dummy

#endif /* GIT3_AUTH_NEGOTIATE */

#endif
