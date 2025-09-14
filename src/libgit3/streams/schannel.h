/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_steams_schannel_h__
#define INCLUDE_steams_schannel_h__

#include "common.h"

#include "git3/sys/stream.h"

#ifdef GIT3_HTTPS_SCHANNEL

extern int git3_schannel_stream_new(
	git3_stream **out,
	const char *host,
	const char *port);

extern int git3_schannel_stream_wrap(
	git3_stream **out,
	git3_stream *in,
	const char *host);

#endif

#endif
