/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_streams_socket_h__
#define INCLUDE_streams_socket_h__

#include "common.h"

#include "stream.h"

typedef struct {
	git3_stream parent;
	char *host;
	char *port;
	GIT3_SOCKET s;
} git3_socket_stream;

extern int git3_socket_stream_new(git3_stream **out, const char *host, const char *port);

extern int git3_socket_stream_global_init(void);

#endif
