/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_streams_registry_h__
#define INCLUDE_streams_registry_h__

#include "common.h"
#include "git3/sys/stream.h"

/** Configure stream registry. */
int git3_stream_registry_global_init(void);

/** Lookup a stream registration. */
extern int git3_stream_registry_lookup(git3_stream_registration *out, git3_stream_t type);

#endif
