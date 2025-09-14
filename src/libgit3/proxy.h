/*
* Copyright (C) the libgit3 contributors. All rights reserved.
*
* This file is part of libgit3, distributed under the GNU GPL v2 with
* a Linking Exception. For full terms see the included COPYING file.
*/
#ifndef INCLUDE_proxy_h__
#define INCLUDE_proxy_h__

#include "common.h"

#include "git3/proxy.h"

extern int git3_proxy_options_dup(git3_proxy_options *tgt, const git3_proxy_options *src);
extern void git3_proxy_options_dispose(git3_proxy_options *opts);

#endif
