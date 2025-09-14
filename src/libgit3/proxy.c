/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "proxy.h"

#include "git3/proxy.h"

int git3_proxy_options_init(git3_proxy_options *opts, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		opts, version, git3_proxy_options, GIT3_PROXY_OPTIONS_INIT);
	return 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_proxy_init_options(git3_proxy_options *opts, unsigned int version)
{
	return git3_proxy_options_init(opts, version);
}
#endif

int git3_proxy_options_dup(git3_proxy_options *tgt, const git3_proxy_options *src)
{
	if (!src) {
		git3_proxy_options_init(tgt, GIT3_PROXY_OPTIONS_VERSION);
		return 0;
	}

	memcpy(tgt, src, sizeof(git3_proxy_options));
	if (src->url) {
		tgt->url = git3__strdup(src->url);
		GIT3_ERROR_CHECK_ALLOC(tgt->url);
	}

	return 0;
}

void git3_proxy_options_dispose(git3_proxy_options *opts)
{
	if (!opts)
		return;

	git3__free((char *) opts->url);
	opts->url = NULL;
}
