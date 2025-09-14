/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_remote_h__
#define INCLUDE_remote_h__

#include "common.h"

#include "git3/remote.h"
#include "git3/transport.h"
#include "git3/sys/remote.h"
#include "git3/sys/transport.h"

#include "refspec.h"
#include "vector.h"
#include "net.h"
#include "proxy.h"

#define GIT3_REMOTE_ORIGIN "origin"

struct git3_remote {
	char *name;
	char *url;
	char *pushurl;
	git3_vector refs;
	git3_vector refspecs;
	git3_vector active_refspecs;
	git3_vector passive_refspecs;
	git3_vector local_heads;
	git3_transport *transport;
	git3_repository *repo;
	git3_push *push;
	git3_indexer_progress stats;
	unsigned int need_pack;
	git3_remote_autotag_option_t download_tags;
	int prune_refs;
	int passed_refspecs;
	git3_fetch_negotiation nego;
};

int git3_remote__urlfordirection(git3_str *url_out, struct git3_remote *remote, int direction, const git3_remote_callbacks *callbacks);
int git3_remote__http_proxy(char **out, git3_remote *remote, git3_net_url *url);

git3_refspec *git3_remote__matching_refspec(git3_remote *remote, const char *refname);
git3_refspec *git3_remote__matching_dst_refspec(git3_remote *remote, const char *refname);

int git3_remote__default_branch(git3_str *out, git3_remote *remote);

int git3_remote_connect_options_dup(
	git3_remote_connect_options *dst,
	const git3_remote_connect_options *src);
int git3_remote_connect_options_normalize(
	git3_remote_connect_options *dst,
	git3_repository *repo,
	const git3_remote_connect_options *src);

int git3_remote_capabilities(unsigned int *out, git3_remote *remote);
int git3_remote_oid_type(git3_oid_t *out, git3_remote *remote);


#define git3_remote_connect_options__copy_opts(out, in) \
	if (in) { \
		(out)->callbacks = (in)->callbacks; \
		(out)->proxy_opts = (in)->proxy_opts; \
		(out)->custom_headers = (in)->custom_headers; \
		(out)->follow_redirects = (in)->follow_redirects; \
	}

GIT3_INLINE(int) git3_remote_connect_options__from_fetch_opts(
	git3_remote_connect_options *out,
	git3_remote *remote,
	const git3_fetch_options *fetch_opts)
{
	git3_remote_connect_options tmp = GIT3_REMOTE_CONNECT_OPTIONS_INIT;
	git3_remote_connect_options__copy_opts(&tmp, fetch_opts);
	return git3_remote_connect_options_normalize(out, remote->repo, &tmp);
}

GIT3_INLINE(int) git3_remote_connect_options__from_push_opts(
	git3_remote_connect_options *out,
	git3_remote *remote,
	const git3_push_options *push_opts)
{
	git3_remote_connect_options tmp = GIT3_REMOTE_CONNECT_OPTIONS_INIT;
	git3_remote_connect_options__copy_opts(&tmp, push_opts);
	return git3_remote_connect_options_normalize(out, remote->repo, &tmp);
}

#undef git3_remote_connect_options__copy_opts

GIT3_INLINE(void) git3_remote_connect_options__dispose(
	git3_remote_connect_options *opts)
{
	git3_proxy_options_dispose(&opts->proxy_opts);
	git3_strarray_dispose(&opts->custom_headers);
}

#endif
