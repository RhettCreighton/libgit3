/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "smart.h"

#include "git3.h"
#include "git3/sys/remote.h"
#include "refs.h"
#include "refspec.h"
#include "proxy.h"

int git3_smart__recv(transport_smart *t)
{
	size_t bytes_read;
	int ret;

	GIT3_ASSERT_ARG(t);
	GIT3_ASSERT(t->current_stream);

	if (git3_staticstr_remain(&t->buffer) == 0) {
		git3_error_set(GIT3_ERROR_NET, "out of buffer space");
		return -1;
	}

	ret = t->current_stream->read(t->current_stream,
		git3_staticstr_offset(&t->buffer),
		git3_staticstr_remain(&t->buffer),
		&bytes_read);

	if (ret < 0)
		return ret;

	GIT3_ASSERT(bytes_read <= INT_MAX);
	GIT3_ASSERT(bytes_read <= git3_staticstr_remain(&t->buffer));

	git3_staticstr_increase(&t->buffer, bytes_read);

	if (t->packetsize_cb && !t->cancelled.val) {
		ret = t->packetsize_cb(bytes_read, t->packetsize_payload);

		if (ret) {
			git3_atomic32_set(&t->cancelled, 1);
			return GIT3_EUSER;
		}
	}

	return (int)bytes_read;
}

GIT3_INLINE(int) git3_smart__reset_stream(transport_smart *t, bool close_subtransport)
{
	if (t->current_stream) {
		t->current_stream->free(t->current_stream);
		t->current_stream = NULL;
	}

	if (close_subtransport) {
		git3__free(t->url);
		t->url = NULL;

		if (t->wrapped->close(t->wrapped) < 0)
			return -1;
	}

	git3__free(t->caps.object_format);
	t->caps.object_format = NULL;

	git3__free(t->caps.agent);
	t->caps.agent = NULL;

	return 0;
}

int git3_smart__update_heads(transport_smart *t, git3_vector *symrefs)
{
	size_t i;
	git3_pkt *pkt;

	git3_vector_clear(&t->heads);
	git3_vector_foreach(&t->refs, i, pkt) {
		git3_pkt_ref *ref = (git3_pkt_ref *) pkt;
		if (pkt->type != GIT3_PKT_REF)
			continue;

		if (symrefs) {
			git3_refspec *spec;
			git3_str buf = GIT3_STR_INIT;
			size_t j;
			int error = 0;

			git3_vector_foreach(symrefs, j, spec) {
				git3_str_clear(&buf);
				if (git3_refspec_src_matches(spec, ref->head.name) &&
				    !(error = git3_refspec__transform(&buf, spec, ref->head.name))) {
					git3__free(ref->head.symref_target);
					ref->head.symref_target = git3_str_detach(&buf);
				}
			}

			git3_str_dispose(&buf);

			if (error < 0)
				return error;
		}

		if (git3_vector_insert(&t->heads, &ref->head) < 0)
			return -1;
	}

	return 0;
}

static void free_symrefs(git3_vector *symrefs)
{
	git3_refspec *spec;
	size_t i;

	git3_vector_foreach(symrefs, i, spec) {
		git3_refspec__dispose(spec);
		git3__free(spec);
	}

	git3_vector_dispose(symrefs);
}

static int git3_smart__connect(
	git3_transport *transport,
	const char *url,
	int direction,
	const git3_remote_connect_options *connect_opts)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);
	git3_smart_subtransport_stream *stream;
	int error;
	git3_pkt *pkt;
	git3_pkt_ref *first;
	git3_vector symrefs;
	git3_smart_service_t service;

	if (git3_smart__reset_stream(t, true) < 0)
		return -1;

	if (git3_remote_connect_options_normalize(&t->connect_opts, t->owner->repo, connect_opts) < 0)
		return -1;

	t->url = git3__strdup(url);
	GIT3_ERROR_CHECK_ALLOC(t->url);

	t->direction = direction;

	if (GIT3_DIRECTION_FETCH == t->direction) {
		service = GIT3_SERVICE_UPLOADPACK_LS;
	} else if (GIT3_DIRECTION_PUSH == t->direction) {
		service = GIT3_SERVICE_RECEIVEPACK_LS;
	} else {
		git3_error_set(GIT3_ERROR_NET, "invalid direction");
		return -1;
	}

	if ((error = t->wrapped->action(&stream, t->wrapped, t->url, service)) < 0)
		return error;

	/* Save off the current stream (i.e. socket) that we are working with */
	t->current_stream = stream;

	/* 2 flushes for RPC; 1 for stateful */
	if ((error = git3_smart__store_refs(t, t->rpc ? 2 : 1)) < 0)
		return error;

	/* Strip the comment packet for RPC */
	if (t->rpc) {
		pkt = (git3_pkt *)git3_vector_get(&t->refs, 0);

		if (!pkt || GIT3_PKT_COMMENT != pkt->type) {
			git3_error_set(GIT3_ERROR_NET, "invalid response");
			return -1;
		} else {
			/* Remove the comment pkt from the list */
			git3_vector_remove(&t->refs, 0);
			git3__free(pkt);
		}
	}

	/* We now have loaded the refs. */
	t->have_refs = 1;

	pkt = (git3_pkt *)git3_vector_get(&t->refs, 0);
	if (pkt && GIT3_PKT_REF != pkt->type) {
		git3_error_set(GIT3_ERROR_NET, "invalid response");
		return -1;
	}
	first = (git3_pkt_ref *)pkt;

	if ((error = git3_vector_init(&symrefs, 1, NULL)) < 0)
		return error;

	/* Detect capabilities */
	if ((error = git3_smart__detect_caps(first, &t->caps, &symrefs)) == 0) {
		/* If the only ref in the list is capabilities^{} with OID_ZERO, remove it */
		if (1 == t->refs.length && !strcmp(first->head.name, "capabilities^{}") &&
			git3_oid_is_zero(&first->head.oid)) {
			git3_vector_clear(&t->refs);
			git3_pkt_free((git3_pkt *)first);
		}

		/* Keep a list of heads for _ls */
		git3_smart__update_heads(t, &symrefs);
	} else if (error == GIT3_ENOTFOUND) {
		/* There was no ref packet received, or the cap list was empty */
		error = 0;
	} else {
		git3_error_set(GIT3_ERROR_NET, "invalid response");
		goto cleanup;
	}

	if (t->rpc && (error = git3_smart__reset_stream(t, false)) < 0)
		goto cleanup;

	/* We're now logically connected. */
	t->connected = 1;

cleanup:
	free_symrefs(&symrefs);

	return error;
}

static int git3_smart__set_connect_opts(
	git3_transport *transport,
	const git3_remote_connect_options *opts)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);

	if (!t->connected) {
		git3_error_set(GIT3_ERROR_NET, "cannot reconfigure a transport that is not connected");
		return -1;
	}

	return git3_remote_connect_options_normalize(&t->connect_opts, t->owner->repo, opts);
}

static int git3_smart__capabilities(unsigned int *capabilities, git3_transport *transport)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);

	*capabilities = 0;

	if (t->caps.push_options)
		*capabilities |= GIT3_REMOTE_CAPABILITY_PUSH_OPTIONS;

	if (t->caps.want_tip_sha1)
		*capabilities |= GIT3_REMOTE_CAPABILITY_TIP_OID;

	if (t->caps.want_reachable_sha1)
		*capabilities |= GIT3_REMOTE_CAPABILITY_REACHABLE_OID;

	return 0;
}

#ifdef GIT3_EXPERIMENTAL_SHA256
static int git3_smart__oid_type(git3_oid_t *out, git3_transport *transport)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);

	*out = 0;

	if (t->caps.object_format == NULL) {
		*out = GIT3_OID_DEFAULT;
	} else {
		*out = git3_oid_type_fromstr(t->caps.object_format);

		if (!*out) {
			git3_error_set(GIT3_ERROR_INVALID,
				"unknown object format '%s'",
				t->caps.object_format);
			return -1;
		}
	}

	return 0;
}
#endif

static int git3_smart__ls(const git3_remote_head ***out, size_t *size, git3_transport *transport)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);

	if (!t->have_refs) {
		git3_error_set(GIT3_ERROR_NET, "the transport has not yet loaded the refs");
		return -1;
	}

	*out = (const git3_remote_head **) t->heads.contents;
	*size = t->heads.length;

	return 0;
}

int git3_smart__negotiation_step(git3_transport *transport, void *data, size_t len)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);
	git3_smart_subtransport_stream *stream;
	int error;

	if (t->rpc && git3_smart__reset_stream(t, false) < 0)
		return -1;

	if (GIT3_DIRECTION_FETCH != t->direction) {
		git3_error_set(GIT3_ERROR_NET, "this operation is only valid for fetch");
		return -1;
	}

	if ((error = t->wrapped->action(&stream, t->wrapped, t->url, GIT3_SERVICE_UPLOADPACK)) < 0)
		return error;

	/* If this is a stateful implementation, the stream we get back should be the same */
	GIT3_ASSERT(t->rpc || t->current_stream == stream);

	/* Save off the current stream (i.e. socket) that we are working with */
	t->current_stream = stream;

	if ((error = stream->write(stream, (const char *)data, len)) < 0)
		return error;

	return 0;
}

int git3_smart__get_push_stream(transport_smart *t, git3_smart_subtransport_stream **stream)
{
	int error;

	if (t->rpc && git3_smart__reset_stream(t, false) < 0)
		return -1;

	if (GIT3_DIRECTION_PUSH != t->direction) {
		git3_error_set(GIT3_ERROR_NET, "this operation is only valid for push");
		return -1;
	}

	if ((error = t->wrapped->action(stream, t->wrapped, t->url, GIT3_SERVICE_RECEIVEPACK)) < 0)
		return error;

	/* If this is a stateful implementation, the stream we get back should be the same */
	GIT3_ASSERT(t->rpc || t->current_stream == *stream);

	/* Save off the current stream (i.e. socket) that we are working with */
	t->current_stream = *stream;

	return 0;
}

static void git3_smart__cancel(git3_transport *transport)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);

	git3_atomic32_set(&t->cancelled, 1);
}

static int git3_smart__is_connected(git3_transport *transport)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);

	return t->connected;
}

static int git3_smart__close(git3_transport *transport)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);
	git3_vector *common = &t->common;
	unsigned int i;
	git3_pkt *p;
	git3_smart_service_t service;
	int ret;
	git3_smart_subtransport_stream *stream;
	const char flush[] = "0000";

	if (t->direction == GIT3_DIRECTION_FETCH) {
		service = GIT3_SERVICE_UPLOADPACK;
	} else if (t->direction == GIT3_DIRECTION_PUSH) {
		service = GIT3_SERVICE_RECEIVEPACK;
	} else {
		git3_error_set(GIT3_ERROR_NET, "invalid direction");
		return -1;
	}

	/*
	 * If we're still connected at this point and not using RPC,
	 * we should say goodbye by sending a flush, or git-daemon
	 * will complain that we disconnected unexpectedly.
	 */
	if (t->connected && !t->rpc &&
	    !t->wrapped->action(&stream, t->wrapped, t->url, service)) {
		t->current_stream->write(t->current_stream, flush, 4);
	}

	ret = git3_smart__reset_stream(t, true);

	git3_vector_foreach(common, i, p)
		git3_pkt_free(p);

	git3_vector_dispose(common);

	if (t->url) {
		git3__free(t->url);
		t->url = NULL;
	}

	t->connected = 0;

	return ret;
}

static void git3_smart__free(git3_transport *transport)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);
	git3_vector *refs = &t->refs;
	unsigned int i;
	git3_pkt *p;

	/* Make sure that the current stream is closed, if we have one. */
	git3_smart__close(transport);

	/* Free the subtransport */
	t->wrapped->free(t->wrapped);

	git3_vector_dispose(&t->heads);
	git3_vector_foreach(refs, i, p)
		git3_pkt_free(p);

	git3_vector_dispose(refs);

	git3_remote_connect_options_dispose(&t->connect_opts);

	git3_array_dispose(t->shallow_roots);

	git3__free(t->caps.object_format);
	git3__free(t->caps.agent);
	git3__free(t);
}

static int ref_name_cmp(const void *a, const void *b)
{
	const git3_pkt_ref *ref_a = a, *ref_b = b;

	return strcmp(ref_a->head.name, ref_b->head.name);
}

int git3_transport_smart_certificate_check(git3_transport *transport, git3_cert *cert, int valid, const char *hostname)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);
	git3_remote_connect_options *connect_opts = &t->connect_opts;

	GIT3_ASSERT_ARG(transport);
	GIT3_ASSERT_ARG(cert);
	GIT3_ASSERT_ARG(hostname);

	if (!connect_opts->callbacks.certificate_check)
		return GIT3_PASSTHROUGH;

	return connect_opts->callbacks.certificate_check(cert, valid, hostname, connect_opts->callbacks.payload);
}

int git3_transport_smart_credentials(git3_credential **out, git3_transport *transport, const char *user, int methods)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);
	git3_remote_connect_options *connect_opts = &t->connect_opts;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(transport);

	if (!connect_opts->callbacks.credentials)
		return GIT3_PASSTHROUGH;

	return connect_opts->callbacks.credentials(out, t->url, user, methods, connect_opts->callbacks.payload);
}

int git3_transport_remote_connect_options(
		git3_remote_connect_options *out,
		git3_transport *transport)
{
	transport_smart *t = GIT3_CONTAINER_OF(transport, transport_smart, parent);

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(transport);

	return git3_remote_connect_options_dup(out, &t->connect_opts);
}

int git3_transport_smart(git3_transport **out, git3_remote *owner, void *param)
{
	transport_smart *t;
	git3_smart_subtransport_definition *definition = (git3_smart_subtransport_definition *)param;

	if (!param)
		return -1;

	t = git3__calloc(1, sizeof(transport_smart));
	GIT3_ERROR_CHECK_ALLOC(t);

	t->parent.version = GIT3_TRANSPORT_VERSION;
	t->parent.connect = git3_smart__connect;
	t->parent.set_connect_opts = git3_smart__set_connect_opts;
	t->parent.capabilities = git3_smart__capabilities;
#ifdef GIT3_EXPERIMENTAL_SHA256
	t->parent.oid_type = git3_smart__oid_type;
#endif
	t->parent.close = git3_smart__close;
	t->parent.free = git3_smart__free;
	t->parent.negotiate_fetch = git3_smart__negotiate_fetch;
	t->parent.shallow_roots = git3_smart__shallow_roots;
	t->parent.download_pack = git3_smart__download_pack;
	t->parent.push = git3_smart__push;
	t->parent.ls = git3_smart__ls;
	t->parent.is_connected = git3_smart__is_connected;
	t->parent.cancel = git3_smart__cancel;

	t->owner = owner;
	t->rpc = definition->rpc;

	if (git3_vector_init(&t->refs, 16, ref_name_cmp) < 0 ||
	    git3_vector_init(&t->heads, 16, ref_name_cmp) < 0 ||
	    definition->callback(&t->wrapped, &t->parent, definition->param) < 0) {
		git3_vector_dispose(&t->refs);
		git3_vector_dispose(&t->heads);
		git3__free(t);
		return -1;
	}

	git3_staticstr_init(&t->buffer, GIT3_SMART_BUFFER_SIZE);

	*out = (git3_transport *) t;
	return 0;
}
