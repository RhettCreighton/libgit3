/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "git3.h"
#include "git3/odb_backend.h"

#include "smart.h"
#include "refs.h"
#include "repository.h"
#include "push.h"
#include "pack-objects.h"
#include "remote.h"
#include "util.h"
#include "revwalk.h"

#define NETWORK_XFER_THRESHOLD (100*1024)
/* The minimal interval between progress updates (in seconds). */
#define MIN_PROGRESS_UPDATE_INTERVAL 0.5

bool git3_smart__ofs_delta_enabled = true;

int git3_smart__store_refs(transport_smart *t, int flushes)
{
	git3_vector *refs = &t->refs;
	int error, flush = 0, recvd;
	const char *line_end = NULL;
	git3_pkt *pkt = NULL;
	git3_pkt_parse_data pkt_parse_data = { 0 };
	size_t i;

	/* Clear existing refs in case git3_remote_connect() is called again
	 * after git3_remote_disconnect().
	 */
	git3_vector_foreach(refs, i, pkt) {
		git3_pkt_free(pkt);
	}
	git3_vector_clear(refs);
	pkt = NULL;

	do {
		if (t->buffer.len > 0)
			error = git3_pkt_parse_line(&pkt, &line_end,
				t->buffer.data, t->buffer.len,
				&pkt_parse_data);
		else
			error = GIT3_EBUFS;

		if (error < 0 && error != GIT3_EBUFS)
			return error;

		if (error == GIT3_EBUFS) {
			if ((recvd = git3_smart__recv(t)) < 0)
				return recvd;

			if (recvd == 0) {
				git3_error_set(GIT3_ERROR_NET, "could not read refs from remote repository");
				return GIT3_EEOF;
			}

			continue;
		}

		git3_staticstr_consume(&t->buffer, line_end);

		if (pkt->type == GIT3_PKT_ERR) {
			git3_error_set(GIT3_ERROR_NET, "remote error: %s", ((git3_pkt_err *)pkt)->error);
			git3__free(pkt);
			return -1;
		}

		if (pkt->type != GIT3_PKT_FLUSH && git3_vector_insert(refs, pkt) < 0)
			return -1;

		if (pkt->type == GIT3_PKT_FLUSH) {
			flush++;
			git3_pkt_free(pkt);
		}
	} while (flush < flushes);

	return flush;
}

static int append_symref(const char **out, git3_vector *symrefs, const char *ptr)
{
	int error;
	const char *end;
	git3_str buf = GIT3_STR_INIT;
	git3_refspec *mapping = NULL;

	ptr += strlen(GIT3_CAP_SYMREF);
	if (*ptr != '=')
		goto on_invalid;

	ptr++;
	if (!(end = strchr(ptr, ' ')) &&
	    !(end = strchr(ptr, '\0')))
		goto on_invalid;

	if ((error = git3_str_put(&buf, ptr, end - ptr)) < 0)
		return error;

	/* symref mapping has refspec format */
	mapping = git3__calloc(1, sizeof(git3_refspec));
	GIT3_ERROR_CHECK_ALLOC(mapping);

	error = git3_refspec__parse(mapping, git3_str_cstr(&buf), true);
	git3_str_dispose(&buf);

	/* if the error isn't OOM, then it's a parse error; let's use a nicer message */
	if (error < 0) {
		if (git3_error_last()->klass != GIT3_ERROR_NOMEMORY)
			goto on_invalid;

		git3__free(mapping);
		return error;
	}

	if ((error = git3_vector_insert(symrefs, mapping)) < 0)
		return error;

	*out = end;
	return 0;

on_invalid:
	git3_error_set(GIT3_ERROR_NET, "remote sent invalid symref");
	git3_refspec__dispose(mapping);
	git3__free(mapping);
	return -1;
}

int git3_smart__detect_caps(
	git3_pkt_ref *pkt,
	transport_smart_caps *caps,
	git3_vector *symrefs)
{
	const char *ptr, *start;

	/* No refs or capabilities, odd but not a problem */
	if (pkt == NULL || pkt->capabilities == NULL)
		return GIT3_ENOTFOUND;

	ptr = pkt->capabilities;
	while (ptr != NULL && *ptr != '\0') {
		if (*ptr == ' ')
			ptr++;

		if (git3_smart__ofs_delta_enabled && !git3__prefixcmp(ptr, GIT3_CAP_OFS_DELTA)) {
			caps->common = caps->ofs_delta = 1;
			ptr += strlen(GIT3_CAP_OFS_DELTA);
			continue;
		}

		/* Keep multi_ack_detailed before multi_ack */
		if (!git3__prefixcmp(ptr, GIT3_CAP_MULTI_ACK_DETAILED)) {
			caps->common = caps->multi_ack_detailed = 1;
			ptr += strlen(GIT3_CAP_MULTI_ACK_DETAILED);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_MULTI_ACK)) {
			caps->common = caps->multi_ack = 1;
			ptr += strlen(GIT3_CAP_MULTI_ACK);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_INCLUDE_TAG)) {
			caps->common = caps->include_tag = 1;
			ptr += strlen(GIT3_CAP_INCLUDE_TAG);
			continue;
		}

		/* Keep side-band check after side-band-64k */
		if (!git3__prefixcmp(ptr, GIT3_CAP_SIDE_BAND_64K)) {
			caps->common = caps->side_band_64k = 1;
			ptr += strlen(GIT3_CAP_SIDE_BAND_64K);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_SIDE_BAND)) {
			caps->common = caps->side_band = 1;
			ptr += strlen(GIT3_CAP_SIDE_BAND);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_DELETE_REFS)) {
			caps->common = caps->delete_refs = 1;
			ptr += strlen(GIT3_CAP_DELETE_REFS);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_PUSH_OPTIONS)) {
			caps->common = caps->push_options = 1;
			ptr += strlen(GIT3_CAP_PUSH_OPTIONS);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_THIN_PACK)) {
			caps->common = caps->thin_pack = 1;
			ptr += strlen(GIT3_CAP_THIN_PACK);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_SYMREF)) {
			int error;

			if ((error = append_symref(&ptr, symrefs, ptr)) < 0)
				return error;

			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_WANT_TIP_SHA1)) {
			caps->common = caps->want_tip_sha1 = 1;
			ptr += strlen(GIT3_CAP_WANT_TIP_SHA1);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_WANT_REACHABLE_SHA1)) {
			caps->common = caps->want_reachable_sha1 = 1;
			ptr += strlen(GIT3_CAP_WANT_REACHABLE_SHA1);
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_OBJECT_FORMAT)) {
			ptr += strlen(GIT3_CAP_OBJECT_FORMAT);

			start = ptr;
			ptr = strchr(ptr, ' ');

			if ((caps->object_format = git3__strndup(start, (ptr - start))) == NULL)
				return -1;
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_AGENT)) {
			ptr += strlen(GIT3_CAP_AGENT);

			start = ptr;
			ptr = strchr(ptr, ' ');

			if ((caps->agent = git3__strndup(start, (ptr - start))) == NULL)
				return -1;
			continue;
		}

		if (!git3__prefixcmp(ptr, GIT3_CAP_SHALLOW)) {
			caps->common = caps->shallow = 1;
			ptr += strlen(GIT3_CAP_SHALLOW);
			continue;
		}

		/* We don't know this capability, so skip it */
		ptr = strchr(ptr, ' ');
	}

	return 0;
}

static int recv_pkt(
	git3_pkt **out_pkt,
	git3_pkt_type *out_type,
	transport_smart *t)
{
	const char *ptr = t->buffer.data, *line_end = ptr;
	git3_pkt *pkt = NULL;
	git3_pkt_parse_data pkt_parse_data = { 0 };
	int error = 0, ret;

	pkt_parse_data.oid_type = t->owner->repo->oid_type;
	pkt_parse_data.seen_capabilities = 1;

	do {
		if (t->buffer.len > 0)
			error = git3_pkt_parse_line(&pkt, &line_end, ptr,
				t->buffer.len, &pkt_parse_data);
		else
			error = GIT3_EBUFS;

		if (error == 0)
			break; /* return the pkt */

		if (error < 0 && error != GIT3_EBUFS)
			return error;

		if ((ret = git3_smart__recv(t)) < 0) {
			return ret;
		} else if (ret == 0) {
			git3_error_set(GIT3_ERROR_NET, "could not read from remote repository");
			return GIT3_EEOF;
		}
	} while (error);

	git3_staticstr_consume(&t->buffer, line_end);

	if (out_type != NULL)
		*out_type = pkt->type;
	if (out_pkt != NULL)
		*out_pkt = pkt;
	else
		git3__free(pkt);

	return error;
}

static int store_common(transport_smart *t)
{
	git3_pkt *pkt = NULL;
	int error;

	do {
		if ((error = recv_pkt(&pkt, NULL, t)) < 0)
			return error;

		if (t->rpc && (pkt->type == GIT3_PKT_SHALLOW ||
		               pkt->type == GIT3_PKT_UNSHALLOW ||
		               pkt->type == GIT3_PKT_FLUSH)) {
			git3__free(pkt);
			continue;
		}

		if (pkt->type != GIT3_PKT_ACK) {
			git3__free(pkt);
			return 0;
		}

		if (git3_vector_insert(&t->common, pkt) < 0) {
			git3__free(pkt);
			return -1;
		}
	} while (1);

	return 0;
}

static int wait_while_ack(transport_smart *t)
{
	int error;
	git3_pkt *pkt = NULL;
	git3_pkt_ack *ack = NULL;

	while (1) {
		git3_pkt_free(pkt);

		if ((error = recv_pkt(&pkt, NULL, t)) < 0)
			return error;

		if (pkt->type == GIT3_PKT_NAK)
			break;
		if (pkt->type != GIT3_PKT_ACK)
			continue;

		ack = (git3_pkt_ack*)pkt;

		if (ack->status != GIT3_ACK_CONTINUE &&
		    ack->status != GIT3_ACK_COMMON &&
		    ack->status != GIT3_ACK_READY) {
			break;
		}
	}

	git3_pkt_free(pkt);
	return 0;
}

static int cap_not_sup_err(const char *cap_name)
{
	git3_error_set(GIT3_ERROR_NET, "server doesn't support %s", cap_name);
	return GIT3_EINVALID;
}

/* Disables server capabilities we're not interested in */
static int setup_caps(
	transport_smart_caps *caps,
	const git3_fetch_negotiation *wants)
{
	if (wants->depth > 0) {
		if (!caps->shallow)
			return cap_not_sup_err(GIT3_CAP_SHALLOW);
	} else {
		caps->shallow = 0;
	}

	return 0;
}

static int setup_shallow_roots(
	git3_array_oid_t *out,
	const git3_fetch_negotiation *wants)
{
	git3_array_clear(*out);

	if (wants->shallow_roots_len > 0) {
		git3_array_init_to_size(*out, wants->shallow_roots_len);
		GIT3_ERROR_CHECK_ALLOC(out->ptr);

		memcpy(out->ptr, wants->shallow_roots,
		       sizeof(git3_oid) * wants->shallow_roots_len);
		out->size = wants->shallow_roots_len;
	}

	return 0;
}

int git3_smart__negotiate_fetch(
	git3_transport *transport,
	git3_repository *repo,
	const git3_fetch_negotiation *wants)
{
	transport_smart *t = (transport_smart *)transport;
	git3_revwalk__push_options opts = GIT3_REVWALK__PUSH_OPTIONS_INIT;
	git3_str data = GIT3_STR_INIT;
	git3_revwalk *walk = NULL;
	int error = -1;
	git3_pkt_type pkt_type;
	unsigned int i;
	git3_oid oid;

	if ((error = setup_caps(&t->caps, wants)) < 0 ||
	    (error = setup_shallow_roots(&t->shallow_roots, wants)) < 0)
		return error;

	if ((error = git3_pkt_buffer_wants(wants, &t->caps, &data)) < 0)
		return error;

	if ((error = git3_revwalk_new(&walk, repo)) < 0)
		goto on_error;

	opts.insert_by_date = 1;
	if ((error = git3_revwalk__push_glob(walk, "refs/*", &opts)) < 0)
		goto on_error;

	if (wants->depth > 0) {
		git3_pkt_shallow *pkt;

		if ((error = git3_smart__negotiation_step(&t->parent, data.ptr, data.size)) < 0)
			goto on_error;

		if (!t->rpc)
			git3_str_clear(&data);

		while ((error = recv_pkt((git3_pkt **)&pkt, NULL, t)) == 0) {
			bool complete = false;

			if (pkt->type == GIT3_PKT_SHALLOW) {
				error = git3_oidarray__add(&t->shallow_roots, &pkt->oid);
			} else if (pkt->type == GIT3_PKT_UNSHALLOW) {
				git3_oidarray__remove(&t->shallow_roots, &pkt->oid);
			} else if (pkt->type == GIT3_PKT_FLUSH) {
				/* Server is done, stop processing shallow oids */
				complete = true;
			} else {
				git3_error_set(GIT3_ERROR_NET, "unexpected packet type");
				error = -1;
			}

			git3_pkt_free((git3_pkt *) pkt);

			if (complete || error < 0)
				break;
		}

		if (error < 0)
			goto on_error;
	}

	/*
	 * Our support for ACK extensions is simply to parse them. On
	 * the first ACK we will accept that as enough common
	 * objects. We give up if we haven't found an answer in the
	 * first 256 we send.
	 */
	i = 0;
	while (i < 256) {
		error = git3_revwalk_next(&oid, walk);

		if (error < 0) {
			if (GIT3_ITEROVER == error)
				break;

			goto on_error;
		}

		git3_pkt_buffer_have(&oid, &data);
		i++;
		if (i % 20 == 0) {
			if (t->cancelled.val) {
				git3_error_set(GIT3_ERROR_NET, "The fetch was cancelled by the user");
				error = GIT3_EUSER;
				goto on_error;
			}

			git3_pkt_buffer_flush(&data);
			if (git3_str_oom(&data)) {
				error = -1;
				goto on_error;
			}

			if ((error = git3_smart__negotiation_step(&t->parent, data.ptr, data.size)) < 0)
				goto on_error;

			git3_str_clear(&data);
			if (t->caps.multi_ack || t->caps.multi_ack_detailed) {
				if ((error = store_common(t)) < 0)
					goto on_error;
			} else {
				if ((error = recv_pkt(NULL, &pkt_type, t)) < 0)
					goto on_error;

				if (pkt_type == GIT3_PKT_ACK) {
					break;
				} else if (pkt_type == GIT3_PKT_NAK) {
					continue;
				} else {
					git3_error_set(GIT3_ERROR_NET, "unexpected pkt type");
					error = -1;
					goto on_error;
				}
			}
		}

		if (t->common.length > 0)
			break;

		if (i % 20 == 0 && t->rpc) {
			git3_pkt_ack *pkt;
			unsigned int j;

			if ((error = git3_pkt_buffer_wants(wants, &t->caps, &data)) < 0)
				goto on_error;

			git3_vector_foreach(&t->common, j, pkt) {
				if ((error = git3_pkt_buffer_have(&pkt->oid, &data)) < 0)
					goto on_error;
			}

			if (git3_str_oom(&data)) {
				error = -1;
				goto on_error;
			}
		}
	}

	/* Tell the other end that we're done negotiating */
	if (t->rpc && t->common.length > 0) {
		git3_pkt_ack *pkt;
		unsigned int j;

		if ((error = git3_pkt_buffer_wants(wants, &t->caps, &data)) < 0)
			goto on_error;

		git3_vector_foreach(&t->common, j, pkt) {
			if ((error = git3_pkt_buffer_have(&pkt->oid, &data)) < 0)
				goto on_error;
		}

		if (git3_str_oom(&data)) {
			error = -1;
			goto on_error;
		}
	}

	if ((error = git3_pkt_buffer_done(&data)) < 0)
		goto on_error;

	if (t->cancelled.val) {
		git3_error_set(GIT3_ERROR_NET, "the fetch was cancelled");
		error = GIT3_EUSER;
		goto on_error;
	}

	if ((error = git3_smart__negotiation_step(&t->parent, data.ptr, data.size)) < 0)
		goto on_error;

	git3_str_dispose(&data);
	git3_revwalk_free(walk);

	/* Now let's eat up whatever the server gives us */
	if (!t->caps.multi_ack && !t->caps.multi_ack_detailed) {
		if ((error = recv_pkt(NULL, &pkt_type, t)) < 0)
			return error;

		if (pkt_type != GIT3_PKT_ACK && pkt_type != GIT3_PKT_NAK) {
			git3_error_set(GIT3_ERROR_NET, "unexpected pkt type");
			return -1;
		}
	} else {
		error = wait_while_ack(t);
	}

	return error;

on_error:
	git3_revwalk_free(walk);
	git3_str_dispose(&data);
	return error;
}

int git3_smart__shallow_roots(git3_oidarray *out, git3_transport *transport)
{
	transport_smart *t = (transport_smart *)transport;
	size_t len;

	GIT3_ERROR_CHECK_ALLOC_MULTIPLY(&len, t->shallow_roots.size, sizeof(git3_oid));

	out->count = t->shallow_roots.size;

	if (len) {
		out->ids = git3__malloc(len);
		memcpy(out->ids, t->shallow_roots.ptr, len);
	} else {
		out->ids = NULL;
	}

	return 0;
}

static int no_sideband(
	transport_smart *t,
	struct git3_odb_writepack *writepack,
	git3_indexer_progress *stats)
{
	int recvd;

	do {
		if (t->cancelled.val) {
			git3_error_set(GIT3_ERROR_NET, "the fetch was cancelled by the user");
			return GIT3_EUSER;
		}

		if (writepack->append(writepack, t->buffer.data, t->buffer.len, stats) < 0)
			return -1;

		git3_staticstr_clear(&t->buffer);

		if ((recvd = git3_smart__recv(t)) < 0)
			return recvd;
	} while(recvd > 0);

	if (writepack->commit(writepack, stats) < 0)
		return -1;

	return 0;
}

struct network_packetsize_payload
{
	git3_indexer_progress_cb callback;
	void *payload;
	git3_indexer_progress *stats;
	size_t last_fired_bytes;
};

static int network_packetsize(size_t received, void *payload)
{
	struct network_packetsize_payload *npp = (struct network_packetsize_payload*)payload;

	/* Accumulate bytes */
	npp->stats->received_bytes += received;

	/* Fire notification if the threshold is reached */
	if ((npp->stats->received_bytes - npp->last_fired_bytes) > NETWORK_XFER_THRESHOLD) {
		npp->last_fired_bytes = npp->stats->received_bytes;

		if (npp->callback(npp->stats, npp->payload))
			return GIT3_EUSER;
	}

	return 0;
}

int git3_smart__download_pack(
	git3_transport *transport,
	git3_repository *repo,
	git3_indexer_progress *stats)
{
	transport_smart *t = (transport_smart *)transport;
	git3_odb *odb;
	struct git3_odb_writepack *writepack = NULL;
	int error = 0;
	struct network_packetsize_payload npp = {0};

	git3_indexer_progress_cb progress_cb = t->connect_opts.callbacks.transfer_progress;
	void *progress_payload = t->connect_opts.callbacks.payload;

	memset(stats, 0, sizeof(git3_indexer_progress));

	if (progress_cb) {
		npp.callback = progress_cb;
		npp.payload = progress_payload;
		npp.stats = stats;
		t->packetsize_cb = &network_packetsize;
		t->packetsize_payload = &npp;

		/* We might have something in the buffer already from negotiate_fetch */
		if (t->buffer.len > 0 && !t->cancelled.val) {
			if (t->packetsize_cb(t->buffer.len, t->packetsize_payload))
				git3_atomic32_set(&t->cancelled, 1);
		}
	}

	if ((error = git3_repository_odb__weakptr(&odb, repo)) < 0 ||
		((error = git3_odb_write_pack(&writepack, odb, progress_cb, progress_payload)) != 0))
		goto done;

	/*
	 * If the remote doesn't support the side-band, we can feed
	 * the data directly to the pack writer. Otherwise, we need to
	 * check which one belongs there.
	 */
	if (!t->caps.side_band && !t->caps.side_band_64k) {
		error = no_sideband(t, writepack, stats);
		goto done;
	}

	do {
		git3_pkt *pkt = NULL;

		/* Check cancellation before network call */
		if (t->cancelled.val) {
			git3_error_clear();
			error = GIT3_EUSER;
			goto done;
		}

		if ((error = recv_pkt(&pkt, NULL, t)) >= 0) {
			/* Check cancellation after network call */
			if (t->cancelled.val) {
				git3_error_clear();
				error = GIT3_EUSER;
			} else if (pkt->type == GIT3_PKT_PROGRESS) {
				if (t->connect_opts.callbacks.sideband_progress) {
					git3_pkt_progress *p = (git3_pkt_progress *) pkt;

					if (p->len > INT_MAX) {
						git3_error_set(GIT3_ERROR_NET, "oversized progress message");
						error = GIT3_ERROR;
						goto done;
					}

					error = t->connect_opts.callbacks.sideband_progress(p->data, (int)p->len, t->connect_opts.callbacks.payload);
				}
			} else if (pkt->type == GIT3_PKT_DATA) {
				git3_pkt_data *p = (git3_pkt_data *) pkt;

				if (p->len)
					error = writepack->append(writepack, p->data, p->len, stats);
			} else if (pkt->type == GIT3_PKT_FLUSH) {
				/* A flush indicates the end of the packfile */
				git3__free(pkt);
				break;
			}
		}

		git3_pkt_free(pkt);

		if (error < 0)
			goto done;

	} while (1);

	/*
	 * Trailing execution of progress_cb, if necessary...
	 * Only the callback through the npp datastructure currently
	 * updates the last_fired_bytes value. It is possible that
	 * progress has already been reported with the correct
	 * "received_bytes" value, but until (if?) this is unified
	 * then we will report progress again to be sure that the
	 * correct last received_bytes value is reported.
	 */
	if (npp.callback && npp.stats->received_bytes > npp.last_fired_bytes) {
		error = npp.callback(npp.stats, npp.payload);
		if (error != 0)
			goto done;
	}

	error = writepack->commit(writepack, stats);

done:
	if (writepack)
		writepack->free(writepack);
	if (progress_cb) {
		t->packetsize_cb = NULL;
		t->packetsize_payload = NULL;
	}

	return error;
}

static int gen_pktline(git3_str *buf, git3_push *push)
{
	push_spec *spec;
	char *option;
	size_t i, len;
	char old_id[GIT3_OID_MAX_HEXSIZE + 1], new_id[GIT3_OID_MAX_HEXSIZE + 1];
	size_t old_id_len, new_id_len;

	git3_vector_foreach(&push->specs, i, spec) {
		len = strlen(spec->refspec.dst) + 7;

		if (i == 0) {
			/* Need a leading \0 */
			++len;

			if (push->report_status)
				len += strlen(GIT3_CAP_REPORT_STATUS) + 1;

			if (git3_vector_length(&push->remote_push_options) > 0)
				len += strlen(GIT3_CAP_PUSH_OPTIONS) + 1;

			len += strlen(GIT3_CAP_SIDE_BAND_64K) + 1;
		}

		old_id_len = git3_oid_hexsize(git3_oid_type(&spec->roid));
		new_id_len = git3_oid_hexsize(git3_oid_type(&spec->loid));

		len += (old_id_len + new_id_len);

		git3_oid_fmt(old_id, &spec->roid);
		old_id[old_id_len] = '\0';

		git3_oid_fmt(new_id, &spec->loid);
		new_id[new_id_len] = '\0';

		git3_str_printf(buf, "%04"PRIxZ"%.*s %.*s %s", len,
			(int)old_id_len, old_id, (int)new_id_len, new_id,
			spec->refspec.dst);

		if (i == 0) {
			git3_str_putc(buf, '\0');

			/* Core git always starts their capabilities string with a space */
			if (push->report_status) {
				git3_str_putc(buf, ' ');
				git3_str_printf(buf, GIT3_CAP_REPORT_STATUS);
			}
			if (git3_vector_length(&push->remote_push_options) > 0) {
				git3_str_putc(buf, ' ');
				git3_str_printf(buf, GIT3_CAP_PUSH_OPTIONS);
			}
			git3_str_putc(buf, ' ');
			git3_str_printf(buf, GIT3_CAP_SIDE_BAND_64K);
		}

		git3_str_putc(buf, '\n');
	}

	if (git3_vector_length(&push->remote_push_options) > 0) {
		git3_str_printf(buf, "0000");
		git3_vector_foreach(&push->remote_push_options, i, option) {
			git3_str_printf(buf, "%04"PRIxZ"%s", strlen(option) + 4 , option);
		}
	}

	git3_str_puts(buf, "0000");
	return git3_str_oom(buf) ? -1 : 0;
}

static int add_push_report_pkt(git3_push *push, git3_pkt *pkt)
{
	push_status *status;

	switch (pkt->type) {
		case GIT3_PKT_OK:
			status = git3__calloc(1, sizeof(push_status));
			GIT3_ERROR_CHECK_ALLOC(status);
			status->msg = NULL;
			status->ref = git3__strdup(((git3_pkt_ok *)pkt)->ref);
			if (!status->ref ||
				git3_vector_insert(&push->status, status) < 0) {
				git3_push_status_free(status);
				return -1;
			}
			break;
		case GIT3_PKT_NG:
			status = git3__calloc(1, sizeof(push_status));
			GIT3_ERROR_CHECK_ALLOC(status);
			status->ref = git3__strdup(((git3_pkt_ng *)pkt)->ref);
			status->msg = git3__strdup(((git3_pkt_ng *)pkt)->msg);
			if (!status->ref || !status->msg ||
				git3_vector_insert(&push->status, status) < 0) {
				git3_push_status_free(status);
				return -1;
			}
			break;
		case GIT3_PKT_UNPACK:
			push->unpack_ok = ((git3_pkt_unpack *)pkt)->unpack_ok;
			break;
		case GIT3_PKT_FLUSH:
			return GIT3_ITEROVER;
		default:
			git3_error_set(GIT3_ERROR_NET, "report-status: protocol error");
			return -1;
	}

	return 0;
}

static int add_push_report_sideband_pkt(git3_push *push, git3_pkt_data *data_pkt, git3_str *data_pkt_buf)
{
	git3_pkt *pkt;
	git3_pkt_parse_data pkt_parse_data = { 0 };
	const char *line, *line_end = NULL;
	size_t line_len;
	int error;
	int reading_from_buf = data_pkt_buf->size > 0;

	if (reading_from_buf) {
		/* We had an existing partial packet, so add the new
		 * packet to the buffer and parse the whole thing */
		git3_str_put(data_pkt_buf, data_pkt->data, data_pkt->len);
		line = data_pkt_buf->ptr;
		line_len = data_pkt_buf->size;
	}
	else {
		line = data_pkt->data;
		line_len = data_pkt->len;
	}

	while (line_len > 0) {
		error = git3_pkt_parse_line(&pkt, &line_end, line, line_len, &pkt_parse_data);

		if (error == GIT3_EBUFS) {
			/* Buffer the data when the inner packet is split
			 * across multiple sideband packets */
			if (!reading_from_buf)
				git3_str_put(data_pkt_buf, line, line_len);
			error = 0;
			goto done;
		}
		else if (error < 0)
			goto done;

		/* Advance in the buffer */
		line_len -= (line_end - line);
		line = line_end;

		error = add_push_report_pkt(push, pkt);

		git3_pkt_free(pkt);

		if (error < 0 && error != GIT3_ITEROVER)
			goto done;
	}

	error = 0;

done:
	if (reading_from_buf)
		git3_str_consume(data_pkt_buf, line_end);
	return error;
}

static int parse_report(transport_smart *transport, git3_push *push)
{
	git3_pkt *pkt = NULL;
	git3_pkt_parse_data pkt_parse_data = { 0 };
	const char *line_end = NULL;
	int error, recvd;
	git3_str data_pkt_buf = GIT3_STR_INIT;

	for (;;) {
		if (transport->buffer.len > 0)
			error = git3_pkt_parse_line(&pkt, &line_end,
				   transport->buffer.data,
				   transport->buffer.len,
				   &pkt_parse_data);
		else
			error = GIT3_EBUFS;

		if (error < 0 && error != GIT3_EBUFS) {
			error = -1;
			goto done;
		}

		if (error == GIT3_EBUFS) {
			if ((recvd = git3_smart__recv(transport)) < 0) {
				error = recvd;
				goto done;
			}

			if (recvd == 0) {
				git3_error_set(GIT3_ERROR_NET, "could not read report from remote repository");
				error = GIT3_EEOF;
				goto done;
			}
			continue;
		}

		git3_staticstr_consume(&transport->buffer, line_end);
		error = 0;

		switch (pkt->type) {
			case GIT3_PKT_DATA:
				/* This is a sideband packet which contains other packets */
				error = add_push_report_sideband_pkt(push, (git3_pkt_data *)pkt, &data_pkt_buf);
				break;
			case GIT3_PKT_ERR:
				git3_error_set(GIT3_ERROR_NET, "report-status: Error reported: %s",
					((git3_pkt_err *)pkt)->error);
				error = -1;
				break;
			case GIT3_PKT_PROGRESS:
				if (transport->connect_opts.callbacks.sideband_progress) {
					git3_pkt_progress *p = (git3_pkt_progress *) pkt;

					if (p->len > INT_MAX) {
						git3_error_set(GIT3_ERROR_NET, "oversized progress message");
						error = GIT3_ERROR;
						goto done;
					}

					error = transport->connect_opts.callbacks.sideband_progress(p->data, (int)p->len, transport->connect_opts.callbacks.payload);
				}
				break;
			default:
				error = add_push_report_pkt(push, pkt);
				break;
		}

		git3_pkt_free(pkt);

		/* add_push_report_pkt returns GIT3_ITEROVER when it receives a flush */
		if (error == GIT3_ITEROVER) {
			error = 0;
			if (data_pkt_buf.size > 0) {
				/* If there was data remaining in the pack data buffer,
				 * then the server sent a partial pkt-line */
				git3_error_set(GIT3_ERROR_NET, "incomplete pack data pkt-line");
				error = GIT3_ERROR;
			}
			goto done;
		}

		if (error < 0) {
			goto done;
		}
	}
done:
	git3_str_dispose(&data_pkt_buf);
	return error;
}

static int add_ref_from_push_spec(git3_vector *refs, push_spec *push_spec)
{
	git3_pkt_ref *added = git3__calloc(1, sizeof(git3_pkt_ref));
	GIT3_ERROR_CHECK_ALLOC(added);

	added->type = GIT3_PKT_REF;
	git3_oid_cpy(&added->head.oid, &push_spec->loid);
	added->head.name = git3__strdup(push_spec->refspec.dst);

	if (!added->head.name ||
		git3_vector_insert(refs, added) < 0) {
		git3_pkt_free((git3_pkt *)added);
		return -1;
	}

	return 0;
}

static int update_refs_from_report(
	git3_vector *refs,
	git3_vector *push_specs,
	git3_vector *push_report)
{
	git3_pkt_ref *ref;
	push_spec *push_spec;
	push_status *push_status;
	size_t i, j, refs_len;
	int cmp;

	/* For each push spec we sent to the server, we should have
	 * gotten back a status packet in the push report */
	if (push_specs->length != push_report->length) {
		git3_error_set(GIT3_ERROR_NET, "report-status: protocol error");
		return -1;
	}

	/* We require that push_specs be sorted with push_spec_rref_cmp,
	 * and that push_report be sorted with push_status_ref_cmp */
	git3_vector_sort(push_specs);
	git3_vector_sort(push_report);

	git3_vector_foreach(push_specs, i, push_spec) {
		push_status = git3_vector_get(push_report, i);

		/* For each push spec we sent to the server, we should have
		 * gotten back a status packet in the push report which matches */
		if (strcmp(push_spec->refspec.dst, push_status->ref)) {
			git3_error_set(GIT3_ERROR_NET, "report-status: protocol error");
			return -1;
		}
	}

	/* We require that refs be sorted with ref_name_cmp */
	git3_vector_sort(refs);
	i = j = 0;
	refs_len = refs->length;

	/* Merge join push_specs with refs */
	while (i < push_specs->length && j < refs_len) {
		push_spec = git3_vector_get(push_specs, i);
		push_status = git3_vector_get(push_report, i);
		ref = git3_vector_get(refs, j);

		cmp = strcmp(push_spec->refspec.dst, ref->head.name);

		/* Iterate appropriately */
		if (cmp <= 0) i++;
		if (cmp >= 0) j++;

		/* Add case */
		if (cmp < 0 &&
			!push_status->msg &&
			add_ref_from_push_spec(refs, push_spec) < 0)
			return -1;

		/* Update case, delete case */
		if (cmp == 0 &&
			!push_status->msg)
			git3_oid_cpy(&ref->head.oid, &push_spec->loid);
	}

	for (; i < push_specs->length; i++) {
		push_spec = git3_vector_get(push_specs, i);
		push_status = git3_vector_get(push_report, i);

		/* Add case */
		if (!push_status->msg &&
			add_ref_from_push_spec(refs, push_spec) < 0)
			return -1;
	}

	/* Remove any refs which we updated to have a zero OID. */
	git3_vector_rforeach(refs, i, ref) {
		if (git3_oid_is_zero(&ref->head.oid)) {
			git3_vector_remove(refs, i);
			git3_pkt_free((git3_pkt *)ref);
		}
	}

	git3_vector_sort(refs);

	return 0;
}

struct push_packbuilder_payload
{
	git3_smart_subtransport_stream *stream;
	git3_packbuilder *pb;
	git3_push_transfer_progress_cb cb;
	void *cb_payload;
	size_t last_bytes;
	uint64_t last_progress_report_time;
};

static int stream_thunk(void *buf, size_t size, void *data)
{
	int error = 0;
	struct push_packbuilder_payload *payload = data;

	if ((error = payload->stream->write(payload->stream, (const char *)buf, size)) < 0)
		return error;

	if (payload->cb) {
		uint64_t current_time = git3_time_monotonic();
		uint64_t elapsed = current_time - payload->last_progress_report_time;
		payload->last_bytes += size;

		if (elapsed >= MIN_PROGRESS_UPDATE_INTERVAL) {
			payload->last_progress_report_time = current_time;
			error = payload->cb(payload->pb->nr_written, payload->pb->nr_objects, payload->last_bytes, payload->cb_payload);
		}
	}

	return error;
}

int git3_smart__push(git3_transport *transport, git3_push *push)
{
	transport_smart *t = (transport_smart *)transport;
	git3_remote_callbacks *cbs = &t->connect_opts.callbacks;
	struct push_packbuilder_payload packbuilder_payload = {0};
	git3_str pktline = GIT3_STR_INIT;
	int error = 0, need_pack = 0;
	push_spec *spec;
	unsigned int i;

	packbuilder_payload.pb = push->pb;

	if (cbs && cbs->push_transfer_progress) {
		packbuilder_payload.cb = cbs->push_transfer_progress;
		packbuilder_payload.cb_payload = cbs->payload;
	}

#ifdef PUSH_DEBUG
{
	git3_remote_head *head;
	char hex[GIT3_OID_MAX_HEXSIZE+1], hex[GIT3_OID_MAX_HEXSIZE] = '\0';

	git3_vector_foreach(&push->remote->refs, i, head) {
		git3_oid_fmt(hex, &head->oid);
		fprintf(stderr, "%s (%s)\n", hex, head->name);
	}

	git3_vector_foreach(&push->specs, i, spec) {
		git3_oid_fmt(hex, &spec->roid);
		fprintf(stderr, "%s (%s) -> ", hex, spec->lref);
		git3_oid_fmt(hex, &spec->loid);
		fprintf(stderr, "%s (%s)\n", hex, spec->rref ?
			spec->rref : spec->lref);
	}
}
#endif

	/*
	 * Figure out if we need to send a packfile; which is in all
	 * cases except when we only send delete commands
	 */
	git3_vector_foreach(&push->specs, i, spec) {
		if (spec->refspec.src && spec->refspec.src[0] != '\0') {
			need_pack = 1;
			break;
		}
	}

	/* prepare pack before sending pack header to avoid timeouts */
	if (need_pack && ((error = git3_packbuilder__prepare(push->pb))) < 0)
		goto done;

	if ((error = git3_smart__get_push_stream(t, &packbuilder_payload.stream)) < 0 ||
		(error = gen_pktline(&pktline, push)) < 0 ||
		(error = packbuilder_payload.stream->write(packbuilder_payload.stream, git3_str_cstr(&pktline), git3_str_len(&pktline))) < 0)
		goto done;

	if (need_pack &&
		(error = git3_packbuilder_foreach(push->pb, &stream_thunk, &packbuilder_payload)) < 0)
		goto done;

	/* If we sent nothing or the server doesn't support report-status, then
	 * we consider the pack to have been unpacked successfully */
	if (!push->specs.length || !push->report_status)
		push->unpack_ok = 1;
	else if ((error = parse_report(t, push)) < 0)
		goto done;

	/* If progress is being reported write the final report */
	if (cbs && cbs->push_transfer_progress) {
		error = cbs->push_transfer_progress(
					push->pb->nr_written,
					push->pb->nr_objects,
					packbuilder_payload.last_bytes,
					cbs->payload);

		if (error < 0)
			goto done;
	}

	if (push->status.length) {
		error = update_refs_from_report(&t->refs, &push->specs, &push->status);
		if (error < 0)
			goto done;

		error = git3_smart__update_heads(t, NULL);
	}

done:
	git3_str_dispose(&pktline);
	return error;
}
