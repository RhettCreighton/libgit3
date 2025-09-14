/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_transports_smart_h__
#define INCLUDE_transports_smart_h__

#include "common.h"

#include "git3.h"
#include "vector.h"
#include "push.h"
#include "str.h"
#include "oidarray.h"
#include "staticstr.h"
#include "git3/sys/transport.h"

#define GIT3_SMART_BUFFER_SIZE  65536

#define GIT3_SIDE_BAND_DATA     1
#define GIT3_SIDE_BAND_PROGRESS 2
#define GIT3_SIDE_BAND_ERROR    3

#define GIT3_CAP_OFS_DELTA "ofs-delta"
#define GIT3_CAP_MULTI_ACK "multi_ack"
#define GIT3_CAP_MULTI_ACK_DETAILED "multi_ack_detailed"
#define GIT3_CAP_SIDE_BAND "side-band"
#define GIT3_CAP_SIDE_BAND_64K "side-band-64k"
#define GIT3_CAP_INCLUDE_TAG "include-tag"
#define GIT3_CAP_DELETE_REFS "delete-refs"
#define GIT3_CAP_REPORT_STATUS "report-status"
#define GIT3_CAP_THIN_PACK "thin-pack"
#define GIT3_CAP_SYMREF "symref"
#define GIT3_CAP_WANT_TIP_SHA1 "allow-tip-sha1-in-want"
#define GIT3_CAP_WANT_REACHABLE_SHA1 "allow-reachable-sha1-in-want"
#define GIT3_CAP_SHALLOW "shallow"
#define GIT3_CAP_OBJECT_FORMAT "object-format="
#define GIT3_CAP_AGENT "agent="
#define GIT3_CAP_PUSH_OPTIONS "push-options"

extern bool git3_smart__ofs_delta_enabled;

typedef enum {
	GIT3_PKT_CMD,
	GIT3_PKT_FLUSH,
	GIT3_PKT_REF,
	GIT3_PKT_HAVE,
	GIT3_PKT_ACK,
	GIT3_PKT_NAK,
	GIT3_PKT_COMMENT,
	GIT3_PKT_ERR,
	GIT3_PKT_DATA,
	GIT3_PKT_PROGRESS,
	GIT3_PKT_OK,
	GIT3_PKT_NG,
	GIT3_PKT_UNPACK,
	GIT3_PKT_SHALLOW,
	GIT3_PKT_UNSHALLOW
} git3_pkt_type;

/* Used for multi_ack and multi_ack_detailed */
enum git3_ack_status {
	GIT3_ACK_NONE,
	GIT3_ACK_CONTINUE,
	GIT3_ACK_COMMON,
	GIT3_ACK_READY
};

/* This would be a flush pkt */
typedef struct {
	git3_pkt_type type;
} git3_pkt;

struct git3_pkt_cmd {
	git3_pkt_type type;
	char *cmd;
	char *path;
	char *host;
};

/* This is a pkt-line with some info in it */
typedef struct {
	git3_pkt_type type;
	git3_remote_head head;
	char *capabilities;
} git3_pkt_ref;

/* Useful later */
typedef struct {
	git3_pkt_type type;
	git3_oid oid;
	enum git3_ack_status status;
} git3_pkt_ack;

typedef struct {
	git3_pkt_type type;
	char comment[GIT3_FLEX_ARRAY];
} git3_pkt_comment;

typedef struct {
	git3_pkt_type type;
	size_t len;
	char data[GIT3_FLEX_ARRAY];
} git3_pkt_data;

typedef git3_pkt_data git3_pkt_progress;

typedef struct {
	git3_pkt_type type;
	size_t len;
	char error[GIT3_FLEX_ARRAY];
} git3_pkt_err;

typedef struct {
	git3_pkt_type type;
	char *ref;
} git3_pkt_ok;

typedef struct {
	git3_pkt_type type;
	char *ref;
	char *msg;
} git3_pkt_ng;

typedef struct {
	git3_pkt_type type;
	int unpack_ok;
} git3_pkt_unpack;

typedef struct {
	git3_pkt_type type;
	git3_oid oid;
} git3_pkt_shallow;

typedef struct transport_smart_caps {
	unsigned int common:1,
	             ofs_delta:1,
	             multi_ack:1,
	             multi_ack_detailed:1,
	             side_band:1,
	             side_band_64k:1,
	             include_tag:1,
	             delete_refs:1,
	             report_status:1,
	             thin_pack:1,
	             want_tip_sha1:1,
	             want_reachable_sha1:1,
	             shallow:1,
	             push_options:1;
	char *object_format;
	char *agent;
} transport_smart_caps;

typedef int (*packetsize_cb)(size_t received, void *payload);

typedef struct {
	git3_transport parent;
	git3_remote *owner;
	char *url;
	git3_remote_connect_options connect_opts;
	int direction;
	git3_smart_subtransport *wrapped;
	git3_smart_subtransport_stream *current_stream;
	transport_smart_caps caps;
	git3_vector refs;
	git3_vector heads;
	git3_vector common;
	git3_array_oid_t shallow_roots;
	git3_atomic32 cancelled;
	packetsize_cb packetsize_cb;
	void *packetsize_payload;
	unsigned rpc : 1,
	         have_refs : 1,
	         connected : 1;
	git3_staticstr_with_size(GIT3_SMART_BUFFER_SIZE) buffer;
} transport_smart;

/* smart_protocol.c */
int git3_smart__store_refs(transport_smart *t, int flushes);
int git3_smart__detect_caps(git3_pkt_ref *pkt, transport_smart_caps *caps, git3_vector *symrefs);
int git3_smart__push(git3_transport *transport, git3_push *push);

int git3_smart__negotiate_fetch(
	git3_transport *transport,
	git3_repository *repo,
	const git3_fetch_negotiation *wants);

int git3_smart__shallow_roots(git3_oidarray *out, git3_transport *transport);

int git3_smart__download_pack(
	git3_transport *transport,
	git3_repository *repo,
	git3_indexer_progress *stats);

/* smart.c */
int git3_smart__recv(transport_smart *t);

int git3_smart__negotiation_step(git3_transport *transport, void *data, size_t len);
int git3_smart__get_push_stream(transport_smart *t, git3_smart_subtransport_stream **out);

int git3_smart__update_heads(transport_smart *t, git3_vector *symrefs);

/* smart_pkt.c */
typedef struct {
	git3_oid_t oid_type;
	unsigned int seen_capabilities: 1;
} git3_pkt_parse_data;

int git3_pkt_parse_line(git3_pkt **head, const char **endptr, const char *line, size_t linelen, git3_pkt_parse_data *data);
int git3_pkt_buffer_flush(git3_str *buf);
int git3_pkt_send_flush(GIT3_SOCKET s);
int git3_pkt_buffer_done(git3_str *buf);
int git3_pkt_buffer_wants(const git3_fetch_negotiation *wants, transport_smart_caps *caps, git3_str *buf);
int git3_pkt_buffer_have(git3_oid *oid, git3_str *buf);
void git3_pkt_free(git3_pkt *pkt);

#endif
