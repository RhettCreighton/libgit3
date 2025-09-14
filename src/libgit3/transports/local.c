/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "pack-objects.h"
#include "refs.h"
#include "posix.h"
#include "fs_path.h"
#include "repository.h"
#include "odb.h"
#include "push.h"
#include "remote.h"
#include "proxy.h"

#include "git3/types.h"
#include "git3/net.h"
#include "git3/repository.h"
#include "git3/object.h"
#include "git3/tag.h"
#include "git3/transport.h"
#include "git3/revwalk.h"
#include "git3/odb_backend.h"
#include "git3/pack.h"
#include "git3/commit.h"
#include "git3/revparse.h"
#include "git3/sys/remote.h"

typedef struct {
	git3_transport parent;
	git3_remote *owner;
	char *url;
	int direction;
	git3_atomic32 cancelled;
	git3_repository *repo;
	git3_remote_connect_options connect_opts;
	git3_vector refs;
	unsigned connected : 1,
		have_refs : 1;
} transport_local;

static void free_head(git3_remote_head *head)
{
	git3__free(head->name);
	git3__free(head->symref_target);
	git3__free(head);
}

static void free_heads(git3_vector *heads)
{
	git3_remote_head *head;
	size_t i;

	git3_vector_foreach(heads, i, head)
		free_head(head);

	git3_vector_dispose(heads);
}

static int add_ref(transport_local *t, const char *name)
{
	const char peeled[] = "^{}";
	git3_reference *ref, *resolved;
	git3_remote_head *head;
	git3_oid obj_id;
	git3_object *obj = NULL, *target = NULL;
	git3_str buf = GIT3_STR_INIT;
	int error;

	if ((error = git3_reference_lookup(&ref, t->repo, name)) < 0)
		return error;

	error = git3_reference_resolve(&resolved, ref);
	if (error < 0) {
		git3_reference_free(ref);
		if (!strcmp(name, GIT3_HEAD_FILE) && error == GIT3_ENOTFOUND) {
			/* This is actually okay.  Empty repos often have a HEAD that
			 * points to a nonexistent "refs/heads/master". */
			git3_error_clear();
			return 0;
		}
		return error;
	}

	git3_oid_cpy(&obj_id, git3_reference_target(resolved));
	git3_reference_free(resolved);

	head = git3__calloc(1, sizeof(git3_remote_head));
	GIT3_ERROR_CHECK_ALLOC(head);

	head->name = git3__strdup(name);
	GIT3_ERROR_CHECK_ALLOC(head->name);

	git3_oid_cpy(&head->oid, &obj_id);

	if (git3_reference_type(ref) == GIT3_REFERENCE_SYMBOLIC) {
		head->symref_target = git3__strdup(git3_reference_symbolic_target(ref));
		GIT3_ERROR_CHECK_ALLOC(head->symref_target);
	}
	git3_reference_free(ref);

	if ((error = git3_vector_insert(&t->refs, head)) < 0) {
		free_head(head);
		return error;
	}

	if ((error = git3_object_lookup(&obj, t->repo, &head->oid, GIT3_OBJECT_ANY)) < 0)
		return error;

	head = NULL;

	/* If it's not an annotated tag, or if we're mocking
	 * git-receive-pack, just get out */
	if (git3_object_type(obj) != GIT3_OBJECT_TAG ||
		t->direction != GIT3_DIRECTION_FETCH) {
		git3_object_free(obj);
		return 0;
	}

	/* And if it's a tag, peel it, and add it to the list */
	head = git3__calloc(1, sizeof(git3_remote_head));
	GIT3_ERROR_CHECK_ALLOC(head);

	if (git3_str_join(&buf, 0, name, peeled) < 0) {
		free_head(head);
		return -1;
	}
	head->name = git3_str_detach(&buf);

	if (!(error = git3_tag_peel(&target, (git3_tag *)obj))) {
		git3_oid_cpy(&head->oid, git3_object_id(target));

		if ((error = git3_vector_insert(&t->refs, head)) < 0) {
			free_head(head);
		}
	}

	git3_object_free(obj);
	git3_object_free(target);

	return error;
}

static int store_refs(transport_local *t)
{
	size_t i;
	git3_remote_head *head;
	git3_strarray ref_names = {0};

	GIT3_ASSERT_ARG(t);

	if (git3_reference_list(&ref_names, t->repo) < 0)
		goto on_error;

	/* Clear all heads we might have fetched in a previous connect */
	git3_vector_foreach(&t->refs, i, head) {
		git3__free(head->name);
		git3__free(head);
	}

	/* Clear the vector so we can reuse it */
	git3_vector_clear(&t->refs);

	/* Sort the references first */
	git3__tsort((void **)ref_names.strings, ref_names.count, &git3__strcmp_cb);

	/* Add HEAD iff direction is fetch */
	if (t->direction == GIT3_DIRECTION_FETCH && add_ref(t, GIT3_HEAD_FILE) < 0)
		goto on_error;

	for (i = 0; i < ref_names.count; ++i) {
		if (add_ref(t, ref_names.strings[i]) < 0)
			goto on_error;
	}

	t->have_refs = 1;
	git3_strarray_dispose(&ref_names);
	return 0;

on_error:
	git3_vector_dispose(&t->refs);
	git3_strarray_dispose(&ref_names);
	return -1;
}

/*
 * Try to open the url as a git directory. The direction doesn't
 * matter in this case because we're calculating the heads ourselves.
 */
static int local_connect(
	git3_transport *transport,
	const char *url,
	int direction,
	const git3_remote_connect_options *connect_opts)
{
	git3_repository *repo;
	int error;
	transport_local *t = (transport_local *)transport;
	const char *path;
	git3_str buf = GIT3_STR_INIT;

	if (t->connected)
		return 0;

	if (git3_remote_connect_options_normalize(&t->connect_opts, t->owner->repo, connect_opts) < 0)
		return -1;

	free_heads(&t->refs);

	t->url = git3__strdup(url);
	GIT3_ERROR_CHECK_ALLOC(t->url);
	t->direction = direction;

	/* 'url' may be a url or path; convert to a path */
	if ((error = git3_fs_path_from_url_or_path(&buf, url)) < 0) {
		git3_str_dispose(&buf);
		return error;
	}
	path = git3_str_cstr(&buf);

	error = git3_repository_open(&repo, path);

	git3_str_dispose(&buf);

	if (error < 0)
		return -1;

	t->repo = repo;

	if (store_refs(t) < 0)
		return -1;

	t->connected = 1;

	return 0;
}

static int local_set_connect_opts(
	git3_transport *transport,
	const git3_remote_connect_options *connect_opts)
{
	transport_local *t = (transport_local *)transport;

	if (!t->connected) {
		git3_error_set(GIT3_ERROR_NET, "cannot reconfigure a transport that is not connected");
		return -1;
	}

	return git3_remote_connect_options_normalize(&t->connect_opts, t->owner->repo, connect_opts);
}

static int local_capabilities(unsigned int *capabilities, git3_transport *transport)
{
	GIT3_UNUSED(transport);

	*capabilities = GIT3_REMOTE_CAPABILITY_TIP_OID |
	                GIT3_REMOTE_CAPABILITY_REACHABLE_OID;
	return 0;
}

#ifdef GIT3_EXPERIMENTAL_SHA256
static int local_oid_type(git3_oid_t *out, git3_transport *transport)
{
	transport_local *t = (transport_local *)transport;

	*out = t->repo->oid_type;

	return 0;
}
#endif

static int local_ls(const git3_remote_head ***out, size_t *size, git3_transport *transport)
{
	transport_local *t = (transport_local *)transport;

	if (!t->have_refs) {
		git3_error_set(GIT3_ERROR_NET, "the transport has not yet loaded the refs");
		return -1;
	}

	*out = (const git3_remote_head **)t->refs.contents;
	*size = t->refs.length;

	return 0;
}

static int local_negotiate_fetch(
	git3_transport *transport,
	git3_repository *repo,
	const git3_fetch_negotiation *wants)
{
	transport_local *t = (transport_local*)transport;
	git3_remote_head *rhead;
	unsigned int i;

	GIT3_UNUSED(wants);

	if (wants->depth) {
		git3_error_set(GIT3_ERROR_NET, "shallow fetch is not supported by the local transport");
		return GIT3_ENOTSUPPORTED;
	}

	/* Fill in the loids */
	git3_vector_foreach(&t->refs, i, rhead) {
		git3_object *obj;

		int error = git3_revparse_single(&obj, repo, rhead->name);
		if (!error)
			git3_oid_cpy(&rhead->loid, git3_object_id(obj));
		else if (error != GIT3_ENOTFOUND)
			return error;
		else
			git3_error_clear();
		git3_object_free(obj);
	}

	return 0;
}

static int local_shallow_roots(
	git3_oidarray *out,
	git3_transport *transport)
{
	GIT3_UNUSED(out);
	GIT3_UNUSED(transport);

	return 0;
}

static int local_push_update_remote_ref(
	git3_repository *remote_repo,
	const char *lref,
	const char *rref,
	git3_oid *loid,
	git3_oid *roid)
{
	int error;
	git3_reference *remote_ref = NULL;

	/* check for lhs, if it's empty it means to delete */
	if (lref[0] != '\0') {
		/* Create or update a ref */
		error = git3_reference_create(NULL, remote_repo, rref, loid,
					     !git3_oid_is_zero(roid), NULL);
	} else {
		/* Delete a ref */
		if ((error = git3_reference_lookup(&remote_ref, remote_repo, rref)) < 0) {
			if (error == GIT3_ENOTFOUND)
				error = 0;
			return error;
		}

		error = git3_reference_delete(remote_ref);
		git3_reference_free(remote_ref);
	}

	return error;
}

static int transfer_to_push_transfer(const git3_indexer_progress *stats, void *payload)
{
	const git3_remote_callbacks *cbs = payload;

	if (!cbs || !cbs->push_transfer_progress)
		return 0;

	return cbs->push_transfer_progress(stats->received_objects, stats->total_objects, stats->received_bytes,
					   cbs->payload);
}

static int local_push(
	git3_transport *transport,
	git3_push *push)
{
	transport_local *t = (transport_local *)transport;
	git3_remote_callbacks *cbs = &t->connect_opts.callbacks;
	git3_repository *remote_repo = NULL;
	push_spec *spec;
	char *url = NULL;
	const char *path;
	git3_str buf = GIT3_STR_INIT, odb_path = GIT3_STR_INIT;
	int error;
	size_t j;

	/* 'push->remote->url' may be a url or path; convert to a path */
	if ((error = git3_fs_path_from_url_or_path(&buf, push->remote->url)) < 0) {
		git3_str_dispose(&buf);
		return error;
	}
	path = git3_str_cstr(&buf);

	error = git3_repository_open(&remote_repo, path);

	git3_str_dispose(&buf);

	if (error < 0)
		return error;

	/* We don't currently support pushing locally to non-bare repos. Proper
	   non-bare repo push support would require checking configs to see if
	   we should override the default 'don't let this happen' behavior.

	   Note that this is only an issue when pushing to the current branch,
	   but we forbid all pushes just in case */
	if (!remote_repo->is_bare) {
		error = GIT3_EBAREREPO;
		git3_error_set(GIT3_ERROR_INVALID, "local push doesn't (yet) support pushing to non-bare repos.");
		goto on_error;
	}

	if ((error = git3_repository__item_path(&odb_path, remote_repo, GIT3_REPOSITORY_ITEM_OBJECTS)) < 0
		|| (error = git3_str_joinpath(&odb_path, odb_path.ptr, "pack")) < 0)
		goto on_error;

	error = git3_packbuilder_write(push->pb, odb_path.ptr, 0, transfer_to_push_transfer, (void *) cbs);
	git3_str_dispose(&odb_path);

	if (error < 0)
		goto on_error;

	push->unpack_ok = 1;

	git3_vector_foreach(&push->specs, j, spec) {
		push_status *status;
		const git3_error *last;
		char *ref = spec->refspec.dst;

		status = git3__calloc(1, sizeof(push_status));
		if (!status)
			goto on_error;

		status->ref = git3__strdup(ref);
		if (!status->ref) {
			git3_push_status_free(status);
			goto on_error;
		}

		error = local_push_update_remote_ref(remote_repo, spec->refspec.src, spec->refspec.dst,
			&spec->loid, &spec->roid);

		switch (error) {
			case GIT3_OK:
				break;
			case GIT3_EINVALIDSPEC:
				status->msg = git3__strdup("funny refname");
				break;
			case GIT3_ENOTFOUND:
				status->msg = git3__strdup("Remote branch not found to delete");
				break;
			default:
				last = git3_error_last();

				if (last->klass != GIT3_ERROR_NONE)
					status->msg = git3__strdup(last->message);
				else
					status->msg = git3__strdup("Unspecified error encountered");
				break;
		}

		/* failed to allocate memory for a status message */
		if (error < 0 && !status->msg) {
			git3_push_status_free(status);
			goto on_error;
		}

		/* failed to insert the ref update status */
		if ((error = git3_vector_insert(&push->status, status)) < 0) {
			git3_push_status_free(status);
			goto on_error;
		}
	}

	if (push->specs.length) {
		url = git3__strdup(t->url);

		if (!url || t->parent.close(&t->parent) < 0 ||
			t->parent.connect(&t->parent, url,
			GIT3_DIRECTION_PUSH, NULL))
			goto on_error;
	}

	error = 0;

on_error:
	git3_repository_free(remote_repo);
	git3__free(url);

	return error;
}

typedef struct foreach_data {
	git3_indexer_progress *stats;
	git3_indexer_progress_cb progress_cb;
	void *progress_payload;
	git3_odb_writepack *writepack;
} foreach_data;

static int foreach_cb(void *buf, size_t len, void *payload)
{
	foreach_data *data = (foreach_data*)payload;

	data->stats->received_bytes += len;
	return data->writepack->append(data->writepack, buf, len, data->stats);
}

static const char *counting_objects_fmt = "Counting objects %d\r";
static const char *compressing_objects_fmt = "Compressing objects: %.0f%% (%d/%d)";

static int local_counting(int stage, unsigned int current, unsigned int total, void *payload)
{
	git3_str progress_info = GIT3_STR_INIT;
	transport_local *t = payload;
	int error;

	if (!t->connect_opts.callbacks.sideband_progress)
		return 0;

	if (stage == GIT3_PACKBUILDER_ADDING_OBJECTS) {
		git3_str_printf(&progress_info, counting_objects_fmt, current);
	} else if (stage == GIT3_PACKBUILDER_DELTAFICATION) {
		float perc = (((float) current) / total) * 100;
		git3_str_printf(&progress_info, compressing_objects_fmt, perc, current, total);
		if (current == total)
			git3_str_printf(&progress_info, ", done\n");
		else
			git3_str_putc(&progress_info, '\r');

	}

	if (git3_str_oom(&progress_info))
		return -1;

	if (progress_info.size > INT_MAX) {
		git3_error_set(GIT3_ERROR_NET, "remote sent overly large progress data");
		git3_str_dispose(&progress_info);
		return -1;
	}


	error = t->connect_opts.callbacks.sideband_progress(
		progress_info.ptr,
		(int)progress_info.size,
		t->connect_opts.callbacks.payload);

	git3_str_dispose(&progress_info);
	return error;
}

static int foreach_reference_cb(git3_reference *reference, void *payload)
{
	git3_revwalk *walk = (git3_revwalk *)payload;
	int error;

	if (git3_reference_type(reference) != GIT3_REFERENCE_DIRECT) {
		git3_reference_free(reference);
		return 0;
	}

	error = git3_revwalk_hide(walk, git3_reference_target(reference));
	/* The reference is in the local repository, so the target may not
	 * exist on the remote.  It also may not be a commit. */
	if (error == GIT3_ENOTFOUND || error == GIT3_ERROR_INVALID) {
		git3_error_clear();
		error = 0;
	}

	git3_reference_free(reference);

	return error;
}

static int local_download_pack(
		git3_transport *transport,
		git3_repository *repo,
		git3_indexer_progress *stats)
{
	transport_local *t = (transport_local*)transport;
	git3_revwalk *walk = NULL;
	git3_remote_head *rhead;
	unsigned int i;
	int error = -1;
	git3_packbuilder *pack = NULL;
	git3_odb_writepack *writepack = NULL;
	git3_odb *odb = NULL;
	git3_str progress_info = GIT3_STR_INIT;
	foreach_data data = {0};

	if ((error = git3_revwalk_new(&walk, t->repo)) < 0)
		goto cleanup;

	git3_revwalk_sorting(walk, GIT3_SORT_TIME);

	if ((error = git3_packbuilder_new(&pack, t->repo)) < 0)
		goto cleanup;

	git3_packbuilder_set_callbacks(pack, local_counting, t);

	stats->total_objects = 0;
	stats->indexed_objects = 0;
	stats->received_objects = 0;
	stats->received_bytes = 0;

	git3_vector_foreach(&t->refs, i, rhead) {
		git3_object *obj;
		if ((error = git3_object_lookup(&obj, t->repo, &rhead->oid, GIT3_OBJECT_ANY)) < 0)
			goto cleanup;

		if (git3_object_type(obj) == GIT3_OBJECT_COMMIT) {
			/* Revwalker includes only wanted commits */
			error = git3_revwalk_push(walk, &rhead->oid);
		} else {
			/* Tag or some other wanted object. Add it on its own */
			error = git3_packbuilder_insert_recur(pack, &rhead->oid, rhead->name);
		}
		git3_object_free(obj);
		if (error < 0)
			goto cleanup;
	}

	if ((error = git3_reference_foreach(repo, foreach_reference_cb, walk)))
		goto cleanup;

	if ((error = git3_packbuilder_insert_walk(pack, walk)))
		goto cleanup;

	if (t->connect_opts.callbacks.sideband_progress) {
		if ((error = git3_str_printf(
				&progress_info,
				counting_objects_fmt,
				git3_packbuilder_object_count(pack))) < 0 ||
		    (error = t->connect_opts.callbacks.sideband_progress(
				progress_info.ptr,
				(int)progress_info.size,
				t->connect_opts.callbacks.payload)) < 0)
			goto cleanup;
	}

	/* Walk the objects, building a packfile */
	if ((error = git3_repository_odb__weakptr(&odb, repo)) < 0)
		goto cleanup;

	/* One last one with the newline */
	if (t->connect_opts.callbacks.sideband_progress) {
		git3_str_clear(&progress_info);

		if ((error = git3_str_printf(
				&progress_info,
				counting_objects_fmt,
				git3_packbuilder_object_count(pack))) < 0 ||
		    (error = git3_str_putc(&progress_info, '\n')) < 0 ||
		    (error = t->connect_opts.callbacks.sideband_progress(
				progress_info.ptr,
				(int)progress_info.size,
				t->connect_opts.callbacks.payload)) < 0)
			goto cleanup;
	}

	if ((error = git3_odb_write_pack(
			&writepack,
			odb,
			t->connect_opts.callbacks.transfer_progress,
			t->connect_opts.callbacks.payload)) < 0)
		goto cleanup;

	/* Write the data to the ODB */
	data.stats = stats;
	data.progress_cb = t->connect_opts.callbacks.transfer_progress;
	data.progress_payload = t->connect_opts.callbacks.payload;
	data.writepack = writepack;

	/* autodetect */
	git3_packbuilder_set_threads(pack, 0);

	if ((error = git3_packbuilder_foreach(pack, foreach_cb, &data)) != 0)
		goto cleanup;

	error = writepack->commit(writepack, stats);

cleanup:
	if (writepack) writepack->free(writepack);
	git3_str_dispose(&progress_info);
	git3_packbuilder_free(pack);
	git3_revwalk_free(walk);
	return error;
}

static int local_is_connected(git3_transport *transport)
{
	transport_local *t = (transport_local *)transport;

	return t->connected;
}

static void local_cancel(git3_transport *transport)
{
	transport_local *t = (transport_local *)transport;

	git3_atomic32_set(&t->cancelled, 1);
}

static int local_close(git3_transport *transport)
{
	transport_local *t = (transport_local *)transport;

	t->connected = 0;

	if (t->repo) {
		git3_repository_free(t->repo);
		t->repo = NULL;
	}

	if (t->url) {
		git3__free(t->url);
		t->url = NULL;
	}

	return 0;
}

static void local_free(git3_transport *transport)
{
	transport_local *t = (transport_local *)transport;

	free_heads(&t->refs);

	/* Close the transport, if it's still open. */
	local_close(transport);

	/* Free the transport */
	git3__free(t);
}

/**************
 * Public API *
 **************/

int git3_transport_local(git3_transport **out, git3_remote *owner, void *param)
{
	int error;
	transport_local *t;

	GIT3_UNUSED(param);

	t = git3__calloc(1, sizeof(transport_local));
	GIT3_ERROR_CHECK_ALLOC(t);

	t->parent.version = GIT3_TRANSPORT_VERSION;
	t->parent.connect = local_connect;
	t->parent.set_connect_opts = local_set_connect_opts;
	t->parent.capabilities = local_capabilities;
#ifdef GIT3_EXPERIMENTAL_SHA256
	t->parent.oid_type = local_oid_type;
#endif
	t->parent.negotiate_fetch = local_negotiate_fetch;
	t->parent.shallow_roots = local_shallow_roots;
	t->parent.download_pack = local_download_pack;
	t->parent.push = local_push;
	t->parent.close = local_close;
	t->parent.free = local_free;
	t->parent.ls = local_ls;
	t->parent.is_connected = local_is_connected;
	t->parent.cancel = local_cancel;

	if ((error = git3_vector_init(&t->refs, 0, NULL)) < 0) {
		git3__free(t);
		return error;
	}

	t->owner = owner;

	*out = (git3_transport *) t;

	return 0;
}
