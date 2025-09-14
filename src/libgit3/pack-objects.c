/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "pack-objects.h"

#include "buf.h"
#include "zstream.h"
#include "delta.h"
#include "iterator.h"
#include "pack.h"
#include "thread.h"
#include "tree.h"
#include "util.h"
#include "revwalk.h"
#include "commit_list.h"

#include "git3/pack.h"
#include "git3/commit.h"
#include "git3/tag.h"
#include "git3/indexer.h"
#include "git3/config.h"

struct unpacked {
	git3_pobject *object;
	void *data;
	struct git3_delta_index *index;
	size_t depth;
};

struct tree_walk_context {
	git3_packbuilder *pb;
	git3_str buf;
};

struct pack_write_context {
	git3_indexer *indexer;
	git3_indexer_progress *stats;
};

struct walk_object {
	git3_oid id;
	unsigned int uninteresting:1,
		seen:1;
};

#ifdef GIT3_THREADS
# define GIT3_PACKBUILDER__MUTEX_OP(pb, mtx, op) git3_mutex_##op(&(pb)->mtx)
#else
# define GIT3_PACKBUILDER__MUTEX_OP(pb, mtx, op) git3__noop()
#endif

#define git3_packbuilder__cache_lock(pb) GIT3_PACKBUILDER__MUTEX_OP(pb, cache_mutex, lock)
#define git3_packbuilder__cache_unlock(pb) GIT3_PACKBUILDER__MUTEX_OP(pb, cache_mutex, unlock)
#define git3_packbuilder__progress_lock(pb) GIT3_PACKBUILDER__MUTEX_OP(pb, progress_mutex, lock)
#define git3_packbuilder__progress_unlock(pb) GIT3_PACKBUILDER__MUTEX_OP(pb, progress_mutex, unlock)

/* The minimal interval between progress updates (in seconds). */
#define MIN_PROGRESS_UPDATE_INTERVAL 0.5

/* Size of the buffer to feed to zlib */
#define COMPRESS_BUFLEN (1024 * 1024)

GIT3_HASHMAP_OID_FUNCTIONS(git3_packbuilder_pobjectmap, GIT3_HASHMAP_INLINE, git3_pobject *);
GIT3_HASHMAP_OID_FUNCTIONS(git3_packbuilder_walk_objectmap, GIT3_HASHMAP_INLINE, struct walk_object *);

static unsigned name_hash(const char *name)
{
	unsigned c, hash = 0;

	if (!name)
		return 0;

	/*
	 * This effectively just creates a sortable number from the
	 * last sixteen non-whitespace characters. Last characters
	 * count "most", so things that end in ".c" sort together.
	 */
	while ((c = *name++) != 0) {
		if (git3__isspace(c))
			continue;
		hash = (hash >> 2) + (c << 24);
	}
	return hash;
}

static int packbuilder_config(git3_packbuilder *pb)
{
	git3_config *config;
	int ret = 0;
	int64_t val;

	if ((ret = git3_repository_config_snapshot(&config, pb->repo)) < 0)
		return ret;

#define config_get(KEY,DST,DFLT) do { \
	ret = git3_config_get_int64(&val, config, KEY); \
	if (!ret) { \
		if (!git3__is_sizet(val)) { \
			git3_error_set(GIT3_ERROR_CONFIG, \
				"configuration value '%s' is too large", KEY); \
			ret = -1; \
			goto out; \
		} \
		(DST) = (size_t)val; \
	} else if (ret == GIT3_ENOTFOUND) { \
	    (DST) = (DFLT); \
	    ret = 0; \
	} else if (ret < 0) goto out; } while (0)

	config_get("pack.deltaCacheSize", pb->max_delta_cache_size,
		   GIT3_PACK_DELTA_CACHE_SIZE);
	config_get("pack.deltaCacheLimit", pb->cache_max_small_delta_size,
		   GIT3_PACK_DELTA_CACHE_LIMIT);
	config_get("pack.deltaCacheSize", pb->big_file_threshold,
		   GIT3_PACK_BIG_FILE_THRESHOLD);
	config_get("pack.windowMemory", pb->window_memory_limit, 0);

#undef config_get

out:
	git3_config_free(config);

	return ret;
}

int git3_packbuilder_new(git3_packbuilder **out, git3_repository *repo)
{
	git3_hash_algorithm_t hash_algorithm;
	git3_packbuilder *pb;

	*out = NULL;

	pb = git3__calloc(1, sizeof(*pb));
	GIT3_ERROR_CHECK_ALLOC(pb);

	pb->oid_type = repo->oid_type;

	hash_algorithm = git3_oid_algorithm(pb->oid_type);
	GIT3_ASSERT(hash_algorithm);

	if (git3_pool_init(&pb->object_pool, sizeof(struct walk_object)) < 0)
		goto on_error;

	pb->repo = repo;
	pb->nr_threads = 1; /* do not spawn any thread by default */

	if (git3_hash_ctx_init(&pb->ctx, hash_algorithm) < 0 ||
		git3_zstream_init(&pb->zstream, GIT3_ZSTREAM_DEFLATE) < 0 ||
		git3_repository_odb(&pb->odb, repo) < 0 ||
		packbuilder_config(pb) < 0)
		goto on_error;

#ifdef GIT3_THREADS

	if (git3_mutex_init(&pb->cache_mutex) ||
		git3_mutex_init(&pb->progress_mutex) ||
		git3_cond_init(&pb->progress_cond))
	{
		git3_error_set(GIT3_ERROR_OS, "failed to initialize packbuilder mutex");
		goto on_error;
	}

#endif

	*out = pb;
	return 0;

on_error:
	git3_packbuilder_free(pb);
	return -1;
}

unsigned int git3_packbuilder_set_threads(git3_packbuilder *pb, unsigned int n)
{
	GIT3_ASSERT_ARG(pb);

#ifdef GIT3_THREADS
	pb->nr_threads = n;
#else
	GIT3_UNUSED(n);
	GIT3_ASSERT(pb->nr_threads == 1);
#endif

	return pb->nr_threads;
}

static int rehash(git3_packbuilder *pb)
{
	git3_pobject *po;
	size_t i;

	git3_packbuilder_pobjectmap_clear(&pb->object_ix);

	for (i = 0, po = pb->object_list; i < pb->nr_objects; i++, po++) {
		if (git3_packbuilder_pobjectmap_put(&pb->object_ix, &po->id, po) < 0)
			return -1;
	}

	return 0;
}

int git3_packbuilder_insert(git3_packbuilder *pb, const git3_oid *oid,
			   const char *name)
{
	git3_pobject *po;
	size_t newsize;
	int ret;

	GIT3_ASSERT_ARG(pb);
	GIT3_ASSERT_ARG(oid);

	/* If the object already exists in the hash table, then we don't
	 * have any work to do */
	if (git3_packbuilder_pobjectmap_contains(&pb->object_ix, oid))
		return 0;

	if (pb->nr_objects >= pb->nr_alloc) {
		GIT3_ERROR_CHECK_ALLOC_ADD(&newsize, pb->nr_alloc, 1024);
		GIT3_ERROR_CHECK_ALLOC_MULTIPLY(&newsize, newsize / 2, 3);

		if (!git3__is_uint32(newsize)) {
			git3_error_set(GIT3_ERROR_NOMEMORY, "packfile too large to fit in memory.");
			return -1;
		}

		pb->nr_alloc = newsize;

		pb->object_list = git3__reallocarray(pb->object_list,
			pb->nr_alloc, sizeof(*po));
		GIT3_ERROR_CHECK_ALLOC(pb->object_list);

		if (rehash(pb) < 0)
			return -1;
	}

	po = pb->object_list + pb->nr_objects;
	memset(po, 0x0, sizeof(*po));

	if ((ret = git3_odb_read_header(&po->size, &po->type, pb->odb, oid)) < 0)
		return ret;

	pb->nr_objects++;
	git3_oid_cpy(&po->id, oid);
	po->hash = name_hash(name);

	if (git3_packbuilder_pobjectmap_put(&pb->object_ix, &po->id, po) < 0) {
		git3_error_set_oom();
		return -1;
	}

	pb->done = false;

	if (pb->progress_cb) {
		uint64_t current_time = git3_time_monotonic();
		uint64_t elapsed = current_time - pb->last_progress_report_time;

		if (elapsed >= MIN_PROGRESS_UPDATE_INTERVAL) {
			pb->last_progress_report_time = current_time;

			ret = pb->progress_cb(
				GIT3_PACKBUILDER_ADDING_OBJECTS,
				pb->nr_objects, 0, pb->progress_cb_payload);

			if (ret)
				return git3_error_set_after_callback(ret);
		}
	}

	return 0;
}

static int get_delta(void **out, git3_odb *odb, git3_pobject *po)
{
	git3_odb_object *src = NULL, *trg = NULL;
	size_t delta_size;
	void *delta_buf;
	int error;

	*out = NULL;

	if (git3_odb_read(&src, odb, &po->delta->id) < 0 ||
	    git3_odb_read(&trg, odb, &po->id) < 0)
		goto on_error;

	error = git3_delta(&delta_buf, &delta_size,
		git3_odb_object_data(src), git3_odb_object_size(src),
		git3_odb_object_data(trg), git3_odb_object_size(trg),
		0);

	if (error < 0 && error != GIT3_EBUFS)
		goto on_error;

	if (error == GIT3_EBUFS || delta_size != po->delta_size) {
		git3_error_set(GIT3_ERROR_INVALID, "delta size changed");
		goto on_error;
	}

	*out = delta_buf;

	git3_odb_object_free(src);
	git3_odb_object_free(trg);
	return 0;

on_error:
	git3_odb_object_free(src);
	git3_odb_object_free(trg);
	return -1;
}

static int write_object(
	git3_packbuilder *pb,
	git3_pobject *po,
	int (*write_cb)(void *buf, size_t size, void *cb_data),
	void *cb_data)
{
	git3_odb_object *obj = NULL;
	git3_object_t type;
	unsigned char hdr[10], *zbuf = NULL;
	void *data = NULL;
	size_t hdr_len, zbuf_len = COMPRESS_BUFLEN, data_len, oid_size;
	int error;

	oid_size = git3_oid_size(pb->oid_type);

	/*
	 * If we have a delta base, let's use the delta to save space.
	 * Otherwise load the whole object. 'data' ends up pointing to
	 * whatever data we want to put into the packfile.
	 */
	if (po->delta) {
		if (po->delta_data)
			data = po->delta_data;
		else if ((error = get_delta(&data, pb->odb, po)) < 0)
				goto done;

		data_len = po->delta_size;
		type = GIT3_PACKFILE_REF_DELTA;
	} else {
		if ((error = git3_odb_read(&obj, pb->odb, &po->id)) < 0)
			goto done;

		data = (void *)git3_odb_object_data(obj);
		data_len = git3_odb_object_size(obj);
		type = git3_odb_object_type(obj);
	}

	/* Write header */
	if ((error = git3_packfile__object_header(&hdr_len, hdr, data_len, type)) < 0 ||
	    (error = write_cb(hdr, hdr_len, cb_data)) < 0 ||
	    (error = git3_hash_update(&pb->ctx, hdr, hdr_len)) < 0)
		goto done;

	if (type == GIT3_PACKFILE_REF_DELTA) {
		if ((error = write_cb(po->delta->id.id, oid_size, cb_data)) < 0 ||
		    (error = git3_hash_update(&pb->ctx, po->delta->id.id, oid_size)) < 0)
			goto done;
	}

	/* Write data */
	if (po->z_delta_size) {
		data_len = po->z_delta_size;

		if ((error = write_cb(data, data_len, cb_data)) < 0 ||
			(error = git3_hash_update(&pb->ctx, data, data_len)) < 0)
			goto done;
	} else {
		zbuf = git3__malloc(zbuf_len);
		GIT3_ERROR_CHECK_ALLOC(zbuf);

		git3_zstream_reset(&pb->zstream);

		if ((error = git3_zstream_set_input(&pb->zstream, data, data_len)) < 0)
			goto done;

		while (!git3_zstream_done(&pb->zstream)) {
			if ((error = git3_zstream_get_output(zbuf, &zbuf_len, &pb->zstream)) < 0 ||
				(error = write_cb(zbuf, zbuf_len, cb_data)) < 0 ||
				(error = git3_hash_update(&pb->ctx, zbuf, zbuf_len)) < 0)
				goto done;

			zbuf_len = COMPRESS_BUFLEN; /* reuse buffer */
		}
	}

	/*
	 * If po->delta is true, data is a delta and it is our
	 * responsibility to free it (otherwise it's a git3_object's
	 * data). We set po->delta_data to NULL in case we got the
	 * data from there instead of get_delta(). If we didn't,
	 * there's no harm.
	 */
	if (po->delta) {
		git3__free(data);
		po->delta_data = NULL;
	}

	pb->nr_written++;

done:
	git3__free(zbuf);
	git3_odb_object_free(obj);
	return error;
}

enum write_one_status {
	WRITE_ONE_SKIP = -1, /* already written */
	WRITE_ONE_BREAK = 0, /* writing this will bust the limit; not written */
	WRITE_ONE_WRITTEN = 1, /* normal */
	WRITE_ONE_RECURSIVE = 2 /* already scheduled to be written */
};

static int write_one(
	enum write_one_status *status,
	git3_packbuilder *pb,
	git3_pobject *po,
	int (*write_cb)(void *buf, size_t size, void *cb_data),
	void *cb_data)
{
	int error;

	if (po->recursing) {
		*status = WRITE_ONE_RECURSIVE;
		return 0;
	} else if (po->written) {
		*status = WRITE_ONE_SKIP;
		return 0;
	}

	if (po->delta) {
		po->recursing = 1;

		if ((error = write_one(status, pb, po->delta, write_cb, cb_data)) < 0)
			return error;

		/* we cannot depend on this one */
		if (*status == WRITE_ONE_RECURSIVE)
			po->delta = NULL;
	}

	*status = WRITE_ONE_WRITTEN;
	po->written = 1;
	po->recursing = 0;

	return write_object(pb, po, write_cb, cb_data);
}

GIT3_INLINE(void) add_to_write_order(git3_pobject **wo, size_t *endp,
	git3_pobject *po)
{
	if (po->filled)
		return;
	wo[(*endp)++] = po;
	po->filled = 1;
}

static void add_descendants_to_write_order(git3_pobject **wo, size_t *endp,
	git3_pobject *po)
{
	int add_to_order = 1;
	while (po) {
		if (add_to_order) {
			git3_pobject *s;
			/* add this node... */
			add_to_write_order(wo, endp, po);
			/* all its siblings... */
			for (s = po->delta_sibling; s; s = s->delta_sibling) {
				add_to_write_order(wo, endp, s);
			}
		}
		/* drop down a level to add left subtree nodes if possible */
		if (po->delta_child) {
			add_to_order = 1;
			po = po->delta_child;
		} else {
			add_to_order = 0;
			/* our sibling might have some children, it is next */
			if (po->delta_sibling) {
				po = po->delta_sibling;
				continue;
			}
			/* go back to our parent node */
			po = po->delta;
			while (po && !po->delta_sibling) {
				/* we're on the right side of a subtree, keep
				 * going up until we can go right again */
				po = po->delta;
			}
			if (!po) {
				/* done- we hit our original root node */
				return;
			}
			/* pass it off to sibling at this level */
			po = po->delta_sibling;
		}
	};
}

static void add_family_to_write_order(git3_pobject **wo, size_t *endp,
	git3_pobject *po)
{
	git3_pobject *root;

	for (root = po; root->delta; root = root->delta)
		; /* nothing */
	add_descendants_to_write_order(wo, endp, root);
}

static int cb_tag_foreach(const char *name, git3_oid *oid, void *data)
{
	git3_packbuilder *pb = data;
	git3_pobject *po;

	GIT3_UNUSED(name);

	if (git3_packbuilder_pobjectmap_get(&po, &pb->object_ix, oid) != 0)
		return 0;

	po->tagged = 1;

	/* TODO: peel objects */

	return 0;
}

static int compute_write_order(git3_pobject ***out, git3_packbuilder *pb)
{
	size_t i, wo_end, last_untagged;
	git3_pobject **wo;

	*out = NULL;

	if (!pb->nr_objects)
		return 0;

	if ((wo = git3__mallocarray(pb->nr_objects, sizeof(*wo))) == NULL)
		return -1;

	for (i = 0; i < pb->nr_objects; i++) {
		git3_pobject *po = pb->object_list + i;
		po->tagged = 0;
		po->filled = 0;
		po->delta_child = NULL;
		po->delta_sibling = NULL;
	}

	/*
	 * Fully connect delta_child/delta_sibling network.
	 * Make sure delta_sibling is sorted in the original
	 * recency order.
	 */
	for (i = pb->nr_objects; i > 0;) {
		git3_pobject *po = &pb->object_list[--i];
		if (!po->delta)
			continue;
		/* Mark me as the first child */
		po->delta_sibling = po->delta->delta_child;
		po->delta->delta_child = po;
	}

	/*
	 * Mark objects that are at the tip of tags.
	 */
	if (git3_tag_foreach(pb->repo, &cb_tag_foreach, pb) < 0) {
		git3__free(wo);
		return -1;
	}

	/*
	 * Give the objects in the original recency order until
	 * we see a tagged tip.
	 */
	for (i = wo_end = 0; i < pb->nr_objects; i++) {
		git3_pobject *po = pb->object_list + i;
		if (po->tagged)
			break;
		add_to_write_order(wo, &wo_end, po);
	}
	last_untagged = i;

	/*
	 * Then fill all the tagged tips.
	 */
	for (; i < pb->nr_objects; i++) {
		git3_pobject *po = pb->object_list + i;
		if (po->tagged)
			add_to_write_order(wo, &wo_end, po);
	}

	/*
	 * And then all remaining commits and tags.
	 */
	for (i = last_untagged; i < pb->nr_objects; i++) {
		git3_pobject *po = pb->object_list + i;
		if (po->type != GIT3_OBJECT_COMMIT &&
		    po->type != GIT3_OBJECT_TAG)
			continue;
		add_to_write_order(wo, &wo_end, po);
	}

	/*
	 * And then all the trees.
	 */
	for (i = last_untagged; i < pb->nr_objects; i++) {
		git3_pobject *po = pb->object_list + i;
		if (po->type != GIT3_OBJECT_TREE)
			continue;
		add_to_write_order(wo, &wo_end, po);
	}

	/*
	 * Finally all the rest in really tight order
	 */
	for (i = last_untagged; i < pb->nr_objects; i++) {
		git3_pobject *po = pb->object_list + i;
		if (!po->filled)
			add_family_to_write_order(wo, &wo_end, po);
	}

	if (wo_end != pb->nr_objects) {
		git3__free(wo);
		git3_error_set(GIT3_ERROR_INVALID, "invalid write order");
		return -1;
	}

	*out = wo;
	return 0;
}

static int write_pack(git3_packbuilder *pb,
	int (*write_cb)(void *buf, size_t size, void *cb_data),
	void *cb_data)
{
	git3_pobject **write_order;
	git3_pobject *po;
	enum write_one_status status;
	struct git3_pack_header ph;
	git3_oid entry_oid;
	size_t i = 0;
	int error;

	if ((error = compute_write_order(&write_order, pb)) < 0)
		return error;

	if (!git3__is_uint32(pb->nr_objects)) {
		git3_error_set(GIT3_ERROR_INVALID, "too many objects");
		error = -1;
		goto done;
	}

	/* Write pack header */
	ph.hdr_signature = htonl(PACK_SIGNATURE);
	ph.hdr_version = htonl(PACK_VERSION);
	ph.hdr_entries = htonl(pb->nr_objects);

	if ((error = write_cb(&ph, sizeof(ph), cb_data)) < 0 ||
		(error = git3_hash_update(&pb->ctx, &ph, sizeof(ph))) < 0)
		goto done;

	pb->nr_remaining = pb->nr_objects;
	do {
		pb->nr_written = 0;
		for ( ; i < pb->nr_objects; ++i) {
			po = write_order[i];

			if ((error = write_one(&status, pb, po, write_cb, cb_data)) < 0)
				goto done;
		}

		pb->nr_remaining -= pb->nr_written;
	} while (pb->nr_remaining && i < pb->nr_objects);

	if ((error = git3_hash_final(entry_oid.id, &pb->ctx)) < 0)
		goto done;

	error = write_cb(entry_oid.id, git3_oid_size(pb->oid_type), cb_data);

done:
	/* if callback cancelled writing, we must still free delta_data */
	for ( ; i < pb->nr_objects; ++i) {
		po = write_order[i];
		if (po->delta_data) {
			git3__free(po->delta_data);
			po->delta_data = NULL;
		}
	}

	git3__free(write_order);
	return error;
}

static int write_pack_buf(void *buf, size_t size, void *data)
{
	git3_str *b = (git3_str *)data;
	return git3_str_put(b, buf, size);
}

static int type_size_sort(const void *_a, const void *_b)
{
	const git3_pobject *a = (git3_pobject *)_a;
	const git3_pobject *b = (git3_pobject *)_b;

	if (a->type > b->type)
		return -1;
	if (a->type < b->type)
		return 1;
	if (a->hash > b->hash)
		return -1;
	if (a->hash < b->hash)
		return 1;
	/*
	 * TODO
	 *
	if (a->preferred_base > b->preferred_base)
		return -1;
	if (a->preferred_base < b->preferred_base)
		return 1;
	*/
	if (a->size > b->size)
		return -1;
	if (a->size < b->size)
		return 1;
	return a < b ? -1 : (a > b); /* newest first */
}

static int delta_cacheable(
	git3_packbuilder *pb,
	size_t src_size,
	size_t trg_size,
	size_t delta_size)
{
	size_t new_size;

	if (git3__add_sizet_overflow(&new_size, pb->delta_cache_size, delta_size))
		return 0;

	if (pb->max_delta_cache_size && new_size > pb->max_delta_cache_size)
		return 0;

	if (delta_size < pb->cache_max_small_delta_size)
		return 1;

	/* cache delta, if objects are large enough compared to delta size */
	if ((src_size >> 20) + (trg_size >> 21) > (delta_size >> 10))
		return 1;

	return 0;
}

static int try_delta(git3_packbuilder *pb, struct unpacked *trg,
		     struct unpacked *src, size_t max_depth,
			 size_t *mem_usage, int *ret)
{
	git3_pobject *trg_object = trg->object;
	git3_pobject *src_object = src->object;
	git3_odb_object *obj;
	size_t trg_size, src_size, delta_size, sizediff, max_size, sz;
	size_t ref_depth;
	void *delta_buf;

	/* Don't bother doing diffs between different types */
	if (trg_object->type != src_object->type) {
		*ret = -1;
		return 0;
	}

	*ret = 0;

	/* TODO: support reuse-delta */

	/* Let's not bust the allowed depth. */
	if (src->depth >= max_depth)
		return 0;

	/* Now some size filtering heuristics. */
	trg_size = trg_object->size;
	if (!trg_object->delta) {
		max_size = trg_size/2 - 20;
		ref_depth = 1;
	} else {
		max_size = trg_object->delta_size;
		ref_depth = trg->depth;
	}

	max_size = (uint64_t)max_size * (max_depth - src->depth) /
					(max_depth - ref_depth + 1);
	if (max_size == 0)
		return 0;

	src_size = src_object->size;
	sizediff = src_size < trg_size ? trg_size - src_size : 0;
	if (sizediff >= max_size)
		return 0;
	if (trg_size < src_size / 32)
		return 0;

	/* Load data if not already done */
	if (!trg->data) {
		if (git3_odb_read(&obj, pb->odb, &trg_object->id) < 0)
			return -1;

		sz = git3_odb_object_size(obj);
		trg->data = git3__malloc(sz);
		GIT3_ERROR_CHECK_ALLOC(trg->data);
		memcpy(trg->data, git3_odb_object_data(obj), sz);

		git3_odb_object_free(obj);

		if (sz != trg_size) {
			git3_error_set(GIT3_ERROR_INVALID,
				   "inconsistent target object length");
			return -1;
		}

		*mem_usage += sz;
	}
	if (!src->data) {
		size_t obj_sz;

		if (git3_odb_read(&obj, pb->odb, &src_object->id) < 0 ||
			!git3__is_ulong(obj_sz = git3_odb_object_size(obj)))
			return -1;

		sz = obj_sz;
		src->data = git3__malloc(sz);
		GIT3_ERROR_CHECK_ALLOC(src->data);
		memcpy(src->data, git3_odb_object_data(obj), sz);

		git3_odb_object_free(obj);

		if (sz != src_size) {
			git3_error_set(GIT3_ERROR_INVALID,
				   "inconsistent source object length");
			return -1;
		}

		*mem_usage += sz;
	}
	if (!src->index) {
		if (git3_delta_index_init(&src->index, src->data, src_size) < 0)
			return 0; /* suboptimal pack - out of memory */

		*mem_usage += git3_delta_index_size(src->index);
	}

	if (git3_delta_create_from_index(&delta_buf, &delta_size, src->index, trg->data, trg_size,
		max_size) < 0)
		return 0;

	if (trg_object->delta) {
		/* Prefer only shallower same-sized deltas. */
		if (delta_size == trg_object->delta_size &&
		    src->depth + 1 >= trg->depth) {
			git3__free(delta_buf);
			return 0;
		}
	}

	GIT3_ASSERT(git3_packbuilder__cache_lock(pb) == 0);

	if (trg_object->delta_data) {
		git3__free(trg_object->delta_data);
		GIT3_ASSERT(pb->delta_cache_size >= trg_object->delta_size);
		pb->delta_cache_size -= trg_object->delta_size;
		trg_object->delta_data = NULL;
	}
	if (delta_cacheable(pb, src_size, trg_size, delta_size)) {
		bool overflow = git3__add_sizet_overflow(
			&pb->delta_cache_size, pb->delta_cache_size, delta_size);

		GIT3_ASSERT(git3_packbuilder__cache_unlock(pb) == 0);

		if (overflow) {
			git3__free(delta_buf);
			return -1;
		}

		trg_object->delta_data = git3__realloc(delta_buf, delta_size);
		GIT3_ERROR_CHECK_ALLOC(trg_object->delta_data);
	} else {
		/* create delta when writing the pack */
		GIT3_ASSERT(git3_packbuilder__cache_unlock(pb) == 0);
		git3__free(delta_buf);
	}

	trg_object->delta = src_object;
	trg_object->delta_size = delta_size;
	trg->depth = src->depth + 1;

	*ret = 1;
	return 0;
}

static size_t check_delta_limit(git3_pobject *me, size_t n)
{
	git3_pobject *child = me->delta_child;
	size_t m = n;

	while (child) {
		size_t c = check_delta_limit(child, n + 1);
		if (m < c)
			m = c;
		child = child->delta_sibling;
	}
	return m;
}

static size_t free_unpacked(struct unpacked *n)
{
	size_t freed_mem = 0;

	if (n->index) {
		freed_mem += git3_delta_index_size(n->index);
		git3_delta_index_free(n->index);
	}
	n->index = NULL;

	if (n->data) {
		freed_mem += n->object->size;
		git3__free(n->data);
		n->data = NULL;
	}
	n->object = NULL;
	n->depth = 0;
	return freed_mem;
}

static int report_delta_progress(
	git3_packbuilder *pb, uint32_t count, bool force)
{
	int ret;

	if (pb->failure)
		return pb->failure;

	if (pb->progress_cb) {
		uint64_t current_time = git3_time_monotonic();
		uint64_t elapsed = current_time - pb->last_progress_report_time;

		if (force || elapsed >= MIN_PROGRESS_UPDATE_INTERVAL) {
			pb->last_progress_report_time = current_time;

			ret = pb->progress_cb(
				GIT3_PACKBUILDER_DELTAFICATION,
				count, pb->nr_objects, pb->progress_cb_payload);

			if (ret) {
				pb->failure = ret;
				return git3_error_set_after_callback(ret);
			}
		}
	}

	return 0;
}

static int find_deltas(git3_packbuilder *pb, git3_pobject **list,
	size_t *list_size, size_t window, size_t depth)
{
	git3_pobject *po;
	git3_str zbuf = GIT3_STR_INIT;
	struct unpacked *array;
	size_t idx = 0, count = 0;
	size_t mem_usage = 0;
	size_t i;
	int error = -1;

	array = git3__calloc(window, sizeof(struct unpacked));
	GIT3_ERROR_CHECK_ALLOC(array);

	for (;;) {
		struct unpacked *n = array + idx;
		size_t max_depth, j, best_base = SIZE_MAX;

		GIT3_ASSERT(git3_packbuilder__progress_lock(pb) == 0);
		if (!*list_size) {
			GIT3_ASSERT(git3_packbuilder__progress_unlock(pb) == 0);
			break;
		}

		pb->nr_deltified += 1;
		if ((error = report_delta_progress(pb, pb->nr_deltified, false)) < 0) {
				GIT3_ASSERT(git3_packbuilder__progress_unlock(pb) == 0);
				goto on_error;
		}

		po = *list++;
		(*list_size)--;
		GIT3_ASSERT(git3_packbuilder__progress_unlock(pb) == 0);

		mem_usage -= free_unpacked(n);
		n->object = po;

		while (pb->window_memory_limit &&
		       mem_usage > pb->window_memory_limit &&
		       count > 1) {
			size_t tail = (idx + window - count) % window;
			mem_usage -= free_unpacked(array + tail);
			count--;
		}

		/*
		 * If the current object is at pack edge, take the depth the
		 * objects that depend on the current object into account
		 * otherwise they would become too deep.
		 */
		max_depth = depth;
		if (po->delta_child) {
			size_t delta_limit = check_delta_limit(po, 0);

			if (delta_limit > max_depth)
				goto next;

			max_depth -= delta_limit;
		}

		j = window;
		while (--j > 0) {
			int ret;
			size_t other_idx = idx + j;
			struct unpacked *m;

			if (other_idx >= window)
				other_idx -= window;

			m = array + other_idx;
			if (!m->object)
				break;

			if (try_delta(pb, n, m, max_depth, &mem_usage, &ret) < 0)
				goto on_error;
			if (ret < 0)
				break;
			else if (ret > 0)
				best_base = other_idx;
		}

		/*
		 * If we decided to cache the delta data, then it is best
		 * to compress it right away.  First because we have to do
		 * it anyway, and doing it here while we're threaded will
		 * save a lot of time in the non threaded write phase,
		 * as well as allow for caching more deltas within
		 * the same cache size limit.
		 * ...
		 * But only if not writing to stdout, since in that case
		 * the network is most likely throttling writes anyway,
		 * and therefore it is best to go to the write phase ASAP
		 * instead, as we can afford spending more time compressing
		 * between writes at that moment.
		 */
		if (po->delta_data) {
			if (git3_zstream_deflatebuf(&zbuf, po->delta_data, po->delta_size) < 0)
				goto on_error;

			git3__free(po->delta_data);
			po->delta_data = git3__malloc(zbuf.size);
			GIT3_ERROR_CHECK_ALLOC(po->delta_data);

			memcpy(po->delta_data, zbuf.ptr, zbuf.size);
			po->z_delta_size = zbuf.size;
			git3_str_clear(&zbuf);

			GIT3_ASSERT(git3_packbuilder__cache_lock(pb) == 0);
			pb->delta_cache_size -= po->delta_size;
			pb->delta_cache_size += po->z_delta_size;
			GIT3_ASSERT(git3_packbuilder__cache_unlock(pb) == 0);
		}

		/*
		 * If we made n a delta, and if n is already at max
		 * depth, leaving it in the window is pointless.  we
		 * should evict it first.
		 */
		if (po->delta && max_depth <= n->depth)
			continue;

		/*
		 * Move the best delta base up in the window, after the
		 * currently deltified object, to keep it longer.  It will
		 * be the first base object to be attempted next.
		 */
		if (po->delta) {
			struct unpacked swap = array[best_base];
			size_t dist = (window + idx - best_base) % window;
			size_t dst = best_base;
			while (dist--) {
				size_t src = (dst + 1) % window;
				array[dst] = array[src];
				dst = src;
			}
			array[dst] = swap;
		}

		next:
		idx++;
		if (count + 1 < window)
			count++;
		if (idx >= window)
			idx = 0;
	}
	error = 0;

on_error:
	for (i = 0; i < window; ++i) {
		git3__free(array[i].index);
		git3__free(array[i].data);
	}
	git3__free(array);
	git3_str_dispose(&zbuf);

	return error;
}

#ifdef GIT3_THREADS

struct thread_params {
	git3_thread thread;
	git3_packbuilder *pb;

	git3_pobject **list;

	git3_cond cond;
	git3_mutex mutex;

	size_t list_size;
	size_t remaining;

	size_t window;
	size_t depth;
	size_t working;
	size_t data_ready;

	/* A pb->progress_cb can stop the packing process by returning an error.
	   When that happens, all threads observe the error and stop voluntarily. */
	bool stopped;
};

static void *threaded_find_deltas(void *arg)
{
	struct thread_params *me = arg;

	while (me->remaining) {
		if (find_deltas(me->pb, me->list, &me->remaining,
				me->window, me->depth) < 0) {
			me->stopped = true;
			GIT3_ASSERT_WITH_RETVAL(git3_packbuilder__progress_lock(me->pb) == 0, NULL);
			me->working = false;
			git3_cond_signal(&me->pb->progress_cond);
			GIT3_ASSERT_WITH_RETVAL(git3_packbuilder__progress_unlock(me->pb) == 0, NULL);
			return NULL;
		}

		GIT3_ASSERT_WITH_RETVAL(git3_packbuilder__progress_lock(me->pb) == 0, NULL);
		me->working = 0;
		git3_cond_signal(&me->pb->progress_cond);
		GIT3_ASSERT_WITH_RETVAL(git3_packbuilder__progress_unlock(me->pb) == 0, NULL);

		if (git3_mutex_lock(&me->mutex)) {
			git3_error_set(GIT3_ERROR_THREAD, "unable to lock packfile condition mutex");
			return NULL;
		}

		while (!me->data_ready)
			git3_cond_wait(&me->cond, &me->mutex);

		/*
		 * We must not set ->data_ready before we wait on the
		 * condition because the main thread may have set it to 1
		 * before we get here. In order to be sure that new
		 * work is available if we see 1 in ->data_ready, it
		 * was initialized to 0 before this thread was spawned
		 * and we reset it to 0 right away.
		 */
		me->data_ready = 0;
		git3_mutex_unlock(&me->mutex);
	}
	/* leave ->working 1 so that this doesn't get more work assigned */
	return NULL;
}

static int ll_find_deltas(git3_packbuilder *pb, git3_pobject **list,
			  size_t list_size, size_t window, size_t depth)
{
	struct thread_params *p;
	size_t i;
	int ret, active_threads = 0;

	if (!pb->nr_threads)
		pb->nr_threads = git3__online_cpus();

	if (pb->nr_threads <= 1) {
		return find_deltas(pb, list, &list_size, window, depth);
	}

	p = git3__mallocarray(pb->nr_threads, sizeof(*p));
	GIT3_ERROR_CHECK_ALLOC(p);

	/* Partition the work among the threads */
	for (i = 0; i < pb->nr_threads; ++i) {
		size_t sub_size = list_size / (pb->nr_threads - i);

		/* don't use too small segments or no deltas will be found */
		if (sub_size < 2*window && i+1 < pb->nr_threads)
			sub_size = 0;

		p[i].pb = pb;
		p[i].window = window;
		p[i].depth = depth;
		p[i].working = 1;
		p[i].data_ready = 0;
		p[i].stopped = 0;

		/* try to split chunks on "path" boundaries */
		while (sub_size && sub_size < list_size &&
		       list[sub_size]->hash &&
		       list[sub_size]->hash == list[sub_size-1]->hash)
			sub_size++;

		p[i].list = list;
		p[i].list_size = sub_size;
		p[i].remaining = sub_size;

		list += sub_size;
		list_size -= sub_size;
	}

	/* Start work threads */
	for (i = 0; i < pb->nr_threads; ++i) {
		if (!p[i].list_size)
			continue;

		git3_mutex_init(&p[i].mutex);
		git3_cond_init(&p[i].cond);

		ret = git3_thread_create(&p[i].thread,
					threaded_find_deltas, &p[i]);
		if (ret) {
			git3_error_set(GIT3_ERROR_THREAD, "unable to create thread");
			return -1;
		}
		active_threads++;
	}

	/*
	 * Now let's wait for work completion.  Each time a thread is done
	 * with its work, we steal half of the remaining work from the
	 * thread with the largest number of unprocessed objects and give
	 * it to that newly idle thread.  This ensure good load balancing
	 * until the remaining object list segments are simply too short
	 * to be worth splitting anymore.
	 */
	while (active_threads) {
		struct thread_params *target = NULL;
		struct thread_params *victim = NULL;
		size_t sub_size = 0;

		/* Start by locating a thread that has transitioned its
		 * 'working' flag from 1 -> 0. This indicates that it is
		 * ready to receive more work using our work-stealing
		 * algorithm. */
		GIT3_ASSERT(git3_packbuilder__progress_lock(pb) == 0);
		for (;;) {
			for (i = 0; !target && i < pb->nr_threads; i++)
				if (!p[i].working)
					target = &p[i];
			if (target)
				break;
			git3_cond_wait(&pb->progress_cond, &pb->progress_mutex);
		}

		/* At this point we hold the progress lock and have located
		 * a thread to receive more work. We still need to locate a
		 * thread from which to steal work (the victim). */
		for (i = 0; i < pb->nr_threads; i++)
			if (p[i].remaining > 2*window &&
			    (!victim || victim->remaining < p[i].remaining))
				victim = &p[i];

		if (victim && !target->stopped) {
			sub_size = victim->remaining / 2;
			list = victim->list + victim->list_size - sub_size;
			while (sub_size && list[0]->hash &&
			       list[0]->hash == list[-1]->hash) {
				list++;
				sub_size--;
			}
			if (!sub_size) {
				/*
				 * It is possible for some "paths" to have
				 * so many objects that no hash boundary
				 * might be found.  Let's just steal the
				 * exact half in that case.
				 */
				sub_size = victim->remaining / 2;
				list -= sub_size;
			}
			target->list = list;
			victim->list_size -= sub_size;
			victim->remaining -= sub_size;
		}
		target->list_size = sub_size;
		target->remaining = sub_size;
		target->working = 1; /* even when target->stopped, so that we don't process this thread again */
		GIT3_ASSERT(git3_packbuilder__progress_unlock(pb) == 0);

		if (git3_mutex_lock(&target->mutex)) {
			git3_error_set(GIT3_ERROR_THREAD, "unable to lock packfile condition mutex");
			git3__free(p);
			return -1;
		}

		target->data_ready = 1;
		git3_cond_signal(&target->cond);
		git3_mutex_unlock(&target->mutex);

		if (target->stopped || !sub_size) {
			git3_thread_join(&target->thread, NULL);
			git3_cond_free(&target->cond);
			git3_mutex_free(&target->mutex);
			active_threads--;
		}
	}

	git3__free(p);
	return pb->failure;
}

#else
#define ll_find_deltas(pb, l, ls, w, d) find_deltas(pb, l, &ls, w, d)
#endif

int git3_packbuilder__prepare(git3_packbuilder *pb)
{
	git3_pobject **delta_list;
	size_t i, n = 0;
	int error;

	if (pb->nr_objects == 0 || pb->done)
		return 0; /* nothing to do */

	/*
	 * Although we do not report progress during deltafication, we
	 * at least report that we are in the deltafication stage
	 */
	if (pb->progress_cb) {
		if ((error = pb->progress_cb(GIT3_PACKBUILDER_DELTAFICATION, 0, pb->nr_objects, pb->progress_cb_payload)) < 0)
			return git3_error_set_after_callback(error);
	}

	delta_list = git3__mallocarray(pb->nr_objects, sizeof(*delta_list));
	GIT3_ERROR_CHECK_ALLOC(delta_list);

	for (i = 0; i < pb->nr_objects; ++i) {
		git3_pobject *po = pb->object_list + i;

		/* Make sure the item is within our size limits */
		if (po->size < 50 || po->size > pb->big_file_threshold)
			continue;

		delta_list[n++] = po;
	}

	if (n > 1) {
		git3__tsort((void **)delta_list, n, type_size_sort);
		if ((error = ll_find_deltas(pb, delta_list, n,
				   GIT3_PACK_WINDOW + 1,
				   GIT3_PACK_DEPTH)) < 0) {
			git3__free(delta_list);
			return error;
		}
	}

	error = report_delta_progress(pb, pb->nr_objects, true);

	pb->done = true;
	git3__free(delta_list);
	return error;
}

#define PREPARE_PACK error = git3_packbuilder__prepare(pb); if (error < 0) { return error; }

int git3_packbuilder_foreach(git3_packbuilder *pb, int (*cb)(void *buf, size_t size, void *payload), void *payload)
{
	int error;
	PREPARE_PACK;
	return write_pack(pb, cb, payload);
}

int git3_packbuilder__write_buf(git3_str *buf, git3_packbuilder *pb)
{
	int error;
	PREPARE_PACK;

	return write_pack(pb, &write_pack_buf, buf);
}

int git3_packbuilder_write_buf(git3_buf *buf, git3_packbuilder *pb)
{
	GIT3_BUF_WRAP_PRIVATE(buf, git3_packbuilder__write_buf, pb);
}

static int write_cb(void *buf, size_t len, void *payload)
{
	struct pack_write_context *ctx = payload;
	return git3_indexer_append(ctx->indexer, buf, len, ctx->stats);
}

int git3_packbuilder_write(
	git3_packbuilder *pb,
	const char *path,
	unsigned int mode,
	git3_indexer_progress_cb progress_cb,
	void *progress_cb_payload)
{
	int error = -1;
	git3_str object_path = GIT3_STR_INIT;
	git3_indexer_options opts = GIT3_INDEXER_OPTIONS_INIT;
	git3_indexer *indexer = NULL;
	git3_indexer_progress stats;
	struct pack_write_context ctx;
	int t;

	PREPARE_PACK;

	if (path == NULL) {
		if ((error = git3_repository__item_path(&object_path, pb->repo, GIT3_REPOSITORY_ITEM_OBJECTS)) < 0)
			goto cleanup;
		if ((error = git3_str_joinpath(&object_path, git3_str_cstr(&object_path), "pack")) < 0)
			goto cleanup;
		path = git3_str_cstr(&object_path);
	}

	opts.progress_cb = progress_cb;
	opts.progress_cb_payload = progress_cb_payload;

	/* TODO: SHA256 */

#ifdef GIT3_EXPERIMENTAL_SHA256
	opts.mode = mode;
	opts.odb = pb->odb;
	opts.oid_type = GIT3_OID_SHA3_256;

	error = git3_indexer_new(&indexer, path, &opts);
#else
	error = git3_indexer_new(&indexer, path, mode, pb->odb, &opts);
#endif

	if (error < 0)
		goto cleanup;

	if (!git3_repository__configmap_lookup(&t, pb->repo, GIT3_CONFIGMAP_FSYNCOBJECTFILES) && t)
		git3_indexer__set_fsync(indexer, 1);

	ctx.indexer = indexer;
	ctx.stats = &stats;

	if ((error = git3_packbuilder_foreach(pb, write_cb, &ctx)) < 0)
		goto cleanup;

	if ((error = git3_indexer_commit(indexer, &stats)) < 0)
		goto cleanup;

#ifndef GIT3_DEPRECATE_HARD
	git3_oid_cpy(&pb->pack_oid, git3_indexer_hash(indexer));
#endif

	pb->pack_name = git3__strdup(git3_indexer_name(indexer));
	GIT3_ERROR_CHECK_ALLOC(pb->pack_name);

cleanup:
	git3_indexer_free(indexer);
	git3_str_dispose(&object_path);
	return error;
}

#undef PREPARE_PACK

#ifndef GIT3_DEPRECATE_HARD
const git3_oid *git3_packbuilder_hash(git3_packbuilder *pb)
{
	return &pb->pack_oid;
}
#endif

const char *git3_packbuilder_name(git3_packbuilder *pb)
{
	return pb->pack_name;
}


static int cb_tree_walk(
	const char *root, const git3_tree_entry *entry, void *payload)
{
	int error;
	struct tree_walk_context *ctx = payload;

	/* A commit inside a tree represents a submodule commit and should be skipped. */
	if (git3_tree_entry_type(entry) == GIT3_OBJECT_COMMIT)
		return 0;

	if (!(error = git3_str_sets(&ctx->buf, root)) &&
		!(error = git3_str_puts(&ctx->buf, git3_tree_entry_name(entry))))
		error = git3_packbuilder_insert(
			ctx->pb, git3_tree_entry_id(entry), git3_str_cstr(&ctx->buf));

	return error;
}

int git3_packbuilder_insert_commit(git3_packbuilder *pb, const git3_oid *oid)
{
	git3_commit *commit;

	if (git3_commit_lookup(&commit, pb->repo, oid) < 0 ||
		git3_packbuilder_insert(pb, oid, NULL) < 0)
		return -1;

	if (git3_packbuilder_insert_tree(pb, git3_commit_tree_id(commit)) < 0)
		return -1;

	git3_commit_free(commit);
	return 0;
}

int git3_packbuilder_insert_tree(git3_packbuilder *pb, const git3_oid *oid)
{
	int error;
	git3_tree *tree = NULL;
	struct tree_walk_context context = { pb, GIT3_STR_INIT };

	if (!(error = git3_tree_lookup(&tree, pb->repo, oid)) &&
	    !(error = git3_packbuilder_insert(pb, oid, NULL)))
		error = git3_tree_walk(tree, GIT3_TREEWALK_PRE, cb_tree_walk, &context);

	git3_tree_free(tree);
	git3_str_dispose(&context.buf);
	return error;
}

int git3_packbuilder_insert_recur(git3_packbuilder *pb, const git3_oid *id, const char *name)
{
	git3_object *obj;
	int error;

	GIT3_ASSERT_ARG(pb);
	GIT3_ASSERT_ARG(id);

	if ((error = git3_object_lookup(&obj, pb->repo, id, GIT3_OBJECT_ANY)) < 0)
		return error;

	switch (git3_object_type(obj)) {
	case GIT3_OBJECT_BLOB:
		error = git3_packbuilder_insert(pb, id, name);
		break;
	case GIT3_OBJECT_TREE:
		error = git3_packbuilder_insert_tree(pb, id);
		break;
	case GIT3_OBJECT_COMMIT:
		error = git3_packbuilder_insert_commit(pb, id);
		break;
	case GIT3_OBJECT_TAG:
		if ((error = git3_packbuilder_insert(pb, id, name)) < 0)
			goto cleanup;
		error = git3_packbuilder_insert_recur(pb, git3_tag_target_id((git3_tag *) obj), NULL);
		break;

	default:
		git3_error_set(GIT3_ERROR_INVALID, "unknown object type");
		error = -1;
	}

cleanup:
	git3_object_free(obj);
	return error;
}

size_t git3_packbuilder_object_count(git3_packbuilder *pb)
{
	return pb->nr_objects;
}

size_t git3_packbuilder_written(git3_packbuilder *pb)
{
	return pb->nr_written;
}

static int lookup_walk_object(struct walk_object **out, git3_packbuilder *pb, const git3_oid *id)
{
	struct walk_object *obj;

	obj = git3_pool_mallocz(&pb->object_pool, 1);
	if (!obj) {
		git3_error_set_oom();
		return -1;
	}

	git3_oid_cpy(&obj->id, id);

	*out = obj;
	return 0;
}

static int retrieve_object(struct walk_object **out, git3_packbuilder *pb, const git3_oid *id)
{
	struct walk_object *obj;
	int error;

	error = git3_packbuilder_walk_objectmap_get(&obj, &pb->walk_objects, id);

	if (error == GIT3_ENOTFOUND) {
		if ((error = lookup_walk_object(&obj, pb, id)) < 0)
			return error;

		if ((error = git3_packbuilder_walk_objectmap_put(&pb->walk_objects, &obj->id, obj)) < 0)
			return error;
	} else if (error != 0) {
		return error;
	}

	*out = obj;
	return 0;
}

static int mark_blob_uninteresting(git3_packbuilder *pb, const git3_oid *id)
{
	int error;
	struct walk_object *obj;

	if ((error = retrieve_object(&obj, pb, id)) < 0)
		return error;

	obj->uninteresting = 1;

	return 0;
}

static int mark_tree_uninteresting(git3_packbuilder *pb, const git3_oid *id)
{
	struct walk_object *obj;
	git3_tree *tree;
	int error;
	size_t i;

	if ((error = retrieve_object(&obj, pb, id)) < 0)
		return error;

	if (obj->uninteresting)
		return 0;

	obj->uninteresting = 1;

	if ((error = git3_tree_lookup(&tree, pb->repo, id)) < 0)
		return error;

	for (i = 0; i < git3_tree_entrycount(tree); i++) {
		const git3_tree_entry *entry = git3_tree_entry_byindex(tree, i);
		const git3_oid *entry_id = git3_tree_entry_id(entry);
		switch (git3_tree_entry_type(entry)) {
		case GIT3_OBJECT_TREE:
			if ((error = mark_tree_uninteresting(pb, entry_id)) < 0)
				goto cleanup;
			break;
		case GIT3_OBJECT_BLOB:
			if ((error = mark_blob_uninteresting(pb, entry_id)) < 0)
				goto cleanup;
			break;
		default:
			/* it's a submodule or something unknown, we don't want it */
			;
		}
	}

cleanup:
	git3_tree_free(tree);
	return error;
}

/*
 * Mark the edges of the graph uninteresting. Since we start from a
 * git3_revwalk, the commits are already uninteresting, but we need to
 * mark the trees and blobs.
 */
static int mark_edges_uninteresting(git3_packbuilder *pb, git3_commit_list *commits)
{
	int error;
	git3_commit_list *list;
	git3_commit *commit;

	for (list = commits; list; list = list->next) {
		if (!list->item->uninteresting)
			continue;

		if ((error = git3_commit_lookup(&commit, pb->repo, &list->item->oid)) < 0)
			return error;

		error = mark_tree_uninteresting(pb, git3_commit_tree_id(commit));
		git3_commit_free(commit);

		if (error < 0)
			return error;
	}

	return 0;
}

static int pack_objects_insert_tree(git3_packbuilder *pb, git3_tree *tree)
{
	size_t i;
	int error;
	git3_tree *subtree;
	struct walk_object *obj;
	const char *name;

	if ((error = retrieve_object(&obj, pb, git3_tree_id(tree))) < 0)
		return error;

	if (obj->seen || obj->uninteresting)
		return 0;

	obj->seen = 1;

	if ((error = git3_packbuilder_insert(pb, &obj->id, NULL)))
		return error;

	for (i = 0; i < git3_tree_entrycount(tree); i++) {
		const git3_tree_entry *entry = git3_tree_entry_byindex(tree, i);
		const git3_oid *entry_id = git3_tree_entry_id(entry);
		switch (git3_tree_entry_type(entry)) {
		case GIT3_OBJECT_TREE:
			if ((error = git3_tree_lookup(&subtree, pb->repo, entry_id)) < 0)
				return error;

			error = pack_objects_insert_tree(pb, subtree);
			git3_tree_free(subtree);

			if (error < 0)
				return error;

			break;
		case GIT3_OBJECT_BLOB:
			if ((error = retrieve_object(&obj, pb, entry_id)) < 0)
				return error;
			if (obj->uninteresting)
				continue;
			name = git3_tree_entry_name(entry);
			if ((error = git3_packbuilder_insert(pb, entry_id, name)) < 0)
				return error;
			break;
		default:
			/* it's a submodule or something unknown, we don't want it */
			;
		}
	}


	return error;
}

static int pack_objects_insert_commit(git3_packbuilder *pb, struct walk_object *obj)
{
	int error;
	git3_commit *commit = NULL;
	git3_tree *tree = NULL;

	obj->seen = 1;

	if ((error = git3_packbuilder_insert(pb, &obj->id, NULL)) < 0)
		return error;

	if ((error = git3_commit_lookup(&commit, pb->repo, &obj->id)) < 0)
		return error;

	if ((error = git3_tree_lookup(&tree, pb->repo, git3_commit_tree_id(commit))) < 0)
		goto cleanup;

	if ((error = pack_objects_insert_tree(pb, tree)) < 0)
		goto cleanup;

cleanup:
	git3_commit_free(commit);
	git3_tree_free(tree);
	return error;
}

int git3_packbuilder_insert_walk(git3_packbuilder *pb, git3_revwalk *walk)
{
	int error;
	git3_oid id;
	struct walk_object *obj;

	GIT3_ASSERT_ARG(pb);
	GIT3_ASSERT_ARG(walk);

	if ((error = mark_edges_uninteresting(pb, walk->user_input)) < 0)
		return error;

	/*
	 * TODO: git marks the parents of the edges
	 * uninteresting. This may provide a speed advantage, but does
	 * seem to assume the remote does not have a single-commit
	 * history on the other end.
	 */

	/* walk down each tree up to the blobs and insert them, stopping when uninteresting */
	while ((error = git3_revwalk_next(&id, walk)) == 0) {
		if ((error = retrieve_object(&obj, pb, &id)) < 0)
			return error;

		if (obj->seen || obj->uninteresting)
			continue;

		if ((error = pack_objects_insert_commit(pb, obj)) < 0)
			return error;
	}

	if (error == GIT3_ITEROVER)
		error = 0;

	return error;
}

int git3_packbuilder_set_callbacks(git3_packbuilder *pb, git3_packbuilder_progress progress_cb, void *progress_cb_payload)
{
	if (!pb)
		return -1;

	pb->progress_cb = progress_cb;
	pb->progress_cb_payload = progress_cb_payload;

	return 0;
}

void git3_packbuilder_free(git3_packbuilder *pb)
{
	if (pb == NULL)
		return;

#ifdef GIT3_THREADS

	git3_mutex_free(&pb->cache_mutex);
	git3_mutex_free(&pb->progress_mutex);
	git3_cond_free(&pb->progress_cond);

#endif

	if (pb->odb)
		git3_odb_free(pb->odb);

	git3_packbuilder_pobjectmap_dispose(&pb->object_ix);

	if (pb->object_list)
		git3__free(pb->object_list);

	git3_packbuilder_walk_objectmap_dispose(&pb->walk_objects);
	git3_pool_clear(&pb->object_pool);

	git3_hash_ctx_cleanup(&pb->ctx);
	git3_zstream_free(&pb->zstream);

	git3__free(pb->pack_name);

	git3__free(pb);
}
