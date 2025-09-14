/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "odb.h"

#include <zlib.h>
#include "git3/object.h"
#include "git3/sys/odb_backend.h"
#include "futils.h"
#include "hash.h"
#include "delta.h"
#include "filter.h"
#include "repository.h"
#include "blob.h"
#include "oid.h"

#include "git3/odb_backend.h"
#include "git3/oid.h"
#include "git3/oidarray.h"

#define GIT3_ALTERNATES_FILE "info/alternates"

#define GIT3_ALTERNATES_MAX_DEPTH 5

/*
 * We work under the assumption that most objects for long-running
 * operations will be packed
 */
int git3_odb__loose_priority = GIT3_ODB_DEFAULT_LOOSE_PRIORITY;
int git3_odb__packed_priority = GIT3_ODB_DEFAULT_PACKED_PRIORITY;

bool git3_odb__strict_hash_verification = true;

typedef struct
{
	git3_odb_backend *backend;
	int priority;
	bool is_alternate;
	ino_t disk_inode;
} backend_internal;

static git3_cache *odb_cache(git3_odb *odb)
{
	git3_repository *owner = GIT3_REFCOUNT_OWNER(odb);
	if (owner != NULL) {
		return &owner->objects;
	}

	return &odb->own_cache;
}

static int odb_otype_fast(git3_object_t *type_p, git3_odb *db, const git3_oid *id);
static int load_alternates(git3_odb *odb, const char *objects_dir, int alternate_depth);
static int error_null_oid(int error, const char *message);

static git3_object_t odb_hardcoded_type(const git3_oid *id)
{
	if (!git3_oid_cmp(id, &git3_oid__empty_tree_sha1))
		return GIT3_OBJECT_TREE;

	return GIT3_OBJECT_INVALID;
}

static int odb_read_hardcoded(bool *found, git3_rawobj *raw, const git3_oid *id)
{
	git3_object_t type;

	*found = false;

	if ((type = odb_hardcoded_type(id)) == GIT3_OBJECT_INVALID)
		return 0;

	raw->type = type;
	raw->len = 0;
	raw->data = git3__calloc(1, sizeof(uint8_t));
	GIT3_ERROR_CHECK_ALLOC(raw->data);

	*found = true;
	return 0;
}

int git3_odb__format_object_header(
	size_t *written,
	char *hdr,
	size_t hdr_size,
	git3_object_size_t obj_len,
	git3_object_t obj_type)
{
	const char *type_str = git3_object_type2string(obj_type);
	int hdr_max = (hdr_size > INT_MAX-2) ? (INT_MAX-2) : (int)hdr_size;
	int len;

	len = p_snprintf(hdr, hdr_max, "%s %"PRId64, type_str, (int64_t)obj_len);

	if (len < 0 || len >= hdr_max) {
		git3_error_set(GIT3_ERROR_OS, "object header creation failed");
		return -1;
	}

	*written = (size_t)(len + 1);
	return 0;
}

int git3_odb__hashobj(git3_oid *id, git3_rawobj *obj, git3_oid_t oid_type)
{
	git3_str_vec vec[2];
	char header[64];
	size_t hdrlen;
	git3_hash_algorithm_t algorithm;
	int error;

	GIT3_ASSERT_ARG(id);
	GIT3_ASSERT_ARG(obj);

	if (!git3_object_type_is_valid(obj->type)) {
		git3_error_set(GIT3_ERROR_INVALID, "invalid object type");
		return -1;
	}

	if (!(algorithm = git3_oid_algorithm(oid_type))) {
		git3_error_set(GIT3_ERROR_INVALID, "unknown oid type");
		return -1;
	}

	if (!obj->data && obj->len != 0) {
		git3_error_set(GIT3_ERROR_INVALID, "invalid object");
		return -1;
	}

	if ((error = git3_odb__format_object_header(&hdrlen,
		header, sizeof(header), obj->len, obj->type)) < 0)
		return error;

	vec[0].data = header;
	vec[0].len = hdrlen;
	vec[1].data = obj->data;
	vec[1].len = obj->len;

	/* For QED/libgit3: Always set the type field for proper SHA3-256 support */
	id->type = oid_type;

	return git3_hash_vec(id->id, vec, 2, algorithm);
}


static git3_odb_object *odb_object__alloc(const git3_oid *oid, git3_rawobj *source)
{
	git3_odb_object *object = git3__calloc(1, sizeof(git3_odb_object));

	if (object != NULL) {
		git3_oid_cpy(&object->cached.oid, oid);
		object->cached.type = source->type;
		object->cached.size = source->len;
		object->buffer      = source->data;
	}

	return object;
}

void git3_odb_object__free(void *object)
{
	if (object != NULL) {
		git3__free(((git3_odb_object *)object)->buffer);
		git3__free(object);
	}
}

const git3_oid *git3_odb_object_id(git3_odb_object *object)
{
	return &object->cached.oid;
}

const void *git3_odb_object_data(git3_odb_object *object)
{
	return object->buffer;
}

size_t git3_odb_object_size(git3_odb_object *object)
{
	return object->cached.size;
}

git3_object_t git3_odb_object_type(git3_odb_object *object)
{
	return object->cached.type;
}

int git3_odb_object_dup(git3_odb_object **dest, git3_odb_object *source)
{
	git3_cached_obj_incref(source);
	*dest = source;
	return 0;
}

void git3_odb_object_free(git3_odb_object *object)
{
	if (object == NULL)
		return;

	git3_cached_obj_decref(object);
}

int git3_odb__hashfd(
	git3_oid *out,
	git3_file fd,
	size_t size,
	git3_object_t object_type,
	git3_oid_t oid_type)
{
	size_t hdr_len;
	char hdr[64], buffer[GIT3_BUFSIZE_FILEIO];
	git3_hash_ctx ctx;
	git3_hash_algorithm_t algorithm;
	ssize_t read_len = 0;
	int error = 0;

	if (!git3_object_type_is_valid(object_type)) {
		git3_error_set(GIT3_ERROR_INVALID, "invalid object type for hash");
		return -1;
	}

	if (!(algorithm = git3_oid_algorithm(oid_type))) {
		git3_error_set(GIT3_ERROR_INVALID, "unknown oid type");
		return -1;
	}

	if ((error = git3_hash_ctx_init(&ctx, algorithm)) < 0)
		return error;

	if ((error = git3_odb__format_object_header(&hdr_len, hdr,
		sizeof(hdr), size, object_type)) < 0)
		goto done;

	if ((error = git3_hash_update(&ctx, hdr, hdr_len)) < 0)
		goto done;

	while (size > 0 && (read_len = p_read(fd, buffer, sizeof(buffer))) > 0) {
		if ((error = git3_hash_update(&ctx, buffer, read_len)) < 0)
			goto done;

		size -= read_len;
	}

	/* If p_read returned an error code, the read obviously failed.
	 * If size is not zero, the file was truncated after we originally
	 * stat'd it, so we consider this a read failure too */
	if (read_len < 0 || size > 0) {
		git3_error_set(GIT3_ERROR_OS, "error reading file for hashing");
		error = -1;

		goto done;
	}

	error = git3_hash_final(out->id, &ctx);

	/* For QED/libgit3: Always set the type field for proper SHA3-256 support */
	out->type = oid_type;

done:
	git3_hash_ctx_cleanup(&ctx);
	return error;
}

int git3_odb__hashfd_filtered(
	git3_oid *out,
	git3_file fd,
	size_t size,
	git3_object_t object_type,
	git3_oid_t oid_type,
	git3_filter_list *fl)
{
	int error;
	git3_str raw = GIT3_STR_INIT;

	if (!fl)
		return git3_odb__hashfd(out, fd, size, object_type, oid_type);

	/* size of data is used in header, so we have to read the whole file
	 * into memory to apply filters before beginning to calculate the hash
	 */

	if (!(error = git3_futils_readbuffer_fd(&raw, fd, size))) {
		git3_str post = GIT3_STR_INIT;

		error = git3_filter_list__convert_buf(&post, fl, &raw);

		if (!error)
			error = git3_odb__hash(out, post.ptr, post.size, object_type, oid_type);

		git3_str_dispose(&post);
	}

	return error;
}

int git3_odb__hashlink(git3_oid *out, const char *path, git3_oid_t oid_type)
{
	struct stat st;
	int size;
	int result;

	if (git3_fs_path_lstat(path, &st) < 0)
		return -1;

	if (!git3__is_int(st.st_size) || (int)st.st_size < 0) {
		git3_error_set(GIT3_ERROR_FILESYSTEM, "file size overflow for 32-bit systems");
		return -1;
	}

	size = (int)st.st_size;

	if (S_ISLNK(st.st_mode)) {
		char *link_data;
		int read_len;
		size_t alloc_size;

		GIT3_ERROR_CHECK_ALLOC_ADD(&alloc_size, size, 1);
		link_data = git3__malloc(alloc_size);
		GIT3_ERROR_CHECK_ALLOC(link_data);

		read_len = p_readlink(path, link_data, size);
		if (read_len == -1) {
			git3_error_set(GIT3_ERROR_OS, "failed to read symlink data for '%s'", path);
			git3__free(link_data);
			return -1;
		}
		GIT3_ASSERT(read_len <= size);
		link_data[read_len] = '\0';

		result = git3_odb__hash(out, link_data, read_len, GIT3_OBJECT_BLOB, oid_type);
		git3__free(link_data);
	} else {
		int fd = git3_futils_open_ro(path);
		if (fd < 0)
			return -1;
		result = git3_odb__hashfd(out, fd, size, GIT3_OBJECT_BLOB, oid_type);
		p_close(fd);
	}

	return result;
}

int git3_odb__hashfile(
	git3_oid *out,
	const char *path,
	git3_object_t object_type,
	git3_oid_t oid_type)
{
	uint64_t size;
	int fd, error = 0;

	if ((fd = git3_futils_open_ro(path)) < 0)
		return fd;

	if ((error = git3_futils_filesize(&size, fd)) < 0)
		goto done;

	if (!git3__is_sizet(size)) {
		git3_error_set(GIT3_ERROR_OS, "file size overflow for 32-bit systems");
		error = -1;
		goto done;
	}

	error = git3_odb__hashfd(out, fd, (size_t)size, object_type, oid_type);

done:
	p_close(fd);
	return error;
}

#ifdef GIT3_EXPERIMENTAL_SHA256
int git3_odb_hashfile(
	git3_oid *out,
	const char *path,
	git3_object_t object_type,
	git3_oid_t oid_type)
{
	return git3_odb__hashfile(out, path, object_type, oid_type);
}
#else
int git3_odb_hashfile(
	git3_oid *out,
	const char *path,
	git3_object_t object_type)
{
	return git3_odb__hashfile(out, path, object_type, GIT3_OID_SHA3_256);
}
#endif

int git3_odb__hash(
	git3_oid *id,
	const void *data,
	size_t len,
	git3_object_t object_type,
	git3_oid_t oid_type)
{
	git3_rawobj raw;

	GIT3_ASSERT_ARG(id);

	raw.data = (void *)data;
	raw.len = len;
	raw.type = object_type;

	return git3_odb__hashobj(id, &raw, oid_type);
}

#ifdef GIT3_EXPERIMENTAL_SHA256
int git3_odb_hash(
	git3_oid *out,
	const void *data,
	size_t len,
	git3_object_t object_type,
	git3_oid_t oid_type)
{
	return git3_odb__hash(out, data, len, object_type, oid_type);
}
#else
int git3_odb_hash(
	git3_oid *out,
	const void *data,
	size_t len,
	git3_object_t type)
{
	return git3_odb__hash(out, data, len, type, GIT3_OID_SHA3_256);
}
#endif

/**
 * FAKE WSTREAM
 */

typedef struct {
	git3_odb_stream stream;
	char *buffer;
	size_t size, written;
	git3_object_t type;
} fake_wstream;

static int fake_wstream__fwrite(git3_odb_stream *_stream, const git3_oid *oid)
{
	fake_wstream *stream = (fake_wstream *)_stream;
	return _stream->backend->write(_stream->backend, oid, stream->buffer, stream->size, stream->type);
}

static int fake_wstream__write(git3_odb_stream *_stream, const char *data, size_t len)
{
	fake_wstream *stream = (fake_wstream *)_stream;

	GIT3_ASSERT(stream->written + len <= stream->size);

	memcpy(stream->buffer + stream->written, data, len);
	stream->written += len;
	return 0;
}

static void fake_wstream__free(git3_odb_stream *_stream)
{
	fake_wstream *stream = (fake_wstream *)_stream;

	git3__free(stream->buffer);
	git3__free(stream);
}

static int init_fake_wstream(git3_odb_stream **stream_p, git3_odb_backend *backend, git3_object_size_t size, git3_object_t type)
{
	fake_wstream *stream;
	size_t blobsize;

	GIT3_ERROR_CHECK_BLOBSIZE(size);
	blobsize = (size_t)size;

	stream = git3__calloc(1, sizeof(fake_wstream));
	GIT3_ERROR_CHECK_ALLOC(stream);

	stream->size = blobsize;
	stream->type = type;
	stream->buffer = git3__malloc(blobsize);
	if (stream->buffer == NULL) {
		git3__free(stream);
		return -1;
	}

	stream->stream.backend = backend;
	stream->stream.read = NULL; /* read only */
	stream->stream.write = &fake_wstream__write;
	stream->stream.finalize_write = &fake_wstream__fwrite;
	stream->stream.free = &fake_wstream__free;
	stream->stream.mode = GIT3_STREAM_WRONLY;

	*stream_p = (git3_odb_stream *)stream;
	return 0;
}

/***********************************************************
 *
 * OBJECT DATABASE PUBLIC API
 *
 * Public calls for the ODB functionality
 *
 ***********************************************************/

static int backend_sort_cmp(const void *a, const void *b)
{
	const backend_internal *backend_a = (const backend_internal *)(a);
	const backend_internal *backend_b = (const backend_internal *)(b);

	if (backend_b->priority == backend_a->priority) {
		if (backend_a->is_alternate)
			return -1;
		if (backend_b->is_alternate)
			return 1;
		return 0;
	}
	return (backend_b->priority - backend_a->priority);
}

static void normalize_options(
	git3_odb_options *opts,
	const git3_odb_options *given_opts)
{
	git3_odb_options init = GIT3_ODB_OPTIONS_INIT;

	if (given_opts)
		memcpy(opts, given_opts, sizeof(git3_odb_options));
	else
		memcpy(opts, &init, sizeof(git3_odb_options));

	if (!opts->oid_type)
		opts->oid_type = GIT3_OID_DEFAULT;
}

int git3_odb_new_ext(git3_odb **out, const git3_odb_options *opts)
{
	git3_odb *db;

	GIT3_ASSERT_ARG(out);
	GIT3_ERROR_CHECK_VERSION(opts, GIT3_ODB_OPTIONS_VERSION, "git3_odb_options");

	db = git3__calloc(1, sizeof(*db));
	GIT3_ERROR_CHECK_ALLOC(db);

	normalize_options(&db->options, opts);

	if (git3_mutex_init(&db->lock) < 0) {
		git3__free(db);
		return -1;
	}
	if (git3_cache_init(&db->own_cache) < 0) {
		git3_mutex_free(&db->lock);
		git3__free(db);
		return -1;
	}
	if (git3_vector_init(&db->backends, 4, backend_sort_cmp) < 0) {
		git3_cache_dispose(&db->own_cache);
		git3_mutex_free(&db->lock);
		git3__free(db);
		return -1;
	}

	*out = db;
	GIT3_REFCOUNT_INC(db);
	return 0;
}

int git3_odb_new(git3_odb **out)
{
	return git3_odb_new_ext(out, NULL);
}

static int add_backend_internal(
	git3_odb *odb, git3_odb_backend *backend,
	int priority, bool is_alternate, ino_t disk_inode)
{
	backend_internal *internal;

	GIT3_ASSERT_ARG(odb);
	GIT3_ASSERT_ARG(backend);

	GIT3_ERROR_CHECK_VERSION(backend, GIT3_ODB_BACKEND_VERSION, "git3_odb_backend");

	/* Check if the backend is already owned by another ODB */
	GIT3_ASSERT(!backend->odb || backend->odb == odb);

	internal = git3__malloc(sizeof(backend_internal));
	GIT3_ERROR_CHECK_ALLOC(internal);

	internal->backend = backend;
	internal->priority = priority;
	internal->is_alternate = is_alternate;
	internal->disk_inode = disk_inode;

	if (git3_mutex_lock(&odb->lock) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return -1;
	}
	if (git3_vector_insert(&odb->backends, internal) < 0) {
		git3_mutex_unlock(&odb->lock);
		git3__free(internal);
		return -1;
	}
	git3_vector_sort(&odb->backends);
	internal->backend->odb = odb;
	git3_mutex_unlock(&odb->lock);
	return 0;
}

int git3_odb_add_backend(git3_odb *odb, git3_odb_backend *backend, int priority)
{
	return add_backend_internal(odb, backend, priority, false, 0);
}

int git3_odb_add_alternate(git3_odb *odb, git3_odb_backend *backend, int priority)
{
	return add_backend_internal(odb, backend, priority, true, 0);
}

size_t git3_odb_num_backends(git3_odb *odb)
{
	size_t length;
	bool locked = true;

	GIT3_ASSERT_ARG(odb);

	if (git3_mutex_lock(&odb->lock) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		locked = false;
	}
	length = odb->backends.length;
	if (locked)
		git3_mutex_unlock(&odb->lock);
	return length;
}

static int git3_odb__error_unsupported_in_backend(const char *action)
{
	git3_error_set(GIT3_ERROR_ODB,
		"cannot %s - unsupported in the loaded odb backends", action);
	return -1;
}


int git3_odb_get_backend(git3_odb_backend **out, git3_odb *odb, size_t pos)
{
	backend_internal *internal;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(odb);


	if ((error = git3_mutex_lock(&odb->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	internal = git3_vector_get(&odb->backends, pos);

	if (!internal || !internal->backend) {
		git3_mutex_unlock(&odb->lock);

		git3_error_set(GIT3_ERROR_ODB, "no ODB backend loaded at index %" PRIuZ, pos);
		return GIT3_ENOTFOUND;
	}
	*out = internal->backend;
	git3_mutex_unlock(&odb->lock);

	return 0;
}

int git3_odb__add_default_backends(
	git3_odb *db, const char *objects_dir,
	bool as_alternates, int alternate_depth)
{
	size_t i = 0;
	struct stat st;
	ino_t inode;
	git3_odb_backend *loose, *packed;
	git3_odb_backend_loose_options loose_opts = GIT3_ODB_BACKEND_LOOSE_OPTIONS_INIT;
	git3_odb_backend_pack_options pack_opts = GIT3_ODB_BACKEND_PACK_OPTIONS_INIT;

	/* TODO: inodes are not really relevant on Win32, so we need to find
	 * a cross-platform workaround for this */
#ifdef GIT3_WIN32
	GIT3_UNUSED(i);
	GIT3_UNUSED(&st);

	inode = 0;
#else
	if (p_stat(objects_dir, &st) < 0) {
		if (as_alternates)
			/* this should warn */
			return 0;

		git3_error_set(GIT3_ERROR_ODB, "failed to load object database in '%s'", objects_dir);
		return -1;
	}

	inode = st.st_ino;

	if (git3_mutex_lock(&db->lock) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return -1;
	}
	for (i = 0; i < db->backends.length; ++i) {
		backend_internal *backend = git3_vector_get(&db->backends, i);
		if (backend->disk_inode == inode) {
			git3_mutex_unlock(&db->lock);
			return 0;
		}
	}
	git3_mutex_unlock(&db->lock);
#endif

	if (db->do_fsync)
		loose_opts.flags |= GIT3_ODB_BACKEND_LOOSE_FSYNC;

	loose_opts.oid_type = db->options.oid_type;
	pack_opts.oid_type = db->options.oid_type;

	/* add the loose object backend */
	if (git3_odb__backend_loose(&loose, objects_dir, &loose_opts) < 0 ||
		add_backend_internal(db, loose, git3_odb__loose_priority, as_alternates, inode) < 0)
		return -1;

	/* add the packed file backend */
#ifdef GIT3_EXPERIMENTAL_SHA256
	if (git3_odb_backend_pack(&packed, objects_dir, &pack_opts) < 0)
		return -1;
#else
	GIT3_UNUSED(pack_opts);

	if (git3_odb_backend_pack(&packed, objects_dir) < 0)
		return -1;
#endif

	if (add_backend_internal(db, packed, git3_odb__packed_priority, as_alternates, inode) < 0)
		return -1;

	if (git3_mutex_lock(&db->lock) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return -1;
	}
	if (!db->cgraph &&
	    git3_commit_graph_new(&db->cgraph, objects_dir, false, db->options.oid_type) < 0) {
		git3_mutex_unlock(&db->lock);
		return -1;
	}
	git3_mutex_unlock(&db->lock);

	return load_alternates(db, objects_dir, alternate_depth);
}

static int load_alternates(git3_odb *odb, const char *objects_dir, int alternate_depth)
{
	git3_str alternates_path = GIT3_STR_INIT;
	git3_str alternates_buf = GIT3_STR_INIT;
	char *buffer;
	const char *alternate;
	int result = 0;

	/* Git reports an error, we just ignore anything deeper */
	if (alternate_depth > GIT3_ALTERNATES_MAX_DEPTH)
		return 0;

	if (git3_str_joinpath(&alternates_path, objects_dir, GIT3_ALTERNATES_FILE) < 0)
		return -1;

	if (git3_fs_path_exists(alternates_path.ptr) == false) {
		git3_str_dispose(&alternates_path);
		return 0;
	}

	if (git3_futils_readbuffer(&alternates_buf, alternates_path.ptr) < 0) {
		git3_str_dispose(&alternates_path);
		return -1;
	}

	buffer = (char *)alternates_buf.ptr;

	/* add each alternate as a new backend; one alternate per line */
	while ((alternate = git3__strtok(&buffer, "\r\n")) != NULL) {
		if (*alternate == '\0' || *alternate == '#')
			continue;

		/* Relative path: build based on the current `objects` folder. */
		if (*alternate == '.') {
			if ((result = git3_str_joinpath(&alternates_path, objects_dir, alternate)) < 0)
				break;
			alternate = git3_str_cstr(&alternates_path);
		}

		if ((result = git3_odb__add_default_backends(odb, alternate, true, alternate_depth + 1)) < 0)
			break;
	}

	git3_str_dispose(&alternates_path);
	git3_str_dispose(&alternates_buf);

	return result;
}

int git3_odb_add_disk_alternate(git3_odb *odb, const char *path)
{
	return git3_odb__add_default_backends(odb, path, true, 0);
}

int git3_odb_set_commit_graph(git3_odb *odb, git3_commit_graph *cgraph)
{
	int error = 0;

	GIT3_ASSERT_ARG(odb);

	if ((error = git3_mutex_lock(&odb->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the db lock");
		return error;
	}
	git3_commit_graph_free(odb->cgraph);
	odb->cgraph = cgraph;
	git3_mutex_unlock(&odb->lock);

	return error;
}

int git3_odb_open_ext(
	git3_odb **out,
	const char *objects_dir,
	const git3_odb_options *opts)
{
	git3_odb *db;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(objects_dir);
	GIT3_ERROR_CHECK_VERSION(opts, GIT3_ODB_OPTIONS_VERSION, "git3_odb_options");

	*out = NULL;

	if (git3_odb_new_ext(&db, opts) < 0)
		return -1;

	if (git3_odb__add_default_backends(db, objects_dir, 0, 0) < 0) {
		git3_odb_free(db);
		return -1;
	}

	*out = db;
	return 0;
}

int git3_odb_open(git3_odb **out, const char *objects_dir)
{
	return git3_odb_open_ext(out, objects_dir, NULL);
}

int git3_odb__set_caps(git3_odb *odb, int caps)
{
	if (caps == GIT3_ODB_CAP_FROM_OWNER) {
		git3_repository *repo = GIT3_REFCOUNT_OWNER(odb);
		int val;

		if (!repo) {
			git3_error_set(GIT3_ERROR_ODB, "cannot access repository to set odb caps");
			return -1;
		}

		if (!git3_repository__configmap_lookup(&val, repo, GIT3_CONFIGMAP_FSYNCOBJECTFILES))
			odb->do_fsync = !!val;
	}

	return 0;
}

static void odb_free(git3_odb *db)
{
	size_t i;
	bool locked = true;

	if (git3_mutex_lock(&db->lock) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		locked = false;
	}
	for (i = 0; i < db->backends.length; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *backend = internal->backend;

		backend->free(backend);

		git3__free(internal);
	}
	if (locked)
		git3_mutex_unlock(&db->lock);

	git3_commit_graph_free(db->cgraph);
	git3_vector_dispose(&db->backends);
	git3_cache_dispose(&db->own_cache);
	git3_mutex_free(&db->lock);

	git3__memzero(db, sizeof(*db));
	git3__free(db);
}

void git3_odb_free(git3_odb *db)
{
	if (db == NULL)
		return;

	GIT3_REFCOUNT_DEC(db, odb_free);
}

static int odb_exists_1(
	git3_odb *db,
	const git3_oid *id,
	bool only_refreshed)
{
	size_t i;
	bool found = false;
	int error;

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	for (i = 0; i < db->backends.length && !found; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		if (only_refreshed && !b->refresh)
			continue;

		if (b->exists != NULL)
			found = (bool)b->exists(b, id);
	}
	git3_mutex_unlock(&db->lock);

	return (int)found;
}

int git3_odb__get_commit_graph_file(git3_commit_graph_file **out, git3_odb *db)
{
	int error = 0;
	git3_commit_graph_file *result = NULL;

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the db lock");
		return error;
	}
	if (!db->cgraph) {
		error = GIT3_ENOTFOUND;
		goto done;
	}
	error = git3_commit_graph_get_file(&result, db->cgraph);
	if (error)
		goto done;
	*out = result;

done:
	git3_mutex_unlock(&db->lock);
	return error;
}

static int odb_freshen_1(
	git3_odb *db,
	const git3_oid *id,
	bool only_refreshed)
{
	size_t i;
	bool found = false;
	int error;

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	for (i = 0; i < db->backends.length && !found; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		if (only_refreshed && !b->refresh)
			continue;

		if (b->freshen != NULL)
			found = !b->freshen(b, id);
		else if (b->exists != NULL)
			found = b->exists(b, id);
	}
	git3_mutex_unlock(&db->lock);

	return (int)found;
}

int git3_odb__freshen(git3_odb *db, const git3_oid *id)
{
	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(id);

	if (odb_freshen_1(db, id, false))
		return 1;

	if (!git3_odb_refresh(db))
		return odb_freshen_1(db, id, true);

	/* Failed to refresh, hence not found */
	return 0;
}

int git3_odb_exists(git3_odb *db, const git3_oid *id)
{
    return git3_odb_exists_ext(db, id, 0);
}

int git3_odb_exists_ext(git3_odb *db, const git3_oid *id, unsigned int flags)
{
	git3_odb_object *object;

	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(id);

	if (git3_oid_is_zero(id))
		return 0;

	if ((object = git3_cache_get_raw(odb_cache(db), id)) != NULL) {
		git3_odb_object_free(object);
		return 1;
	}

	if (odb_exists_1(db, id, false))
		return 1;

	if (!(flags & GIT3_ODB_LOOKUP_NO_REFRESH) && !git3_odb_refresh(db))
		return odb_exists_1(db, id, true);

	/* Failed to refresh, hence not found */
	return 0;
}

static int odb_exists_prefix_1(git3_oid *out, git3_odb *db,
	const git3_oid *key, size_t len, bool only_refreshed)
{
	size_t i;
	int error = GIT3_ENOTFOUND, num_found = 0;
	git3_oid last_found = GIT3_OID_NONE, found;

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	error = GIT3_ENOTFOUND;
	for (i = 0; i < db->backends.length; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		if (only_refreshed && !b->refresh)
			continue;

		if (!b->exists_prefix)
			continue;

		error = b->exists_prefix(&found, b, key, len);
		if (error == GIT3_ENOTFOUND || error == GIT3_PASSTHROUGH)
			continue;
		if (error) {
			git3_mutex_unlock(&db->lock);
			return error;
		}

		/* make sure found item doesn't introduce ambiguity */
		if (num_found) {
			if (git3_oid__cmp(&last_found, &found)) {
				git3_mutex_unlock(&db->lock);
				return git3_odb__error_ambiguous("multiple matches for prefix");
			}
		} else {
			git3_oid_cpy(&last_found, &found);
			num_found++;
		}
	}
	git3_mutex_unlock(&db->lock);

	if (!num_found)
		return GIT3_ENOTFOUND;

	if (out)
		git3_oid_cpy(out, &last_found);

	return 0;
}

int git3_odb_exists_prefix(
	git3_oid *out, git3_odb *db, const git3_oid *short_id, size_t len)
{
	int error;
	git3_oid key = GIT3_OID_NONE;

	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(short_id);

	if (len < GIT3_OID_MINPREFIXLEN)
		return git3_odb__error_ambiguous("prefix length too short");

	if (len >= git3_oid_hexsize(db->options.oid_type)) {
		if (git3_odb_exists(db, short_id)) {
			if (out)
				git3_oid_cpy(out, short_id);
			return 0;
		} else {
			return git3_odb__error_notfound(
				"no match for id prefix", short_id, len);
		}
	}

	git3_oid__cpy_prefix(&key, short_id, len);

	error = odb_exists_prefix_1(out, db, &key, len, false);

	if (error == GIT3_ENOTFOUND && !git3_odb_refresh(db))
		error = odb_exists_prefix_1(out, db, &key, len, true);

	if (error == GIT3_ENOTFOUND)
		return git3_odb__error_notfound("no match for id prefix", &key, len);

	return error;
}

int git3_odb_expand_ids(
	git3_odb *db,
	git3_odb_expand_id *ids,
	size_t count)
{
	size_t hex_size, i;

	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(ids);

	hex_size = git3_oid_hexsize(db->options.oid_type);

	for (i = 0; i < count; i++) {
		git3_odb_expand_id *query = &ids[i];
		int error = GIT3_EAMBIGUOUS;

		if (!query->type)
			query->type = GIT3_OBJECT_ANY;

		/* if we have a short OID, expand it first */
		if (query->length >= GIT3_OID_MINPREFIXLEN && query->length < hex_size) {
			git3_oid actual_id;

			error = odb_exists_prefix_1(&actual_id, db, &query->id, query->length, false);
			if (!error) {
				git3_oid_cpy(&query->id, &actual_id);
				query->length = (unsigned short)hex_size;
			}
		}

		/*
		 * now we ought to have a 40-char OID, either because we've expanded it
		 * or because the user passed a full OID. Ensure its type is right.
		 */
		if (query->length >= hex_size) {
			git3_object_t actual_type;

			error = odb_otype_fast(&actual_type, db, &query->id);
			if (!error) {
				if (query->type != GIT3_OBJECT_ANY && query->type != actual_type)
					error = GIT3_ENOTFOUND;
				else
					query->type = actual_type;
			}
		}

		switch (error) {
		/* no errors, so we've successfully expanded the OID */
		case 0:
			continue;

		/* the object is missing or ambiguous */
		case GIT3_ENOTFOUND:
		case GIT3_EAMBIGUOUS:
			git3_oid_clear(&query->id, db->options.oid_type);
			query->length = 0;
			query->type = 0;
			break;

		/* something went very wrong with the ODB; bail hard */
		default:
			return error;
		}
	}

	git3_error_clear();
	return 0;
}

int git3_odb_read_header(size_t *len_p, git3_object_t *type_p, git3_odb *db, const git3_oid *id)
{
	int error;
	git3_odb_object *object = NULL;

	error = git3_odb__read_header_or_object(&object, len_p, type_p, db, id);

	if (object)
		git3_odb_object_free(object);

	return error;
}

static int odb_read_header_1(
	size_t *len_p, git3_object_t *type_p, git3_odb *db,
	const git3_oid *id, bool only_refreshed)
{
	size_t i;
	git3_object_t ht;
	bool passthrough = false;
	int error;

	if (!only_refreshed && (ht = odb_hardcoded_type(id)) != GIT3_OBJECT_INVALID) {
		*type_p = ht;
		*len_p = 0;
		return 0;
	}

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	for (i = 0; i < db->backends.length; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		if (only_refreshed && !b->refresh)
			continue;

		if (!b->read_header) {
			passthrough = true;
			continue;
		}

		error = b->read_header(len_p, type_p, b, id);

		switch (error) {
		case GIT3_PASSTHROUGH:
			passthrough = true;
			break;
		case GIT3_ENOTFOUND:
			break;
		default:
			git3_mutex_unlock(&db->lock);
			return error;
		}
	}
	git3_mutex_unlock(&db->lock);

	return passthrough ? GIT3_PASSTHROUGH : GIT3_ENOTFOUND;
}

int git3_odb__read_header_or_object(
	git3_odb_object **out, size_t *len_p, git3_object_t *type_p,
	git3_odb *db, const git3_oid *id)
{
	int error = GIT3_ENOTFOUND;
	git3_odb_object *object;

	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(id);
	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(len_p);
	GIT3_ASSERT_ARG(type_p);

	*out = NULL;

	if (git3_oid_is_zero(id))
		return error_null_oid(GIT3_ENOTFOUND, "cannot read object");

	if ((object = git3_cache_get_raw(odb_cache(db), id)) != NULL) {
		*len_p = object->cached.size;
		*type_p = object->cached.type;
		*out = object;
		return 0;
	}

	error = odb_read_header_1(len_p, type_p, db, id, false);

	if (error == GIT3_ENOTFOUND && !git3_odb_refresh(db))
		error = odb_read_header_1(len_p, type_p, db, id, true);

	if (error == GIT3_ENOTFOUND)
		return git3_odb__error_notfound("cannot read header for", id, git3_oid_hexsize(db->options.oid_type));

	/* we found the header; return early */
	if (!error)
		return 0;

	if (error == GIT3_PASSTHROUGH) {
		/*
		 * no backend has header-reading functionality
		 * so try using `git3_odb_read` instead
		 */
		error = git3_odb_read(&object, db, id);
		if (!error) {
			*len_p = object->cached.size;
			*type_p = object->cached.type;
			*out = object;
		}
	}

	return error;
}

static int odb_read_1(
	git3_odb_object **out,
	git3_odb *db,
	const git3_oid *id,
	bool only_refreshed)
{
	size_t i;
	git3_rawobj raw;
	git3_odb_object *object;
	git3_oid hashed;
	bool found = false;
	int error = 0;

	if (!only_refreshed) {
		if ((error = odb_read_hardcoded(&found, &raw, id)) < 0)
			return error;
	}

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	for (i = 0; i < db->backends.length && !found; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		if (only_refreshed && !b->refresh)
			continue;

		if (b->read != NULL) {
			error = b->read(&raw.data, &raw.len, &raw.type, b, id);
			if (error == GIT3_PASSTHROUGH || error == GIT3_ENOTFOUND)
				continue;

			if (error < 0) {
				git3_mutex_unlock(&db->lock);
				return error;
			}

			found = true;
		}
	}
	git3_mutex_unlock(&db->lock);

	if (!found)
		return GIT3_ENOTFOUND;

	if (git3_odb__strict_hash_verification) {
		if ((error = git3_odb__hash(&hashed, raw.data, raw.len, raw.type, db->options.oid_type)) < 0)
			goto out;

		if (!git3_oid_equal(id, &hashed)) {
			error = git3_odb__error_mismatch(id, &hashed);
			goto out;
		}
	}

	git3_error_clear();
	if ((object = odb_object__alloc(id, &raw)) == NULL) {
		error = -1;
		goto out;
	}

	*out = git3_cache_store_raw(odb_cache(db), object);

out:
	if (error)
		git3__free(raw.data);
	return error;
}

int git3_odb_read(git3_odb_object **out, git3_odb *db, const git3_oid *id)
{
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(db);
	GIT3_ASSERT_ARG(id);

	if (git3_oid_is_zero(id))
		return error_null_oid(GIT3_ENOTFOUND, "cannot read object");

	*out = git3_cache_get_raw(odb_cache(db), id);
	if (*out != NULL)
		return 0;

	error = odb_read_1(out, db, id, false);

	if (error == GIT3_ENOTFOUND && !git3_odb_refresh(db))
		error = odb_read_1(out, db, id, true);

	if (error == GIT3_ENOTFOUND)
		return git3_odb__error_notfound("no match for id", id, git3_oid_hexsize(git3_oid_type(id)));

	return error;
}

static int odb_otype_fast(git3_object_t *type_p, git3_odb *db, const git3_oid *id)
{
	git3_odb_object *object;
	size_t _unused;
	int error;

	if (git3_oid_is_zero(id))
		return error_null_oid(GIT3_ENOTFOUND, "cannot get object type");

	if ((object = git3_cache_get_raw(odb_cache(db), id)) != NULL) {
		*type_p = object->cached.type;
		git3_odb_object_free(object);
		return 0;
	}

	error = odb_read_header_1(&_unused, type_p, db, id, false);

	if (error == GIT3_PASSTHROUGH) {
		error = odb_read_1(&object, db, id, false);
		if (!error)
			*type_p = object->cached.type;
		git3_odb_object_free(object);
	}

	return error;
}

static int read_prefix_1(git3_odb_object **out, git3_odb *db,
		const git3_oid *key, size_t len, bool only_refreshed)
{
	size_t i;
	int error = 0;
	git3_oid found_full_oid = GIT3_OID_NONE;
	git3_rawobj raw = {0};
	void *data = NULL;
	bool found = false;
	git3_odb_object *object;

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	for (i = 0; i < db->backends.length; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		if (only_refreshed && !b->refresh)
			continue;

		if (b->read_prefix != NULL) {
			git3_oid full_oid;
			error = b->read_prefix(&full_oid, &raw.data, &raw.len, &raw.type, b, key, len);

			if (error == GIT3_ENOTFOUND || error == GIT3_PASSTHROUGH) {
				error = 0;
				continue;
			}

			if (error) {
				git3_mutex_unlock(&db->lock);
				goto out;
			}

			git3__free(data);
			data = raw.data;

			if (found && git3_oid__cmp(&full_oid, &found_full_oid)) {
				git3_str buf = GIT3_STR_INIT;
				const char *idstr;

				if ((idstr = git3_oid_tostr_s(&full_oid)) == NULL) {
					git3_str_puts(&buf, "failed to parse object id");
				} else {
					git3_str_printf(&buf, "multiple matches for prefix: %s", idstr);

					if ((idstr = git3_oid_tostr_s(&found_full_oid)) != NULL)
						git3_str_printf(&buf, " %s", idstr);
				}

				error = git3_odb__error_ambiguous(buf.ptr);
				git3_str_dispose(&buf);
				git3_mutex_unlock(&db->lock);
				goto out;
			}

			found_full_oid = full_oid;
			found = true;
		}
	}
	git3_mutex_unlock(&db->lock);

	if (!found)
		return GIT3_ENOTFOUND;

	if (git3_odb__strict_hash_verification) {
		git3_oid hash;

		if ((error = git3_odb__hash(&hash, raw.data, raw.len, raw.type, db->options.oid_type)) < 0)
			goto out;

		if (!git3_oid_equal(&found_full_oid, &hash)) {
			error = git3_odb__error_mismatch(&found_full_oid, &hash);
			goto out;
		}
	}

	if ((object = odb_object__alloc(&found_full_oid, &raw)) == NULL) {
		error = -1;
		goto out;
	}

	*out = git3_cache_store_raw(odb_cache(db), object);

out:
	if (error)
		git3__free(raw.data);

	return error;
}

int git3_odb_read_prefix(
	git3_odb_object **out, git3_odb *db, const git3_oid *short_id, size_t len)
{
	git3_oid key = GIT3_OID_NONE;
	size_t hex_size;
	int error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(db);

	hex_size = git3_oid_hexsize(db->options.oid_type);

	if (len < GIT3_OID_MINPREFIXLEN)
		return git3_odb__error_ambiguous("prefix length too short");

	if (len > hex_size)
		len = hex_size;

	if (len == hex_size) {
		*out = git3_cache_get_raw(odb_cache(db), short_id);
		if (*out != NULL)
			return 0;
	}

	git3_oid__cpy_prefix(&key, short_id, len);

	error = read_prefix_1(out, db, &key, len, false);

	if (error == GIT3_ENOTFOUND && !git3_odb_refresh(db))
		error = read_prefix_1(out, db, &key, len, true);

	if (error == GIT3_ENOTFOUND)
		return git3_odb__error_notfound("no match for prefix", &key, len);

	return error;
}

int git3_odb_foreach(git3_odb *db, git3_odb_foreach_cb cb, void *payload)
{
	unsigned int i;
	git3_vector backends = GIT3_VECTOR_INIT;
	backend_internal *internal;
	int error = 0;

	/* Make a copy of the backends vector to invoke the callback without holding the lock. */
	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		goto cleanup;
	}
	error = git3_vector_dup(&backends, &db->backends, NULL);
	git3_mutex_unlock(&db->lock);

	if (error < 0)
		goto cleanup;

	git3_vector_foreach(&backends, i, internal) {
		git3_odb_backend *b = internal->backend;
		error = b->foreach(b, cb, payload);
		if (error != 0)
			goto cleanup;
	}

cleanup:
	git3_vector_dispose(&backends);

	return error;
}

int git3_odb_write(
	git3_oid *oid, git3_odb *db, const void *data, size_t len, git3_object_t type)
{
	size_t i;
	int error;
	git3_odb_stream *stream;

	GIT3_ASSERT_ARG(oid);
	GIT3_ASSERT_ARG(db);

	if ((error = git3_odb__hash(oid, data, len, type, db->options.oid_type)) < 0)
		return error;

	if (git3_oid_is_zero(oid))
		return error_null_oid(GIT3_EINVALID, "cannot write object");

	if (git3_odb__freshen(db, oid))
		return 0;

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	for (i = 0, error = GIT3_ERROR; i < db->backends.length && error < 0; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		/* we don't write in alternates! */
		if (internal->is_alternate)
			continue;

		if (b->write != NULL)
			error = b->write(b, oid, data, len, type);
	}
	git3_mutex_unlock(&db->lock);

	if (!error || error == GIT3_PASSTHROUGH)
		return 0;

	/* if no backends were able to write the object directly, we try a
	 * streaming write to the backends; just write the whole object into the
	 * stream in one push
	 */
	if ((error = git3_odb_open_wstream(&stream, db, len, type)) != 0)
		return error;

	if ((error = stream->write(stream, data, len)) == 0)
		error = stream->finalize_write(stream, oid);

	git3_odb_stream_free(stream);
	return error;
}

static int hash_header(git3_hash_ctx *ctx, git3_object_size_t size, git3_object_t type)
{
	char header[64];
	size_t hdrlen;
	int error;

	 if ((error = git3_odb__format_object_header(&hdrlen,
		header, sizeof(header), size, type)) < 0)
		return error;

	return git3_hash_update(ctx, header, hdrlen);
}

int git3_odb_open_wstream(
	git3_odb_stream **stream, git3_odb *db, git3_object_size_t size, git3_object_t type)
{
	size_t i, writes = 0;
	int error = GIT3_ERROR;
	git3_hash_ctx *ctx = NULL;

	GIT3_ASSERT_ARG(stream);
	GIT3_ASSERT_ARG(db);

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	error = GIT3_ERROR;
	for (i = 0; i < db->backends.length && error < 0; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		/* we don't write in alternates! */
		if (internal->is_alternate)
			continue;

		if (b->writestream != NULL) {
			++writes;
			error = b->writestream(stream, b, size, type);
		} else if (b->write != NULL) {
			++writes;
			error = init_fake_wstream(stream, b, size, type);
		}
	}
	git3_mutex_unlock(&db->lock);

	if (error < 0) {
		if (error == GIT3_PASSTHROUGH)
			error = 0;
		else if (!writes)
			error = git3_odb__error_unsupported_in_backend("write object");

		goto done;
	}

	ctx = git3__malloc(sizeof(git3_hash_ctx));
	GIT3_ERROR_CHECK_ALLOC(ctx);

	if ((error = git3_hash_ctx_init(ctx, git3_oid_algorithm(db->options.oid_type))) < 0 ||
	    (error = hash_header(ctx, size, type)) < 0)
		goto done;

#ifdef GIT3_EXPERIMENTAL_SHA256
	(*stream)->oid_type = db->options.oid_type;
#endif
	(*stream)->hash_ctx = ctx;
	(*stream)->declared_size = size;
	(*stream)->received_bytes = 0;

done:
	if (error)
		git3__free(ctx);
	return error;
}

static int git3_odb_stream__invalid_length(
	const git3_odb_stream *stream,
	const char *action)
{
	git3_error_set(GIT3_ERROR_ODB,
		"cannot %s - "
		"Invalid length. %"PRId64" was expected. The "
		"total size of the received chunks amounts to %"PRId64".",
		action, stream->declared_size, stream->received_bytes);

	return -1;
}

int git3_odb_stream_write(git3_odb_stream *stream, const char *buffer, size_t len)
{
	git3_hash_update(stream->hash_ctx, buffer, len);

	stream->received_bytes += len;

	if (stream->received_bytes > stream->declared_size)
		return git3_odb_stream__invalid_length(stream,
			"stream_write()");

	return stream->write(stream, buffer, len);
}

int git3_odb_stream_finalize_write(git3_oid *out, git3_odb_stream *stream)
{
	if (stream->received_bytes != stream->declared_size)
		return git3_odb_stream__invalid_length(stream,
			"stream_finalize_write()");

	git3_hash_final(out->id, stream->hash_ctx);

#ifdef GIT3_EXPERIMENTAL_SHA256
	out->type = stream->oid_type;
#endif

	if (git3_odb__freshen(stream->backend->odb, out))
		return 0;

	return stream->finalize_write(stream, out);
}

int git3_odb_stream_read(git3_odb_stream *stream, char *buffer, size_t len)
{
	return stream->read(stream, buffer, len);
}

void git3_odb_stream_free(git3_odb_stream *stream)
{
	if (stream == NULL)
		return;

	if (stream->hash_ctx)
		git3_hash_ctx_cleanup(stream->hash_ctx);
	git3__free(stream->hash_ctx);
	stream->free(stream);
}

int git3_odb_open_rstream(
	git3_odb_stream **stream,
	size_t *len,
	git3_object_t *type,
	git3_odb *db,
	const git3_oid *oid)
{
	size_t i, reads = 0;
	int error = GIT3_ERROR;

	GIT3_ASSERT_ARG(stream);
	GIT3_ASSERT_ARG(db);

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	error = GIT3_ERROR;
	for (i = 0; i < db->backends.length && error < 0; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		if (b->readstream != NULL) {
			++reads;
			error = b->readstream(stream, len, type, b, oid);
		}
	}
	git3_mutex_unlock(&db->lock);

	if (error == GIT3_PASSTHROUGH)
		error = 0;
	if (error < 0 && !reads)
		error = git3_odb__error_unsupported_in_backend("read object streamed");

	return error;
}

int git3_odb_write_pack(struct git3_odb_writepack **out, git3_odb *db, git3_indexer_progress_cb progress_cb, void *progress_payload)
{
	size_t i, writes = 0;
	int error = GIT3_ERROR;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(db);

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	error = GIT3_ERROR;
	for (i = 0; i < db->backends.length && error < 0; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		/* we don't write in alternates! */
		if (internal->is_alternate)
			continue;

		if (b->writepack != NULL) {
			++writes;
			error = b->writepack(out, b, db, progress_cb, progress_payload);
		}
	}
	git3_mutex_unlock(&db->lock);

	if (error == GIT3_PASSTHROUGH)
		error = 0;
	if (error < 0 && !writes)
		error = git3_odb__error_unsupported_in_backend("write pack");

	return error;
}

int git3_odb_write_multi_pack_index(git3_odb *db)
{
	size_t i, writes = 0;
	int error = GIT3_ERROR;

	GIT3_ASSERT_ARG(db);

	for (i = 0; i < db->backends.length && error < 0; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		/* we don't write in alternates! */
		if (internal->is_alternate)
			continue;

		if (b->writemidx != NULL) {
			++writes;
			error = b->writemidx(b);
		}
	}

	if (error == GIT3_PASSTHROUGH)
		error = 0;
	if (error < 0 && !writes)
		error = git3_odb__error_unsupported_in_backend("write multi-pack-index");

	return error;
}

void *git3_odb_backend_data_alloc(git3_odb_backend *backend, size_t len)
{
	GIT3_UNUSED(backend);
	return git3__malloc(len);
}

#ifndef GIT3_DEPRECATE_HARD
void *git3_odb_backend_malloc(git3_odb_backend *backend, size_t len)
{
	return git3_odb_backend_data_alloc(backend, len);
}
#endif

void git3_odb_backend_data_free(git3_odb_backend *backend, void *data)
{
	GIT3_UNUSED(backend);
	git3__free(data);
}

int git3_odb_refresh(git3_odb *db)
{
	size_t i;
	int error;

	GIT3_ASSERT_ARG(db);

	if ((error = git3_mutex_lock(&db->lock)) < 0) {
		git3_error_set(GIT3_ERROR_ODB, "failed to acquire the odb lock");
		return error;
	}
	for (i = 0; i < db->backends.length; ++i) {
		backend_internal *internal = git3_vector_get(&db->backends, i);
		git3_odb_backend *b = internal->backend;

		if (b->refresh != NULL) {
			int error = b->refresh(b);
			if (error < 0) {
				git3_mutex_unlock(&db->lock);
				return error;
			}
		}
	}
	if (db->cgraph)
		git3_commit_graph_refresh(db->cgraph);
	git3_mutex_unlock(&db->lock);

	return 0;
}

int git3_odb__error_mismatch(const git3_oid *expected, const git3_oid *actual)
{
	char expected_oid[GIT3_OID_MAX_HEXSIZE + 1],
	     actual_oid[GIT3_OID_MAX_HEXSIZE + 1];

	git3_oid_tostr(expected_oid, git3_oid_hexsize(git3_oid_type(expected)) + 1, expected);
	git3_oid_tostr(actual_oid, git3_oid_hexsize(git3_oid_type(actual)) + 1, actual);

	git3_error_set(GIT3_ERROR_ODB, "object hash mismatch - expected %s but got %s",
		expected_oid, actual_oid);

	return GIT3_EMISMATCH;
}

int git3_odb__error_notfound(
	const char *message, const git3_oid *oid, size_t oid_len)
{
	if (oid != NULL) {
		char oid_str[GIT3_OID_MAX_HEXSIZE + 1];
		git3_oid_tostr(oid_str, oid_len+1, oid);
		git3_error_set(GIT3_ERROR_ODB, "object not found - %s (%.*s)",
			message, (int) oid_len, oid_str);
	} else
		git3_error_set(GIT3_ERROR_ODB, "object not found - %s", message);

	return GIT3_ENOTFOUND;
}

static int error_null_oid(int error, const char *message)
{
	git3_error_set(GIT3_ERROR_ODB, "odb: %s: null OID cannot exist", message);
	return error;
}

int git3_odb__error_ambiguous(const char *message)
{
	git3_error_set(GIT3_ERROR_ODB, "ambiguous OID prefix - %s", message);
	return GIT3_EAMBIGUOUS;
}

int git3_odb_init_backend(git3_odb_backend *backend, unsigned int version)
{
	GIT3_INIT_STRUCTURE_FROM_TEMPLATE(
		backend, version, git3_odb_backend, GIT3_ODB_BACKEND_INIT);
	return 0;
}
