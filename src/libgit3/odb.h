/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_odb_h__
#define INCLUDE_odb_h__

#include "common.h"

#include "git3/odb.h"
#include "git3/odb_backend.h"
#include "git3/oid.h"
#include "git3/types.h"
#include "git3/sys/commit_graph.h"

#include "cache.h"
#include "commit_graph.h"
#include "filter.h"
#include "posix.h"
#include "vector.h"

#define GIT3_OBJECTS_DIR "objects/"
#define GIT3_OBJECT_DIR_MODE 0777
#define GIT3_OBJECT_FILE_MODE 0444

#define GIT3_ODB_DEFAULT_LOOSE_PRIORITY 1
#define GIT3_ODB_DEFAULT_PACKED_PRIORITY 2

extern bool git3_odb__strict_hash_verification;

/* DO NOT EXPORT */
typedef struct {
	void *data;			/**< Raw, decompressed object data. */
	size_t len;			/**< Total number of bytes in data. */
	git3_object_t type;		/**< Type of this object. */
} git3_rawobj;

/* EXPORT */
struct git3_odb_object {
	git3_cached_obj cached;
	void *buffer;
};

/* EXPORT */
struct git3_odb {
	git3_refcount rc;
	git3_mutex lock;  /* protects backends */
	git3_odb_options options;
	git3_vector backends;
	git3_cache own_cache;
	git3_commit_graph *cgraph;
	unsigned int do_fsync :1;
};

typedef enum {
	GIT3_ODB_CAP_FROM_OWNER = -1
} git3_odb_cap_t;

/*
 * Set the capabilities for the object database.
 */
int git3_odb__set_caps(git3_odb *odb, int caps);

/*
 * Add the default loose and packed backends for a database.
 */
int git3_odb__add_default_backends(
	git3_odb *db, const char *objects_dir,
	bool as_alternates, int alternate_depth);

/*
 * Hash a git3_rawobj internally.
 * The `git3_rawobj` is supposed to be previously initialized
 */
int git3_odb__hashobj(git3_oid *id, git3_rawobj *obj, git3_oid_t oid_type);

/*
 * Format the object header such as it would appear in the on-disk object
 */
int git3_odb__format_object_header(size_t *out_len, char *hdr, size_t hdr_size, git3_object_size_t obj_len, git3_object_t obj_type);

/*
 * Hash an open file descriptor.
 * This is a performance call when the contents of a fd need to be hashed,
 * but the fd is already open and we have the size of the contents.
 *
 * Saves us some `stat` calls.
 *
 * The fd is never closed, not even on error. It must be opened and closed
 * by the caller
 */
int git3_odb__hashfd(
	git3_oid *out,
	git3_file fd,
	size_t size,
	git3_object_t object_type,
	git3_oid_t oid_type);

/*
 * Hash an open file descriptor applying an array of filters
 * Acts just like git3_odb__hashfd with the addition of filters...
 */
int git3_odb__hashfd_filtered(
	git3_oid *out,
	git3_file fd,
	size_t len,
	git3_object_t object_type,
	git3_oid_t oid_type,
	git3_filter_list *fl);

/*
 * Hash a `path`, assuming it could be a POSIX symlink: if the path is a
 * symlink, then the raw contents of the symlink will be hashed. Otherwise,
 * this will fallback to `git3_odb__hashfd`.
 *
 * The hash type for this call is always `GIT3_OBJECT_BLOB` because
 * symlinks may only point to blobs.
 */
int git3_odb__hashlink(git3_oid *out, const char *path, git3_oid_t oid_type);

/**
 * Generate a GIT3_EMISMATCH error for the ODB.
 */
int git3_odb__error_mismatch(
	const git3_oid *expected, const git3_oid *actual);

/*
 * Generate a GIT3_ENOTFOUND error for the ODB.
 */
int git3_odb__error_notfound(
	const char *message, const git3_oid *oid, size_t oid_len);

/*
 * Generate a GIT3_EAMBIGUOUS error for the ODB.
 */
int git3_odb__error_ambiguous(const char *message);

/*
 * Attempt to read object header or just return whole object if it could
 * not be read.
 */
int git3_odb__read_header_or_object(
	git3_odb_object **out, size_t *len_p, git3_object_t *type_p,
	git3_odb *db, const git3_oid *id);

/*
 * Attempt to get the ODB's commit-graph file. This object is still owned by
 * the ODB. If the repository does not contain a commit-graph, it will return
 * GIT3_ENOTFOUND.
 */
int git3_odb__get_commit_graph_file(git3_commit_graph_file **out, git3_odb *odb);

/* freshen an entry in the object database */
int git3_odb__freshen(git3_odb *db, const git3_oid *id);

/* fully free the object; internal method, DO NOT EXPORT */
void git3_odb_object__free(void *object);

/* SHA256 support */

int git3_odb__hash(
	git3_oid *out,
	const void *data,
	size_t len,
	git3_object_t object_type,
	git3_oid_t oid_type);

int git3_odb__hashfile(
	git3_oid *out,
	const char *path,
	git3_object_t object_type,
	git3_oid_t oid_type);

int git3_odb__backend_loose(
	git3_odb_backend **out,
	const char *objects_dir,
	git3_odb_backend_loose_options *opts);

#ifndef GIT3_EXPERIMENTAL_SHA256

int git3_odb_open_ext(
	git3_odb **odb_out,
	const char *objects_dir,
	const git3_odb_options *opts);

int git3_odb_new_ext(
	git3_odb **odb,
	const git3_odb_options *opts);

#endif

#endif
