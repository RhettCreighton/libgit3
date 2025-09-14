/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "buf.h"
#include "futils.h"
#include "hash.h"
#include "odb.h"
#include "array.h"
#include "pack-objects.h"

#include "git3/odb_backend.h"
#include "git3/object.h"
#include "git3/types.h"
#include "git3/pack.h"
#include "git3/sys/odb_backend.h"
#include "git3/sys/mempack.h"

struct memobject {
	git3_oid oid;
	size_t len;
	git3_object_t type;
	char data[GIT3_FLEX_ARRAY];
};

GIT3_HASHMAP_OID_SETUP(git3_odb_mempack_oidmap, struct memobject *);

struct memory_packer_db {
	git3_odb_backend parent;
	git3_odb_mempack_oidmap objects;
	git3_array_t(struct memobject *) commits;
};

static int impl__write(git3_odb_backend *_backend, const git3_oid *oid, const void *data, size_t len, git3_object_t type)
{
	struct memory_packer_db *db = (struct memory_packer_db *)_backend;
	struct memobject *obj = NULL;
	size_t alloc_len;

	if (git3_odb_mempack_oidmap_contains(&db->objects, oid))
		return 0;

	GIT3_ERROR_CHECK_ALLOC_ADD(&alloc_len, sizeof(struct memobject), len);
	obj = git3__malloc(alloc_len);
	GIT3_ERROR_CHECK_ALLOC(obj);

	memcpy(obj->data, data, len);
	git3_oid_cpy(&obj->oid, oid);
	obj->len = len;
	obj->type = type;

	if (git3_odb_mempack_oidmap_put(&db->objects, &obj->oid, obj) < 0)
		return -1;

	if (type == GIT3_OBJECT_COMMIT) {
		struct memobject **store = git3_array_alloc(db->commits);
		GIT3_ERROR_CHECK_ALLOC(store);
		*store = obj;
	}

	return 0;
}

static int impl__exists(git3_odb_backend *backend, const git3_oid *oid)
{
	struct memory_packer_db *db = (struct memory_packer_db *)backend;

	return git3_odb_mempack_oidmap_contains(&db->objects, oid);
}

static int impl__read(void **buffer_p, size_t *len_p, git3_object_t *type_p, git3_odb_backend *backend, const git3_oid *oid)
{
	struct memory_packer_db *db = (struct memory_packer_db *)backend;
	struct memobject *obj;
	int error;

	if ((error = git3_odb_mempack_oidmap_get(&obj, &db->objects, oid)) != 0)
		return error;

	*len_p = obj->len;
	*type_p = obj->type;
	*buffer_p = git3__malloc(obj->len);
	GIT3_ERROR_CHECK_ALLOC(*buffer_p);

	memcpy(*buffer_p, obj->data, obj->len);
	return 0;
}

static int impl__read_header(size_t *len_p, git3_object_t *type_p, git3_odb_backend *backend, const git3_oid *oid)
{
	struct memory_packer_db *db = (struct memory_packer_db *)backend;
	struct memobject *obj;
	int error;

	if ((error = git3_odb_mempack_oidmap_get(&obj, &db->objects, oid)) != 0)
		return error;

	*len_p = obj->len;
	*type_p = obj->type;
	return 0;
}

static int git3_mempack__dump(
	git3_str *pack,
	git3_repository *repo,
	git3_odb_backend *_backend)
{
	struct memory_packer_db *db = (struct memory_packer_db *)_backend;
	git3_packbuilder *packbuilder;
	uint32_t i;
	int err = -1;

	if (git3_packbuilder_new(&packbuilder, repo) < 0)
		return -1;

	git3_packbuilder_set_threads(packbuilder, 0);

	for (i = 0; i < db->commits.size; ++i) {
		struct memobject *commit = db->commits.ptr[i];

		err = git3_packbuilder_insert_commit(packbuilder, &commit->oid);
		if (err < 0)
			goto cleanup;
	}

	err = git3_packbuilder__write_buf(pack, packbuilder);

cleanup:
	git3_packbuilder_free(packbuilder);
	return err;
}

int git3_mempack_write_thin_pack(git3_odb_backend *backend, git3_packbuilder *pb)
{
	struct memory_packer_db *db = (struct memory_packer_db *)backend;
	const git3_oid *oid;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_INIT;
	int err;

	while (true) {
		err = git3_odb_mempack_oidmap_iterate(&iter, &oid, NULL, &db->objects);

		if (err == GIT3_ITEROVER)
			break;
		else if (err != 0)
			return err;

		err = git3_packbuilder_insert(pb, oid, NULL);
		if (err != 0)
			return err;
	}

	return 0;
}

int git3_mempack_dump(
	git3_buf *pack,
	git3_repository *repo,
	git3_odb_backend *_backend)
{
	GIT3_BUF_WRAP_PRIVATE(pack, git3_mempack__dump, repo, _backend);
}

int git3_mempack_reset(git3_odb_backend *_backend)
{
	struct memory_packer_db *db = (struct memory_packer_db *)_backend;
	struct memobject *object = NULL;
	git3_hashmap_iter_t iter = GIT3_HASHMAP_ITER_INIT;

	while (git3_odb_mempack_oidmap_iterate(&iter, NULL, &object, &db->objects) == 0)
		git3__free(object);

	git3_array_clear(db->commits);
	git3_odb_mempack_oidmap_clear(&db->objects);

	return 0;
}

static void impl__free(git3_odb_backend *_backend)
{
	struct memory_packer_db *db = (struct memory_packer_db *)_backend;

	git3_mempack_reset(_backend);
	git3_odb_mempack_oidmap_dispose(&db->objects);
	git3__free(db);
}

int git3_mempack_new(git3_odb_backend **out)
{
	struct memory_packer_db *db;

	GIT3_ASSERT_ARG(out);

	db = git3__calloc(1, sizeof(struct memory_packer_db));
	GIT3_ERROR_CHECK_ALLOC(db);

	db->parent.version = GIT3_ODB_BACKEND_VERSION;
	db->parent.read = &impl__read;
	db->parent.write = &impl__write;
	db->parent.read_header = &impl__read_header;
	db->parent.exists = &impl__exists;
	db->parent.free = &impl__free;

	*out = (git3_odb_backend *)db;
	return 0;
}

int git3_mempack_object_count(size_t *out, git3_odb_backend *_backend)
{
	struct memory_packer_db *db = (struct memory_packer_db *)_backend;

	GIT3_ASSERT_ARG(_backend);

	*out = (size_t)git3_odb_mempack_oidmap_size(&db->objects);
	return 0;
}
