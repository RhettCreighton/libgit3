/*
 * Copyright (C) the libgit3 contributors. All rights reserved.
 *
 * This file is part of libgit3, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "object.h"

#include "git3/object.h"

#include "repository.h"

#include "buf.h"
#include "commit.h"
#include "hash.h"
#include "tree.h"
#include "blob.h"
#include "oid.h"
#include "tag.h"

bool git3_object__strict_input_validation = true;

size_t git3_object__size(git3_object_t type);

typedef struct {
	const char	*str;	/* type name string */
	size_t		size;	/* size in bytes of the object structure */

	int  (*parse)(void *self, git3_odb_object *obj, git3_oid_t oid_type);
	int  (*parse_raw)(void *self, const char *data, size_t size, git3_oid_t oid_type);
	void (*free)(void *self);
} git3_object_def;

static git3_object_def git3_objects_table[] = {
	/* 0 = unused */
	{ "", 0, NULL, NULL, NULL },

	/* 1 = GIT3_OBJECT_COMMIT */
	{ "commit", sizeof(git3_commit), git3_commit__parse, git3_commit__parse_raw, git3_commit__free },

	/* 2 = GIT3_OBJECT_TREE */
	{ "tree", sizeof(git3_tree), git3_tree__parse, git3_tree__parse_raw, git3_tree__free },

	/* 3 = GIT3_OBJECT_BLOB */
	{ "blob", sizeof(git3_blob), git3_blob__parse, git3_blob__parse_raw, git3_blob__free },

	/* 4 = GIT3_OBJECT_TAG */
	{ "tag", sizeof(git3_tag), git3_tag__parse, git3_tag__parse_raw, git3_tag__free }
};

int git3_object__from_raw(
	git3_object **object_out,
	const char *data,
	size_t size,
	git3_object_t object_type,
	git3_oid_t oid_type)
{
	git3_object_def *def;
	git3_object *object;
	size_t object_size;
	int error;

	GIT3_ASSERT_ARG(object_out);
	*object_out = NULL;

	/* Validate type match */
	if (object_type != GIT3_OBJECT_BLOB &&
	    object_type != GIT3_OBJECT_TREE &&
	    object_type != GIT3_OBJECT_COMMIT &&
	    object_type != GIT3_OBJECT_TAG) {
		git3_error_set(GIT3_ERROR_INVALID, "the requested type is invalid");
		return GIT3_ENOTFOUND;
	}

	if ((object_size = git3_object__size(object_type)) == 0) {
		git3_error_set(GIT3_ERROR_INVALID, "the requested type is invalid");
		return GIT3_ENOTFOUND;
	}

	/* Allocate and initialize base object */
	object = git3__calloc(1, object_size);
	GIT3_ERROR_CHECK_ALLOC(object);
	object->cached.flags = GIT3_CACHE_STORE_PARSED;
	object->cached.type = object_type;
	if ((error = git3_odb__hash(&object->cached.oid, data, size, object_type, oid_type)) < 0)
		return error;

	/* Parse raw object data */
	def = &git3_objects_table[object_type];
	GIT3_ASSERT(def->free && def->parse_raw);

	if ((error = def->parse_raw(object, data, size, oid_type)) < 0) {
		def->free(object);
		return error;
	}

	git3_cached_obj_incref(object);
	*object_out = object;

	return 0;
}

int git3_object__init_from_odb_object(
	git3_object **object_out,
	git3_repository *repo,
	git3_odb_object *odb_obj,
	git3_object_t type)
{
	size_t object_size;
	git3_object *object = NULL;

	GIT3_ASSERT_ARG(object_out);
	*object_out = NULL;

	/* Validate type match */
	if (type != GIT3_OBJECT_ANY && type != odb_obj->cached.type) {
		git3_error_set(GIT3_ERROR_INVALID,
			"the requested type does not match the type in the ODB");
		return GIT3_ENOTFOUND;
	}

	if ((object_size = git3_object__size(odb_obj->cached.type)) == 0) {
		git3_error_set(GIT3_ERROR_INVALID, "the requested type is invalid");
		return GIT3_ENOTFOUND;
	}

	/* Allocate and initialize base object */
	object = git3__calloc(1, object_size);
	GIT3_ERROR_CHECK_ALLOC(object);

	git3_oid_cpy(&object->cached.oid, &odb_obj->cached.oid);
	object->cached.type = odb_obj->cached.type;
	object->cached.size = odb_obj->cached.size;
	object->repo = repo;

	*object_out = object;
	return 0;
}

int git3_object__from_odb_object(
	git3_object **object_out,
	git3_repository *repo,
	git3_odb_object *odb_obj,
	git3_object_t type)
{
	int error;
	git3_object_def *def;
	git3_object *object = NULL;

	if ((error = git3_object__init_from_odb_object(&object, repo, odb_obj, type)) < 0)
		return error;

	/* Parse raw object data */
	def = &git3_objects_table[odb_obj->cached.type];
	GIT3_ASSERT(def->free && def->parse);

	if ((error = def->parse(object, odb_obj, repo->oid_type)) < 0) {
		/*
		 * parse returns EINVALID on invalid data; downgrade
		 * that to a normal -1 error code.
		 */
		def->free(object);
		return -1;
	}

	*object_out = git3_cache_store_parsed(&repo->objects, object);
	return 0;
}

void git3_object__free(void *obj)
{
	git3_object_t type = ((git3_object *)obj)->cached.type;

	if (type < 0 || ((size_t)type) >= ARRAY_SIZE(git3_objects_table) ||
		!git3_objects_table[type].free)
		git3__free(obj);
	else
		git3_objects_table[type].free(obj);
}

int git3_object_lookup_prefix(
	git3_object **object_out,
	git3_repository *repo,
	const git3_oid *id,
	size_t len,
	git3_object_t type)
{
	git3_object *object = NULL;
	git3_odb *odb = NULL;
	git3_odb_object *odb_obj = NULL;
	size_t oid_hexsize;
	int error = 0;

	GIT3_ASSERT_ARG(repo);
	GIT3_ASSERT_ARG(object_out);
	GIT3_ASSERT_ARG(id);

	if (len < GIT3_OID_MINPREFIXLEN) {
		git3_error_set(GIT3_ERROR_OBJECT, "ambiguous lookup - OID prefix is too short");
		return GIT3_EAMBIGUOUS;
	}

	error = git3_repository_odb__weakptr(&odb, repo);
	if (error < 0)
		return error;

	oid_hexsize = git3_oid_hexsize(repo->oid_type);

	if (len > oid_hexsize)
		len = oid_hexsize;

	if (len == oid_hexsize) {
		git3_cached_obj *cached = NULL;

		/* We want to match the full id : we can first look up in the cache,
		 * since there is no need to check for non ambiguousity
		 */
		cached = git3_cache_get_any(&repo->objects, id);
		if (cached != NULL) {
			if (cached->flags == GIT3_CACHE_STORE_PARSED) {
				object = (git3_object *)cached;

				if (type != GIT3_OBJECT_ANY && type != object->cached.type) {
					git3_object_free(object);
					git3_error_set(GIT3_ERROR_INVALID,
						"the requested type does not match the type in the ODB");
					return GIT3_ENOTFOUND;
				}

				*object_out = object;
				return 0;
			} else if (cached->flags == GIT3_CACHE_STORE_RAW) {
				odb_obj = (git3_odb_object *)cached;
			} else {
				GIT3_ASSERT(!"Wrong caching type in the global object cache");
			}
		} else {
			/* Object was not found in the cache, let's explore the backends.
			 * We could just use git3_odb_read_unique_short_oid,
			 * it is the same cost for packed and loose object backends,
			 * but it may be much more costly for sqlite and hiredis.
			 */
			error = git3_odb_read(&odb_obj, odb, id);
		}
	} else {
		git3_oid short_oid;

		git3_oid_clear(&short_oid, repo->oid_type);
		git3_oid__cpy_prefix(&short_oid, id, len);

		/* If len < GIT3_OID_MAX_HEXSIZE (a strict short oid was given), we have
		 * 2 options :
		 * - We always search in the cache first. If we find that short oid is
		 *	ambiguous, we can stop. But in all the other cases, we must then
		 *	explore all the backends (to find an object if there was match,
		 *	or to check that oid is not ambiguous if we have found 1 match in
		 *	the cache)
		 * - We never explore the cache, go right to exploring the backends
		 * We chose the latter : we explore directly the backends.
		 */
		error = git3_odb_read_prefix(&odb_obj, odb, &short_oid, len);
	}

	if (error < 0)
		return error;

	GIT3_ASSERT(odb_obj);
	error = git3_object__from_odb_object(object_out, repo, odb_obj, type);

	git3_odb_object_free(odb_obj);

	return error;
}

int git3_object_lookup(git3_object **object_out, git3_repository *repo, const git3_oid *id, git3_object_t type) {
	return git3_object_lookup_prefix(object_out,
		repo, id, git3_oid_hexsize(repo->oid_type), type);
}

void git3_object_free(git3_object *object)
{
	if (object == NULL)
		return;

	git3_cached_obj_decref(object);
}

const git3_oid *git3_object_id(const git3_object *obj)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(obj, NULL);
	return &obj->cached.oid;
}

git3_object_t git3_object_type(const git3_object *obj)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(obj, GIT3_OBJECT_INVALID);
	return obj->cached.type;
}

git3_repository *git3_object_owner(const git3_object *obj)
{
	GIT3_ASSERT_ARG_WITH_RETVAL(obj, NULL);
	return obj->repo;
}

const char *git3_object_type2string(git3_object_t type)
{
	if (type < 0 || ((size_t) type) >= ARRAY_SIZE(git3_objects_table))
		return "";

	return git3_objects_table[type].str;
}

git3_object_t git3_object_string2type(const char *str)
{
	if (!str)
		return GIT3_OBJECT_INVALID;

	return git3_object_stringn2type(str, strlen(str));
}

git3_object_t git3_object_stringn2type(const char *str, size_t len)
{
	size_t i;

	if (!str || !len || !*str)
		return GIT3_OBJECT_INVALID;

	for (i = 0; i < ARRAY_SIZE(git3_objects_table); i++)
		if (*git3_objects_table[i].str &&
			!git3__prefixncmp(str, len, git3_objects_table[i].str))
			return (git3_object_t)i;

	return GIT3_OBJECT_INVALID;
}

int git3_object_type_is_valid(git3_object_t type)
{
	if (type < 0 || ((size_t) type) >= ARRAY_SIZE(git3_objects_table))
		return 0;

	return (git3_objects_table[type].size > 0) ? 1 : 0;
}

#ifndef GIT3_DEPRECATE_HARD
int git3_object_typeisloose(git3_object_t type)
{
	return git3_object_type_is_valid(type);
}
#endif

size_t git3_object__size(git3_object_t type)
{
	if (type < 0 || ((size_t) type) >= ARRAY_SIZE(git3_objects_table))
		return 0;

	return git3_objects_table[type].size;
}

static int dereference_object(git3_object **dereferenced, git3_object *obj)
{
	git3_object_t type = git3_object_type(obj);

	switch (type) {
	case GIT3_OBJECT_COMMIT:
		return git3_commit_tree((git3_tree **)dereferenced, (git3_commit*)obj);

	case GIT3_OBJECT_TAG:
		return git3_tag_target(dereferenced, (git3_tag*)obj);

	case GIT3_OBJECT_BLOB:
	case GIT3_OBJECT_TREE:
		return GIT3_EPEEL;

	default:
		return GIT3_EINVALIDSPEC;
	}
}

static int peel_error(int error, const git3_oid *oid, git3_object_t type)
{
	const char *type_name;
	char hex_oid[GIT3_OID_MAX_HEXSIZE + 1];

	type_name = git3_object_type2string(type);

	git3_oid_nfmt(hex_oid, GIT3_OID_MAX_HEXSIZE + 1, oid);

	git3_error_set(GIT3_ERROR_OBJECT, "the git3_object of id '%s' can not be "
		"successfully peeled into a %s (git3_object_t=%i).", hex_oid, type_name, type);

	return error;
}

static int check_type_combination(git3_object_t type, git3_object_t target)
{
	if (type == target)
		return 0;

	switch (type) {
	case GIT3_OBJECT_BLOB:
	case GIT3_OBJECT_TREE:
		/* a blob or tree can never be peeled to anything but themselves */
		return GIT3_EINVALIDSPEC;
		break;
	case GIT3_OBJECT_COMMIT:
		/* a commit can only be peeled to a tree */
		if (target != GIT3_OBJECT_TREE && target != GIT3_OBJECT_ANY)
			return GIT3_EINVALIDSPEC;
		break;
	case GIT3_OBJECT_TAG:
		/* a tag may point to anything, so we let anything through */
		break;
	default:
		return GIT3_EINVALIDSPEC;
	}

	return 0;
}

int git3_object_peel(
	git3_object **peeled,
	const git3_object *object,
	git3_object_t target_type)
{
	git3_object *source, *deref = NULL;
	int error;

	GIT3_ASSERT_ARG(object);
	GIT3_ASSERT_ARG(peeled);

	GIT3_ASSERT_ARG(target_type == GIT3_OBJECT_TAG ||
		target_type == GIT3_OBJECT_COMMIT ||
		target_type == GIT3_OBJECT_TREE ||
		target_type == GIT3_OBJECT_BLOB ||
		target_type == GIT3_OBJECT_ANY);

	if ((error = check_type_combination(git3_object_type(object), target_type)) < 0)
		return peel_error(error, git3_object_id(object), target_type);

	if (git3_object_type(object) == target_type)
		return git3_object_dup(peeled, (git3_object *)object);

	source = (git3_object *)object;

	while (!(error = dereference_object(&deref, source))) {

		if (source != object)
			git3_object_free(source);

		if (git3_object_type(deref) == target_type) {
			*peeled = deref;
			return 0;
		}

		if (target_type == GIT3_OBJECT_ANY &&
			git3_object_type(deref) != git3_object_type(object))
		{
			*peeled = deref;
			return 0;
		}

		source = deref;
		deref = NULL;
	}

	if (source != object)
		git3_object_free(source);

	git3_object_free(deref);

	if (error)
		error = peel_error(error, git3_object_id(object), target_type);

	return error;
}

int git3_object_dup(git3_object **dest, git3_object *source)
{
	git3_cached_obj_incref(source);
	*dest = source;
	return 0;
}

int git3_object_lookup_bypath(
		git3_object **out,
		const git3_object *treeish,
		const char *path,
		git3_object_t type)
{
	int error = -1;
	git3_tree *tree = NULL;
	git3_tree_entry *entry = NULL;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(treeish);
	GIT3_ASSERT_ARG(path);

	if ((error = git3_object_peel((git3_object**)&tree, treeish, GIT3_OBJECT_TREE)) < 0 ||
		 (error = git3_tree_entry_bypath(&entry, tree, path)) < 0)
	{
		goto cleanup;
	}

	if (type != GIT3_OBJECT_ANY && git3_tree_entry_type(entry) != type)
	{
		git3_error_set(GIT3_ERROR_OBJECT,
				"object at path '%s' is not of the asked-for type %d",
				path, type);
		error = GIT3_EINVALIDSPEC;
		goto cleanup;
	}

	error = git3_tree_entry_to_object(out, git3_object_owner(treeish), entry);

cleanup:
	git3_tree_entry_free(entry);
	git3_tree_free(tree);
	return error;
}

static int git3_object__short_id(git3_str *out, const git3_object *obj)
{
	git3_repository *repo;
	git3_oid id;
	git3_odb *odb;
	size_t oid_hexsize;
	int len, error;

	GIT3_ASSERT_ARG(out);
	GIT3_ASSERT_ARG(obj);

	repo = git3_object_owner(obj);

	git3_oid_clear(&id, repo->oid_type);
	oid_hexsize = git3_oid_hexsize(repo->oid_type);

	if ((error = git3_repository__abbrev_length(&len, repo)) < 0)
		return error;

	if ((size_t)len == oid_hexsize) {
		if ((error = git3_oid_cpy(&id, &obj->cached.oid)) < 0) {
			return error;
		}
	}

	if ((error = git3_repository_odb(&odb, repo)) < 0)
		return error;

	while ((size_t)len < oid_hexsize) {
		/* set up short oid */
		memcpy(&id.id, &obj->cached.oid.id, (len + 1) / 2);
		if (len & 1)
			id.id[len / 2] &= 0xf0;

		error = git3_odb_exists_prefix(NULL, odb, &id, len);
		if (error != GIT3_EAMBIGUOUS)
			break;

		git3_error_clear();
		len++;
	}

	if (!error && !(error = git3_str_grow(out, len + 1))) {
		git3_oid_tostr(out->ptr, len + 1, &id);
		out->size = len;
	}

	git3_odb_free(odb);

	return error;
}

int git3_object_short_id(git3_buf *out, const git3_object *obj)
{
	GIT3_BUF_WRAP_PRIVATE(out, git3_object__short_id, obj);
}

bool git3_object__is_valid(
	git3_repository *repo, const git3_oid *id, git3_object_t expected_type)
{
	git3_odb *odb;
	git3_object_t actual_type;
	size_t len;
	int error;

	if (!git3_object__strict_input_validation)
		return true;

	if ((error = git3_repository_odb__weakptr(&odb, repo)) < 0 ||
		(error = git3_odb_read_header(&len, &actual_type, odb, id)) < 0)
		return false;

	if (expected_type != GIT3_OBJECT_ANY && expected_type != actual_type) {
		git3_error_set(GIT3_ERROR_INVALID,
			"the requested type does not match the type in the ODB");
		return false;
	}

	return true;
}

int git3_object_rawcontent_is_valid(
	int *valid,
	const char *buf,
	size_t len,
	git3_object_t object_type
#ifdef GIT3_EXPERIMENTAL_SHA256
	, git3_oid_t oid_type
#endif
	)
{
	git3_object *obj = NULL;
	int error;

#ifndef GIT3_EXPERIMENTAL_SHA256
	git3_oid_t oid_type = GIT3_OID_SHA3_256;
#endif

	GIT3_ASSERT_ARG(valid);
	GIT3_ASSERT_ARG(buf);

	/* Blobs are always valid; don't bother parsing. */
	if (object_type == GIT3_OBJECT_BLOB) {
		*valid = 1;
		return 0;
	}

	error = git3_object__from_raw(&obj, buf, len, object_type, oid_type);
	git3_object_free(obj);

	if (error == 0) {
		*valid = 1;
		return 0;
	} else if (error == GIT3_EINVALID) {
		*valid = 0;
		return 0;
	}

	return error;
}

int git3_object__parse_oid_header(
	git3_oid *oid,
	const char **buffer_out,
	const char *buffer_end,
	const char *header,
	git3_oid_t oid_type)
{
	const size_t sha_len = git3_oid_hexsize(oid_type);
	const size_t header_len = strlen(header);

	const char *buffer = *buffer_out;

	if (buffer + (header_len + sha_len + 1) > buffer_end)
		return -1;

	if (memcmp(buffer, header, header_len) != 0)
		return -1;

	if (buffer[header_len + sha_len] != '\n')
		return -1;

	if (git3_oid_from_prefix(oid, buffer + header_len, sha_len, oid_type) < 0)
		return -1;

	*buffer_out = buffer + (header_len + sha_len + 1);

	return 0;
}

int git3_object__write_oid_header(
	git3_str *buf,
	const char *header,
	const git3_oid *oid)
{
	size_t hex_size = git3_oid_hexsize(git3_oid_type(oid));
	char hex_oid[GIT3_OID_MAX_HEXSIZE];

	if (!hex_size) {
		git3_error_set(GIT3_ERROR_INVALID, "unknown type");
		return -1;
	}

	git3_oid_fmt(hex_oid, oid);
	git3_str_puts(buf, header);
	git3_str_put(buf, hex_oid, hex_size);
	git3_str_putc(buf, '\n');

	return git3_str_oom(buf) ? -1 : 0;
}
