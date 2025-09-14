#include "clar_libgit3.h"
#include "git3/sys/odb_backend.h"
#include "backend_helpers.h"

static int search_object(const fake_object **out, fake_backend *fake, const git3_oid *oid, size_t len)
{
	const fake_object *obj = fake->objects, *found = NULL;

	while (obj && obj->oid) {
		git3_oid current_oid;

		git3_oid_from_string(&current_oid, obj->oid, GIT3_OID_SHA1);

		if (git3_oid_ncmp(&current_oid, oid, len) == 0) {
			if (found)
				return GIT3_EAMBIGUOUS;
			found = obj;
		}

		obj++;
	}

	if (found && out)
		*out = found;

	return found ? GIT3_OK : GIT3_ENOTFOUND;
}

static int fake_backend__exists(git3_odb_backend *backend, const git3_oid *oid)
{
	fake_backend *fake;

	fake = (fake_backend *)backend;

	fake->exists_calls++;

	return search_object(NULL, fake, oid, GIT3_OID_SHA1_HEXSIZE) == GIT3_OK;
}

static int fake_backend__exists_prefix(
	git3_oid *out, git3_odb_backend *backend, const git3_oid *oid, size_t len)
{
	const fake_object *obj;
	fake_backend *fake;
	int error;

	fake = (fake_backend *)backend;

	fake->exists_prefix_calls++;

	if ((error = search_object(&obj, fake, oid, len)) < 0)
		return error;

	if (out)
		git3_oid_from_string(out, obj->oid, GIT3_OID_SHA1);

	return 0;
}

static int fake_backend__read(
	void **buffer_p, size_t *len_p, git3_object_t *type_p,
	git3_odb_backend *backend, const git3_oid *oid)
{
	const fake_object *obj;
	fake_backend *fake;
	int error;

	fake = (fake_backend *)backend;

	fake->read_calls++;

	if ((error = search_object(&obj, fake, oid, GIT3_OID_SHA1_HEXSIZE)) < 0)
		return error;

	*len_p = strlen(obj->content);
	*buffer_p = git3__strdup(obj->content);
	*type_p = GIT3_OBJECT_BLOB;

	return 0;
}

static int fake_backend__read_header(
	size_t *len_p, git3_object_t *type_p,
	git3_odb_backend *backend, const git3_oid *oid)
{
	const fake_object *obj;
	fake_backend *fake;
	int error;

	fake = (fake_backend *)backend;

	fake->read_header_calls++;

	if ((error = search_object(&obj, fake, oid, GIT3_OID_SHA1_HEXSIZE)) < 0)
		return error;

	*len_p = strlen(obj->content);
	*type_p = GIT3_OBJECT_BLOB;

	return 0;
}

static int fake_backend__read_prefix(
	git3_oid *out_oid, void **buffer_p, size_t *len_p, git3_object_t *type_p,
	git3_odb_backend *backend, const git3_oid *short_oid, size_t len)
{
	const fake_object *obj;
	fake_backend *fake;
	int error;

	fake = (fake_backend *)backend;

	fake->read_prefix_calls++;

	if ((error = search_object(&obj, fake, short_oid, len)) < 0)
		return error;

	git3_oid_from_string(out_oid, obj->oid, GIT3_OID_SHA1);
	*len_p = strlen(obj->content);
	*buffer_p = git3__strdup(obj->content);
	*type_p = GIT3_OBJECT_BLOB;

	return 0;
}

static int fake_backend__refresh(git3_odb_backend *backend)
{
	fake_backend *fake;

	fake = (fake_backend *)backend;

	fake->refresh_calls++;

	return 0;
}


static void fake_backend__free(git3_odb_backend *_backend)
{
	fake_backend *backend;

	backend = (fake_backend *)_backend;

	git3__free(backend);
}

int build_fake_backend(
	git3_odb_backend **out,
	const fake_object *objects,
	bool support_refresh)
{
	fake_backend *backend;

	backend = git3__calloc(1, sizeof(fake_backend));
	GIT3_ERROR_CHECK_ALLOC(backend);

	backend->parent.version = GIT3_ODB_BACKEND_VERSION;

	backend->objects = objects;

	backend->parent.read = fake_backend__read;
	backend->parent.read_prefix = fake_backend__read_prefix;
	backend->parent.read_header = fake_backend__read_header;
	backend->parent.refresh = support_refresh ? fake_backend__refresh : NULL;
	backend->parent.exists = fake_backend__exists;
	backend->parent.exists_prefix = fake_backend__exists_prefix;
	backend->parent.free = &fake_backend__free;

	*out = (git3_odb_backend *)backend;

	return 0;
}
