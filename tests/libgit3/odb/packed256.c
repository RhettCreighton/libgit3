#include "clar_libgit3.h"
#include "odb.h"
#include "pack_data_256.h"

#ifdef GIT3_EXPERIMENTAL_SHA256
static git3_odb *_odb;
#endif

void test_odb_packed256__initialize(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_odb_options opts = GIT3_ODB_OPTIONS_INIT;

	opts.oid_type = GIT3_OID_SHA256;

	cl_git_pass(git3_odb_open_ext(
		&_odb,
		cl_fixture("testrepo_256.git/objects"),
		&opts));
#endif
}

void test_odb_packed256__cleanup(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	git3_odb_free(_odb);
	_odb = NULL;
#endif
}

void test_odb_packed256__mass_read(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(packed_objects_256); ++i) {
		git3_oid id;
		git3_odb_object *obj;

		cl_git_pass(git3_oid_from_string(&id, packed_objects_256[i], GIT3_OID_SHA256));
		cl_assert(git3_odb_exists(_odb, &id) == 1);
		cl_git_pass(git3_odb_read(&obj, _odb, &id));

		git3_odb_object_free(obj);
	}
#endif
}

void test_odb_packed256__read_header_0(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(packed_objects_256); ++i) {
		git3_oid id;
		git3_odb_object *obj;
		size_t len;
		git3_object_t type;

		cl_git_pass(git3_oid_from_string(&id, packed_objects_256[i], GIT3_OID_SHA256));

		cl_git_pass(git3_odb_read(&obj, _odb, &id));
		cl_git_pass(git3_odb_read_header(&len, &type, _odb, &id));

		cl_assert(obj->cached.size == len);
		cl_assert(obj->cached.type == type);

		git3_odb_object_free(obj);
	}
#endif
}

void test_odb_packed256__read_header_1(void)
{
#ifdef GIT3_EXPERIMENTAL_SHA256
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(loose_objects_256); ++i) {
		git3_oid id;
		git3_odb_object *obj;
		size_t len;
		git3_object_t type;

		cl_git_pass(git3_oid_from_string(&id, loose_objects_256[i], GIT3_OID_SHA256));

		cl_assert(git3_odb_exists(_odb, &id) == 1);

		cl_git_pass(git3_odb_read(&obj, _odb, &id));
		cl_git_pass(git3_odb_read_header(&len, &type, _odb, &id));

		cl_assert(obj->cached.size == len);
		cl_assert(obj->cached.type == type);

		git3_odb_object_free(obj);
	}
#endif
}

